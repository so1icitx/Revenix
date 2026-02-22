use anyhow::Result;
use hostname;
use pcap::{Activated, Capture, Device};
#[cfg(target_os = "windows")]
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::thread;
use std::time::Duration;
use uuid::Uuid;

mod dpi_analyzer;
mod flows;

use dpi_analyzer::DPIAnalyzer;
use flows::FlowAggregator;

#[cfg(target_os = "windows")]
fn is_unwanted_interface(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower.contains("loopback")
        || lower.contains("npcap loopback")
        || lower.contains("bluetooth")
        || lower.contains("vmware")
        || lower.contains("vethernet")
        || lower.contains("hyper-v")
        || lower.contains("isatap")
        || lower.contains("teredo")
}

#[cfg(not(target_os = "windows"))]
fn is_unwanted_interface(name: &str) -> bool {
    name.starts_with("docker")
        || name.starts_with("br-")
        || name.starts_with("veth")
        || name.starts_with("services")
}

#[cfg(target_os = "windows")]
fn detect_default_ipv4() -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    match socket.local_addr().ok()?.ip() {
        IpAddr::V4(ip) => Some(ip),
        IpAddr::V6(_) => None,
    }
}

#[cfg(target_os = "windows")]
fn device_has_ipv4(device: &Device, ip: Ipv4Addr) -> bool {
    device
        .addresses
        .iter()
        .any(|addr| matches!(addr.addr, IpAddr::V4(v4) if v4 == ip))
}

fn pick_capture_device(requested_interface: Option<String>) -> Result<Device> {
    let devices = Device::list()?;

    if devices.is_empty() {
        return Err(anyhow::anyhow!("No capture devices returned by pcap"));
    }

    if let Some(interface_name) = requested_interface {
        if let Some(device) = devices
            .iter()
            .find(|d| {
                d.name.eq_ignore_ascii_case(&interface_name)
                    || d.desc
                        .as_ref()
                        .map(|desc| desc.to_lowercase().contains(&interface_name.to_lowercase()))
                        .unwrap_or(false)
            })
            .cloned()
        {
            println!("Using specified network interface: {}", device.name);
            return Ok(device);
        }

        #[cfg(target_os = "windows")]
        {
            eprintln!(
                "Specified interface '{}' was not found in pcap devices. Falling back to auto-detection.",
                interface_name
            );
        }

        #[cfg(not(target_os = "windows"))]
        {
            return Err(anyhow::anyhow!(
                "Specified interface '{}' not found",
                interface_name
            ));
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Some(default_ip) = detect_default_ipv4() {
            if let Some(device) = devices
                .iter()
                .find(|d| device_has_ipv4(d, default_ip) && !is_unwanted_interface(&d.name))
                .cloned()
            {
                println!(
                    "Auto-detected interface by default-route IP {}: {}",
                    default_ip, device.name
                );
                return Ok(device);
            }
        }

        let auto_device = devices
            .iter()
            .into_iter()
            .find(|d| !is_unwanted_interface(&d.name))
            .cloned()
            .unwrap_or_else(|| devices[0].clone());
        println!("Auto-detected network interface: {}", auto_device.name);
        return Ok(auto_device);
    }

    #[cfg(not(target_os = "windows"))]
    {
        let auto_device = devices
            .into_iter()
            .find(|d| d.flags.is_up() && !d.flags.is_loopback() && !is_unwanted_interface(&d.name))
            .ok_or_else(|| anyhow::anyhow!("No suitable network interface found"))?;
        println!("Auto-detected network interface: {}", auto_device.name);
        return Ok(auto_device);
    }
}

fn with_internal_service_header(builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    match std::env::var("INTERNAL_SERVICE_TOKEN") {
        Ok(token) if !token.trim().is_empty() => builder.header("X-Internal-Token", token.trim()),
        _ => builder,
    }
}

async fn check_learning_phase() -> Result<bool> {
    let client = reqwest::Client::new();
    let api_url = std::env::var("API_URL").unwrap_or_else(|_| "http://localhost:8000".to_string());

    let request = with_internal_service_header(client.get(&format!("{}/system/state", api_url)))
        .timeout(std::time::Duration::from_secs(3));

    match request.send().await {
        Ok(resp) => {
            if let Ok(json) = resp.json::<serde_json::Value>().await {
                let phase = json["learning_phase"].as_str().unwrap_or("idle");
                // Only capture if in "learning" or "active" mode
                Ok(phase == "learning" || phase == "active")
            } else {
                Ok(false)
            }
        }
        Err(_) => Ok(false), // Default to not capturing if API unreachable
    }
}

async fn register_device(agent_id: &str, hostname: &str) -> Result<()> {
    let client = reqwest::Client::new();
    let api_url = std::env::var("API_URL").unwrap_or_else(|_| "http://localhost:8000".to_string());

    let body = serde_json::json!({
        "agent_id": agent_id,
        "hostname": hostname,
        "ip": "auto"
    });

    let request = with_internal_service_header(client.post(&format!("{}/register", api_url)))
        .json(&body)
        .timeout(std::time::Duration::from_secs(5));

    match request.send().await {
        Ok(resp) => {
            if resp.status().is_success() {
                println!("Registered device successfully");
            } else {
                let status = resp.status();
                let body = resp
                    .text()
                    .await
                    .unwrap_or_else(|_| "<no response body>".to_string());
                eprintln!("Device registration failed: {} - {}", status, body);
            }
        }
        Err(e) => eprintln!("Failed to register device: {}", e),
    }
    Ok(())
}

fn connect_redis_with_retry(redis_url: &str, max_retries: u32) -> Result<redis::Connection> {
    let redis_client = redis::Client::open(redis_url)?;

    for attempt in 1..=max_retries {
        println!(
            "Attempting to connect to Redis (attempt {}/{})",
            attempt, max_retries
        );
        match redis_client.get_connection() {
            Ok(conn) => {
                println!("Connected to Redis successfully");
                return Ok(conn);
            }
            Err(e) => {
                if attempt < max_retries {
                    eprintln!("Redis connection failed: {}. Retrying in 2s...", e);
                    thread::sleep(Duration::from_secs(2));
                } else {
                    return Err(anyhow::anyhow!(
                        "Failed to connect to Redis after {} attempts: {}",
                        max_retries,
                        e
                    ));
                }
            }
        }
    }

    Err(anyhow::anyhow!("Failed to connect to Redis"))
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("Revenix Core Starting...");

    let agent_id = Uuid::new_v4().to_string();
    let hostname_str = hostname::get()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    println!("Agent ID: {}", agent_id);
    println!("Hostname: {}", hostname_str);

    thread::sleep(Duration::from_secs(3));
    register_device(&agent_id, &hostname_str).await.ok();

    let redis_password = std::env::var("REDIS_PASSWORD")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string());

    println!("Connecting to Redis at: {}", redis_url);
    let mut redis_conn = connect_redis_with_retry(&redis_url, 10)?;

    if let Some(ref password) = redis_password {
        match redis::cmd("AUTH")
            .arg(password)
            .query::<String>(&mut redis_conn)
        {
            Ok(_) => println!("Authenticated with Redis successfully"),
            Err(e) => {
                eprintln!("Redis authentication failed: {}", e);
                return Err(anyhow::anyhow!("Redis auth failed: {}", e));
            }
        }
    }

    let mut aggregator = FlowAggregator::new(redis_password);
    let mut dpi_analyzer = DPIAnalyzer::new();

    println!("🔬 DPI Analyzer initialized (TLS fingerprinting, DNS tunneling, SSH brute force detection)");

    thread::sleep(Duration::from_secs(1));

    let requested_interface = std::env::var("NETWORK_INTERFACE")
        .ok()
        .map(|name| name.trim().to_string())
        .filter(|name| !name.is_empty());

    let device = pick_capture_device(requested_interface)?;

    let promiscuous = std::env::var("PROMISCUOUS_MODE")
        .unwrap_or_else(|_| "false".to_string())
        .to_lowercase() == "true";
    
    if promiscuous {
        println!("⚠️  Promiscuous mode ENABLED - capturing all network traffic");
    } else {
        println!("📡 Promiscuous mode disabled - capturing host traffic only");
    }

    let mut cap: Capture<dyn Activated> = Capture::from_device(device)?
        .promisc(promiscuous)
        .snaplen(1514)
        .timeout(1000)
        .open()?
        .into();

    println!("Packet capture interface ready.");
    
    println!("⏳ Waiting for admin to start learning phase...");
    let mut last_phase_check = std::time::Instant::now();
    let mut is_capturing = false;
    let phase_check_interval = Duration::from_secs(5);

    let mut packet_count = 0;

    loop {
        if last_phase_check.elapsed() >= phase_check_interval {
            let should_capture = check_learning_phase().await.unwrap_or(false);
            
            if should_capture && !is_capturing {
                println!("✅ Learning phase started - beginning packet capture");
                is_capturing = true;
            } else if !should_capture && is_capturing {
                println!("⏸️  Learning phase stopped - pausing packet capture");
                is_capturing = false;
            } else if !should_capture && !is_capturing {
                // Still waiting
                print!(".");
                std::io::Write::flush(&mut std::io::stdout()).ok();
            }
            
            last_phase_check = std::time::Instant::now();
        }

        if !is_capturing {
            thread::sleep(Duration::from_millis(100));
            continue;
        }

        match cap.next_packet() {
            Ok(packet) => {
                packet_count += 1;
                if packet_count % 100 == 0 {
                    println!("Captured {} packets...", packet_count);
                }

                if let Some(dpi_result) = dpi_analyzer.analyze_packet(packet.data) {
                    let dpi_json = serde_json::to_string(&dpi_result)?;
                    redis::cmd("XADD")
                        .arg("dpi_results")
                        .arg("*")
                        .arg("result")
                        .arg(&dpi_json)
                        .query::<String>(&mut redis_conn)
                        .ok();
                }

                if let Some(flow_json) = aggregator.process_packet(&packet, &mut redis_conn)? {
                    println!("Flow published: {}", flow_json);
                }
            }
            Err(pcap::Error::TimeoutExpired) => {
                aggregator.check_timeouts(&mut redis_conn)?;
            }
            Err(e) => {
                eprintln!("Packet capture error: {}", e);
            }
        }
    }
}
