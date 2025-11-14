use pcap::{Capture, Device, Activated};
use anyhow::Result;
use uuid::Uuid;
use hostname;

mod flows;
use flows::FlowAggregator;

async fn register_device(agent_id: &str, hostname: &str) -> Result<()> {
    let client = reqwest::Client::new();
    let api_url = std::env::var("API_URL").unwrap_or_else(|_| "http://api:8000".to_string());

    let body = serde_json::json!({
        "agent_id": agent_id,
        "hostname": hostname,
        "ip": "auto"
    });

    match client.post(&format!("{}/register", api_url))
    .json(&body)
    .timeout(std::time::Duration::from_secs(5))
    .send()
    .await
    {
        Ok(response) => {
            if response.status().is_success() {
                println!("✓ Registered device: {} ({})", hostname, agent_id);
            } else {
                eprintln!("⚠ Registration returned status: {}", response.status());
            }
            Ok(())
        }
        Err(e) => {
            eprintln!("⚠ Failed to register device: {}", e);
            Err(anyhow::anyhow!("Registration failed: {}", e))
        }
    }
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

    if let Err(e) = register_device(&agent_id, &hostname_str).await {
        eprintln!("Warning: Could not register device: {}", e);
    }

    let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://redis:6379".to_string());
    println!("Connecting to Redis at: {}", redis_url);
    let redis_client = redis::Client::open(redis_url.as_str())?;
    let mut redis_conn = redis_client.get_connection()?;
    println!("Connected to Redis successfully");

    let mut aggregator = FlowAggregator::new();

    let mut cap: Capture<dyn Activated> = match Device::list()?
    .into_iter()
    .find(|d| d.flags.is_up() && !d.flags.is_loopback())
    {
        Some(device) => {
            println!("Auto-detected network interface: {}", device.name);
            let active = Capture::from_device(device)?
            .promisc(true)
            .timeout(1000)
            .open()?;
            active.into()
        }
        None => {
            println!("No active network interface found, reading from sample.pcap");
            let offline = Capture::from_file("sample.pcap")?;
            offline.into()
        }
    };

    println!("Starting packet capture loop...");
    let mut packet_count = 0;

    loop {
        match cap.next_packet() {
            Ok(packet) => {
                packet_count += 1;
                if packet_count % 10 == 0 {
                    println!("Captured {} packets so far...", packet_count);
                }
                if let Some(flow_json) = aggregator.process_packet(&packet, &mut redis_conn)? {
                    println!("Flow completed: {}", flow_json);
                }
            }
            Err(pcap::Error::TimeoutExpired) => {
                aggregator.check_timeouts(&mut redis_conn)?;
                continue;
            }
            Err(e) => {
                eprintln!("Capture error: {}", e);
                break;
            }
        }
    }

    Ok(())
}
