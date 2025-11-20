use pcap::{Capture, Device, Activated};
use anyhow::Result;
use uuid::Uuid;
use hostname;

mod flows;
use flows::FlowAggregator;

async fn register_device(agent_id: &str, hostname: &str) -> Result<()> {
    let client = reqwest::Client::new();
    let api_url = std::env::var("API_URL").unwrap_or_else(|_| "http://localhost:8000".to_string());

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
        Ok(_) => println!("Registered device successfully"),
        Err(e) => eprintln!("Failed to register device: {}", e),
    }
    Ok(())
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

    register_device(&agent_id, &hostname_str).await.ok();

    let redis_password = std::env::var("REDIS_PASSWORD").ok();
    let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string());

    println!("Connecting to Redis at: {}", redis_url);
    let redis_client = redis::Client::open(redis_url.as_str())?;
    let mut redis_conn = redis_client.get_connection()?;

    if let Some(ref password) = redis_password {
        match redis::cmd("AUTH").arg(password).query::<String>(&mut redis_conn) {
            Ok(_) => println!("Authenticated with Redis successfully"),
            Err(e) => {
                eprintln!("Redis authentication failed: {}", e);
                return Err(anyhow::anyhow!("Redis auth failed: {}", e));
            }
        }
    }

    println!("Connected to Redis successfully");

    let mut aggregator = FlowAggregator::new(redis_password);

    let device = Device::list()?
    .into_iter()
    .find(|d| {
        d.flags.is_up() &&
        !d.flags.is_loopback() &&
        !d.name.starts_with("docker") &&
        !d.name.starts_with("br-") &&
        !d.name.starts_with("veth")
    })
    .ok_or_else(|| anyhow::anyhow!("No suitable network interface found"))?;

    println!("Auto-detected network interface: {}", device.name);

    let mut cap: Capture<dyn Activated> = Capture::from_device(device)?
    .promisc(false)
    .snaplen(256)
    .timeout(1000)
    .open()?
    .into();

    println!("Starting packet capture...");
    let mut packet_count = 0;

    loop {
        match cap.next_packet() {
            Ok(packet) => {
                packet_count += 1;
                if packet_count % 100 == 0 {
                    println!("Captured {} packets...", packet_count);
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
