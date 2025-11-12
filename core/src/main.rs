use pcap::{Capture, Device, Activated};
use anyhow::Result;

mod flows;
use flows::FlowAggregator;

#[tokio::main]
async fn main() -> Result<()> {
    println!("Revenix Core Starting...");

    let redis_client = redis::Client::open("redis://localhost:6379")?;
    let mut redis_conn = redis_client.get_connection()?;

    let mut aggregator = FlowAggregator::new();

    let mut cap: Capture<dyn Activated> = match Device::list()?
    .into_iter()
    .find(|d| d.name == "eth0")
    {
        Some(device) => {
            println!("Capturing from eth0");
            let active = Capture::from_device(device)?.open()?;
            active.into()
        }
        None => {
            println!("eth0 not found, reading from sample.pcap");
            let offline = Capture::from_file("sample.pcap")?;
            offline.into()
        }
    };

    loop {
        match cap.next_packet() {
            Ok(packet) => {
                if let Some(flow_json) = aggregator.process_packet(&packet)? {
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

