use anyhow::Result;
use pcap::Device;
use std::net::IpAddr;

fn main() -> Result<()> {
    let devices = Device::list()?;
    println!("Found {} pcap device(s)\n", devices.len());

    for (idx, d) in devices.iter().enumerate() {
        println!("[{}] name: {}", idx, d.name);
        if let Some(desc) = &d.desc {
            println!("    desc: {}", desc);
        } else {
            println!("    desc: <none>");
        }
        println!(
            "    flags: up={} loopback={} running={} wireless={}",
            d.flags.is_up(),
            d.flags.is_loopback(),
            d.flags.is_running(),
            d.flags.is_wireless()
        );

        if d.addresses.is_empty() {
            println!("    addresses: <none>");
        } else {
            println!("    addresses:");
            for a in &d.addresses {
                match a.addr {
                    IpAddr::V4(ip) => println!("      - {}", ip),
                    IpAddr::V6(ip) => println!("      - {}", ip),
                }
            }
        }

        println!();
    }

    Ok(())
}
