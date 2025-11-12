use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use pcap::Packet;
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use anyhow::Result;
use redis::Connection;

const FLOW_TIMEOUT: u64 = 5;

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct FlowKey {
    src_ip: String,
    dst_ip: String,
    src_port: u16,
    dst_port: u16,
    protocol: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Flow {
    flow_id: String,
    src_ip: String,
    dst_ip: String,
    src_port: u16,
    dst_port: u16,
    protocol: String,
    bytes: u64,
    packets: u64,
    start_ts: u64,
    end_ts: u64,
}

pub struct FlowAggregator {
    flows: HashMap<FlowKey, Flow>,
}

impl FlowAggregator {
    pub fn new() -> Self {
        Self {
            flows: HashMap::new(),
        }
    }

    pub fn process_packet(&mut self, packet: &Packet) -> Result<Option<String>> {
        let data = packet.data;
        if data.len() < 34 {
            return Ok(None);
        }

        let ip_header_start = 14;
        let protocol = data[ip_header_start + 9];
        let src_ip = format!("{}.{}.{}.{}",
                             data[ip_header_start + 12], data[ip_header_start + 13],
                             data[ip_header_start + 14], data[ip_header_start + 15]);
        let dst_ip = format!("{}.{}.{}.{}",
                             data[ip_header_start + 16], data[ip_header_start + 17],
                             data[ip_header_start + 18], data[ip_header_start + 19]);

        let protocol_str = match protocol {
            6 => "TCP",
            17 => "UDP",
            _ => "OTHER",
        }.to_string();

        let (src_port, dst_port) = if protocol == 6 || protocol == 17 {
            let transport_start = ip_header_start + 20;
            if data.len() >= transport_start + 4 {
                let src = u16::from_be_bytes([data[transport_start], data[transport_start + 1]]);
                let dst = u16::from_be_bytes([data[transport_start + 2], data[transport_start + 3]]);
                (src, dst)
            } else {
                (0, 0)
            }
        } else {
            (0, 0)
        };

        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let packet_len = data.len() as u64;

        let key = FlowKey {
            src_ip: src_ip.clone(),
            dst_ip: dst_ip.clone(),
            src_port,
            dst_port,
            protocol: protocol_str.clone(),
        };

        let flow = self.flows.entry(key.clone()).or_insert_with(|| Flow {
            flow_id: Uuid::new_v4().to_string(),
                                                                src_ip: src_ip.clone(),
                                                                dst_ip: dst_ip.clone(),
                                                                src_port,
                                                                dst_port,
                                                                protocol: protocol_str.clone(),
                                                                bytes: 0,
                                                                packets: 0,
                                                                start_ts: now,
                                                                end_ts: now,
        });

        flow.bytes += packet_len;
        flow.packets += 1;
        flow.end_ts = now;

        Ok(None)
    }

    pub fn check_timeouts(&mut self, redis_conn: &mut Connection) -> Result<()> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let mut expired_keys = Vec::new();

        for (key, flow) in &self.flows {
            if now - flow.end_ts >= FLOW_TIMEOUT {
                expired_keys.push(key.clone());
                let flow_json = serde_json::to_string(flow)?;
                redis::cmd("XADD")
                .arg("revenix:flows")
                .arg("*")
                .arg("flow")
                .arg(&flow_json)
                .query::<String>(redis_conn)?;
            }
        }

        for key in expired_keys {
            self.flows.remove(&key);
        }

        Ok(())
    }
}

