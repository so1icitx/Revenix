use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use pcap::Packet;
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use anyhow::Result;
use redis::Connection;
use hostname;
use etherparse::{SlicedPacket, TransportSlice, NetSlice};

const FLOW_TIMEOUT: u64 = 30; // Flows expire after 30 seconds of inactivity
const PUBLISH_INTERVAL: u64 = 30; // Publish all flows every 30 seconds

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
    hostname: String,
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
    packets_processed: u64,
    last_publish: u64, // Track last publish time
    redis_password: Option<String>, // Store Redis password for re-authentication
}

impl FlowAggregator {
    pub fn new(redis_password: Option<String>) -> Self {
        Self {
            flows: HashMap::new(),
            packets_processed: 0,
            last_publish: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
            redis_password, // Store password
        }
    }

    pub fn process_packet(&mut self, packet: &Packet, redis_conn: &mut Connection) -> Result<Option<String>> {
        self.packets_processed += 1;

        if self.packets_processed % 1000 == 0 {
            println!("[Production] Processed {} packets, active flows: {}", self.packets_processed, self.flows.len());
        }

        let data = packet.data;

        let parsed = match SlicedPacket::from_ethernet(data) {
            Ok(p) => p,
            Err(_e) => return Ok(None),
        };

        let (src_ip, dst_ip, protocol_num) = match parsed.net {
            Some(NetSlice::Ipv4(ipv4)) => {
                let header = ipv4.header();
                let src_arr = header.source();
                let dst_arr = header.destination();
                let src = format!("{}.{}.{}.{}",
                                  src_arr[0], src_arr[1],
                                  src_arr[2], src_arr[3]);
                let dst = format!("{}.{}.{}.{}",
                                  dst_arr[0], dst_arr[1],
                                  dst_arr[2], dst_arr[3]);
                (src, dst, header.protocol().0)
            },
            Some(NetSlice::Ipv6(ipv6)) => {
                let header = ipv6.header();
                let src_bytes = header.source();
                let dst_bytes = header.destination();
                let src = format!("{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                                  u16::from_be_bytes([src_bytes[0], src_bytes[1]]),
                                  u16::from_be_bytes([src_bytes[2], src_bytes[3]]),
                                  u16::from_be_bytes([src_bytes[4], src_bytes[5]]),
                                  u16::from_be_bytes([src_bytes[6], src_bytes[7]]),
                                  u16::from_be_bytes([src_bytes[8], src_bytes[9]]),
                                  u16::from_be_bytes([src_bytes[10], src_bytes[11]]),
                                  u16::from_be_bytes([src_bytes[12], src_bytes[13]]),
                                  u16::from_be_bytes([src_bytes[14], src_bytes[15]]));
                let dst = format!("{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                                  u16::from_be_bytes([dst_bytes[0], dst_bytes[1]]),
                                  u16::from_be_bytes([dst_bytes[2], dst_bytes[3]]),
                                  u16::from_be_bytes([dst_bytes[4], dst_bytes[5]]),
                                  u16::from_be_bytes([dst_bytes[6], dst_bytes[7]]),
                                  u16::from_be_bytes([dst_bytes[8], dst_bytes[9]]),
                                  u16::from_be_bytes([dst_bytes[10], dst_bytes[11]]),
                                  u16::from_be_bytes([dst_bytes[12], dst_bytes[13]]),
                                  u16::from_be_bytes([dst_bytes[14], dst_bytes[15]]));
                (src, dst, header.next_header().0)
            },
            None => return Ok(None),
        };

        let (src_port, dst_port, protocol_str) = match parsed.transport {
            Some(TransportSlice::Tcp(tcp)) => {
                (tcp.source_port(), tcp.destination_port(), "TCP")
            },
            Some(TransportSlice::Udp(udp)) => {
                (udp.source_port(), udp.destination_port(), "UDP")
            },
            Some(TransportSlice::Icmpv4(_)) => (0, 0, "ICMP"),
            Some(TransportSlice::Icmpv6(_)) => (0, 0, "ICMPV6"),
            None => {
                let proto = match protocol_num {
                    1 => "ICMP",
                    6 => "TCP",
                    17 => "UDP",
                    58 => "ICMPV6",
                    _ => "OTHER",
                };
                (0, 0, proto)
            }
        };

        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let packet_len = data.len() as u64;

        let key = FlowKey {
            src_ip: src_ip.clone(),
            dst_ip: dst_ip.clone(),
            src_port,
            dst_port,
            protocol: protocol_str.to_string(),
        };

        let flow = self.flows.entry(key.clone()).or_insert_with(|| {
            Flow {
                flow_id: Uuid::new_v4().to_string(),
                                                                hostname: hostname::get()
                                                                .unwrap_or_default()
                                                                .to_string_lossy()
                                                                .to_string(),
                                                                src_ip: src_ip.clone(),
                                                                dst_ip: dst_ip.clone(),
                                                                src_port,
                                                                dst_port,
                                                                protocol: protocol_str.to_string(),
                                                                bytes: 0,
                                                                packets: 0,
                                                                start_ts: now,
                                                                end_ts: now,
            }
        });

        flow.bytes += packet_len;
        flow.packets += 1;
        flow.end_ts = now;

        if now - self.last_publish >= PUBLISH_INTERVAL {
            self.publish_all_flows(redis_conn)?;
            self.last_publish = now;
        }

        Ok(None)
    }

    fn publish_all_flows(&self, redis_conn: &mut Connection) -> Result<()> {
        if self.flows.is_empty() {
            return Ok(());
        }

        self.ensure_auth(redis_conn)?;

        println!("[Production] Publishing {} active flows to Redis", self.flows.len());
        for flow in self.flows.values() {
            let flow_json = serde_json::to_string(flow)?;
            redis::cmd("XADD")
            .arg("flows")
            .arg("*")
            .arg("flow")
            .arg(&flow_json)
            .query::<String>(redis_conn)?;
        }
        Ok(())
    }

    pub fn check_timeouts(&mut self, redis_conn: &mut Connection) -> Result<()> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let mut expired_keys = Vec::new();

        for (key, flow) in &self.flows {
            if now - flow.end_ts >= FLOW_TIMEOUT {
                expired_keys.push(key.clone());
            }
        }

        if !expired_keys.is_empty() {
            self.ensure_auth(redis_conn)?;

            for key in &expired_keys {
                if let Some(flow) = self.flows.get(key) {
                    let flow_json = serde_json::to_string(flow)?;
                    redis::cmd("XADD")
                    .arg("flows")
                    .arg("*")
                    .arg("flow")
                    .arg(&flow_json)
                    .query::<String>(redis_conn)?;
                }
            }

            println!("[Production] Cleaned {} expired flows ({}s timeout)", expired_keys.len(), FLOW_TIMEOUT);
        }

        for key in expired_keys {
            self.flows.remove(&key);
        }

        Ok(())
    }

    fn ensure_auth(&self, redis_conn: &mut Connection) -> Result<()> {
        if let Some(ref password) = self.redis_password {
            redis::cmd("AUTH")
            .arg(password)
            .query::<String>(redis_conn)
            .map_err(|e| anyhow::anyhow!("Redis auth failed: {}", e))?;
        }
        Ok(())
    }
}
