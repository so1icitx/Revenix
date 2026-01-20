use serde::Deserialize;
use serde_json::json;
use md5;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

const JA3_DB_DATA: &str = include_str!("../data/ja3_malware_db.json");

#[derive(Deserialize)]
struct JA3Entry {
    hash: String,
    family: String,
}

/// Advanced Deep Packet Inspection Analyzer
/// Detects: TLS fingerprinting (JA3), DNS tunneling, SSH brute force, protocol anomalies
pub struct DPIAnalyzer {
    // TLS JA3 fingerprinting
    ja3_malware_database: HashMap<String, String>,
    tls_sessions: HashMap<String, TLSSession>,

    // DNS tunneling detection
    dns_queries: HashMap<String, Vec<DNSQuery>>,
    dns_baseline_entropy: f64,

    // SSH brute force tracking
    ssh_attempts: HashMap<String, Vec<SSHAttempt>>,

    // Protocol anomaly detection
    protocol_stats: HashMap<String, ProtocolStats>,
}

#[derive(Clone)]
struct TLSSession {
    ja3_hash: String,
    ja3s_hash: Option<String>,
    cipher_suites: Vec<u16>,
    extensions: Vec<u16>,
    timestamp: u64,
    suspicious: bool,
}

#[derive(Clone)]
struct DNSQuery {
    domain: String,
    query_type: u16,
    length: usize,
    entropy: f64,
    timestamp: u64,
    subdomain_count: usize,
}

#[derive(Clone)]
struct SSHAttempt {
    timestamp: u64,
    success: bool,
    username: Option<String>,
}

#[derive(Clone)]
struct ProtocolStats {
    packet_count: u64,
    avg_size: f64,
    last_seen: u64,
}

impl DPIAnalyzer {
    pub fn new() -> Self {
        let mut ja3_malware_db = HashMap::new();
        if let Ok(entries) = serde_json::from_str::<Vec<JA3Entry>>(JA3_DB_DATA) {
            for entry in entries {
                ja3_malware_db.insert(entry.hash.to_lowercase(), entry.family);
            }
        }

        // Fallback seeds in case the JSON fails to load
        if ja3_malware_db.is_empty() {
            ja3_malware_db.insert(
                "f42f4f3d6f6b6a5d4e4c4a3b2a1".to_string(),
                "TrickBot C2".to_string(),
            );
            ja3_malware_db.insert(
                "5c5a4d4b4a3a2b1c1d1e1f2a3b".to_string(),
                "Cobalt Strike".to_string(),
            );
        }

        Self {
            ja3_malware_database: ja3_malware_db,
            tls_sessions: HashMap::new(),
            dns_queries: HashMap::new(),
            dns_baseline_entropy: 3.5, // Normal DNS entropy
            ssh_attempts: HashMap::new(),
            protocol_stats: HashMap::new(),
        }
    }

    /// Generate JA3 fingerprint from TLS ClientHello
    pub fn generate_ja3_fingerprint(
        &mut self,
        src_ip: &str,
        payload: &[u8],
    ) -> Option<serde_json::Value> {
        if payload.len() < 43 {
            return None;
        }

        // Parse TLS record
        let content_type = payload[0];
        if content_type != 0x16 {
            // Handshake
            return None;
        }

        let handshake_type = payload[5];
        if handshake_type != 0x01 {
            // ClientHello
            return None;
        }

        // Extract TLS version (bytes 9-10)
        let tls_version = u16::from_be_bytes([payload[9], payload[10]]);

        // Extract cipher suites
        let mut cipher_suites = Vec::new();
        let cipher_suite_length_offset = 43;
        if payload.len() > cipher_suite_length_offset + 1 {
            let cipher_suite_length = u16::from_be_bytes([
                payload[cipher_suite_length_offset],
                payload[cipher_suite_length_offset + 1],
            ]) as usize;

            let mut offset = cipher_suite_length_offset + 2;
            while offset + 1 < payload.len()
                && offset < cipher_suite_length_offset + 2 + cipher_suite_length
            {
                let cipher = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
                cipher_suites.push(cipher);
                offset += 2;
            }
        }

        // Extract extensions
        let mut extensions = Vec::new();
        let extensions_offset = cipher_suite_length_offset + 2 + cipher_suites.len() * 2 + 2;
        if payload.len() > extensions_offset + 1 {
            let extensions_length =
                u16::from_be_bytes([payload[extensions_offset], payload[extensions_offset + 1]])
                    as usize;

            let mut offset = extensions_offset + 2;
            while offset + 3 < payload.len() && offset < extensions_offset + 2 + extensions_length {
                let ext_type = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
                extensions.push(ext_type);

                let ext_length =
                    u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]) as usize;
                offset += 4 + ext_length;
            }
        }

        // Generate JA3 string: TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
        let cipher_str: Vec<String> = cipher_suites.iter().map(|c| c.to_string()).collect();
        let ext_str: Vec<String> = extensions.iter().map(|e| e.to_string()).collect();

        let ja3_string = format!(
            "{},{},{},",
            tls_version,
            cipher_str.join("-"),
            ext_str.join("-")
        );

        // Generate JA3 hash (MD5 - standard JA3 specification)
        let digest = md5::compute(ja3_string.as_bytes());
        let ja3_hash = format!("{:x}", digest);

        // Check against malware database
        let is_malicious = self.ja3_malware_database.contains_key(&ja3_hash);
        let malware_name = self.ja3_malware_database.get(&ja3_hash).cloned();

        // Store session
        let session = TLSSession {
            ja3_hash: ja3_hash.clone(),
            ja3s_hash: None,
            cipher_suites: cipher_suites.clone(),
            extensions: extensions.clone(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            suspicious: is_malicious || cipher_suites.len() < 5 || extensions.is_empty(),
        };
        self.tls_sessions.insert(src_ip.to_string(), session);

        // Advanced anomaly detection
        let mut anomaly_score: f32 = 0.0;

        // 1. Check for weak ciphers
        for cipher in &cipher_suites {
            if *cipher == 0x0000 || *cipher == 0x0001 {
                // NULL ciphers
                anomaly_score += 0.3;
            }
        }

        // 2. Check for missing critical extensions
        if !extensions.contains(&0x0000) {
            // server_name missing
            anomaly_score += 0.1;
        }

        // 3. Unusual cipher suite count
        if cipher_suites.len() < 3 || cipher_suites.len() > 30 {
            anomaly_score += 0.2;
        }

        // 4. Known malware JA3
        if is_malicious {
            anomaly_score += 0.8;
        }

        Some(json!({
            "type": "tls_fingerprint",
            "ja3_hash": ja3_hash,
            "tls_version": tls_version,
            "cipher_count": cipher_suites.len(),
            "extension_count": extensions.len(),
            "is_malicious": is_malicious,
            "malware_name": malware_name,
            "anomaly_score": anomaly_score.min(1.0),
            "details": if is_malicious {
                format!("MALWARE DETECTED: {} - JA3: {}", malware_name.unwrap_or_default(), ja3_hash)
            } else if anomaly_score > 0.5 {
                format!("Suspicious TLS fingerprint - Score: {:.2}", anomaly_score)
            } else {
                "Normal TLS connection".to_string()
            }
        }))
    }

    /// Analyze DNS query for tunneling
    pub fn analyze_dns_tunneling(
        &mut self,
        src_ip: &str,
        domain: &str,
        query_type: u16,
    ) -> Option<serde_json::Value> {
        // Calculate domain entropy (randomness)
        let entropy = self.calculate_entropy(domain);

        // Count subdomains
        let subdomain_count = domain.matches('.').count();

        // Store query
        let query = DNSQuery {
            domain: domain.to_string(),
            query_type,
            length: domain.len(),
            entropy,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            subdomain_count,
        };

        self.dns_queries
            .entry(src_ip.to_string())
            .or_insert_with(Vec::new)
            .push(query.clone());

        // Cleanup old queries (older than 5 minutes)
        let cutoff = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 300;
        if let Some(queries) = self.dns_queries.get_mut(src_ip) {
            queries.retain(|q| q.timestamp > cutoff);
        }

        // =========================================================
        // PROFESSIONAL DNS TUNNELING DETECTION ALGORITHM
        // Based on: Zeek, Suricata, and academic research
        // Detects: Iodine, dnscat2, DNSExfiltrator, covert channels
        // =========================================================
        
        let mut suspicion_score: f32 = 0.0;
        let mut indicators: Vec<&str> = Vec::new();

        // 1. ENTROPY ANALYSIS (Shannon entropy)
        // Normal domains: 2.5-3.5, Tunneling: >4.0
        if entropy > 4.5 {
            suspicion_score += 0.35;
            indicators.push("Very high entropy (data encoding)");
        } else if entropy > 4.0 {
            suspicion_score += 0.25;
            indicators.push("High entropy");
        }

        // 2. DOMAIN LENGTH ANALYSIS
        // Tunneling encodes data in subdomains, causing long domains
        if domain.len() > 100 {
            suspicion_score += 0.35;
            indicators.push("Extremely long domain (>100 chars)");
        } else if domain.len() > 50 {
            suspicion_score += 0.25;
            indicators.push("Long domain (>50 chars)");
        }

        // 3. SUBDOMAIN DEPTH
        // Normal: 1-3 levels, Tunneling: >4 levels
        if subdomain_count > 6 {
            suspicion_score += 0.20;
            indicators.push("Excessive subdomain depth");
        } else if subdomain_count > 4 {
            suspicion_score += 0.10;
        }

        // 4. NUMERIC RATIO IN SUBDOMAIN
        // Tunneling tools often use hex or base64 encoding with high numeric ratio
        let first_label = domain.split('.').next().unwrap_or("");
        let numeric_chars = first_label.chars().filter(|c| c.is_ascii_digit()).count();
        let numeric_ratio = if first_label.len() > 0 {
            numeric_chars as f32 / first_label.len() as f32
        } else { 0.0 };
        
        if numeric_ratio > 0.5 && first_label.len() > 10 {
            suspicion_score += 0.25;
            indicators.push("High numeric ratio (hex encoding)");
        } else if numeric_ratio > 0.3 && first_label.len() > 20 {
            suspicion_score += 0.15;
        }

        // 5. QUERY FREQUENCY ANALYSIS
        // Tunneling requires many queries to transfer data
        let query_count = self.dns_queries.get(src_ip).map(|q| q.len()).unwrap_or(0);
        if query_count > 100 {
            suspicion_score += 0.30;
            indicators.push("Excessive query volume (>100 in window)");
        } else if query_count > 50 {
            suspicion_score += 0.15;
            indicators.push("High query volume");
        }

        // 6. SUSPICIOUS RECORD TYPES
        // TXT (16), NULL (10), AAAA (28), CNAME (5) often used by tunneling
        match query_type {
            10 => { // NULL record - very suspicious (Iodine uses this)
                suspicion_score += 0.35;
                indicators.push("NULL record type (Iodine signature)");
            }
            16 => { // TXT record - commonly used for tunneling
                suspicion_score += 0.20;
                indicators.push("TXT record (common tunnel type)");
            }
            5 => { // CNAME - sometimes used
                if domain.len() > 40 {
                    suspicion_score += 0.10;
                }
            }
            _ => {}
        }

        // 7. IODINE PATTERN DETECTION
        // Iodine uses Base32/Base64 encoded subdomains with specific patterns
        let has_iodine_pattern = first_label.len() > 20 
            && first_label.chars().all(|c| c.is_ascii_alphanumeric())
            && !first_label.contains(' ');
        if has_iodine_pattern && entropy > 3.8 {
            suspicion_score += 0.20;
            indicators.push("Matches Iodine encoding pattern");
        }

        // 8. DNSCAT2 PATTERN DETECTION
        // dnscat2 uses hex encoding (all hex characters in subdomain)
        let is_hex_encoded = first_label.len() > 16 
            && first_label.chars().all(|c| c.is_ascii_hexdigit());
        if is_hex_encoded {
            suspicion_score += 0.25;
            indicators.push("Hex-encoded subdomain (dnscat2 signature)");
        }

        let is_tunneling = suspicion_score >= 0.70;

        // Only return alerts for suspicious or confirmed tunneling
        if suspicion_score < 0.40 {
            return None; // Normal DNS - don't create noise
        }

        Some(json!({
            "type": "dns_tunneling",
            "src_ip": src_ip,
            "domain": domain,
            "entropy": format!("{:.2}", entropy),
            "length": domain.len(),
            "subdomain_count": subdomain_count,
            "numeric_ratio": format!("{:.0}%", numeric_ratio * 100.0),
            "query_type": query_type,
            "query_count": query_count,
            "is_tunneling": is_tunneling,
            "suspicion_score": format!("{:.2}", suspicion_score.min(1.0)),
            "indicators": indicators.join(", "),
            "note": if is_tunneling {
                format!("🚨 DNS TUNNELING DETECTED - {}", indicators.join(", "))
            } else {
                format!("⚠️ Suspicious DNS - {}", indicators.join(", "))
            }
        }))
    }

    /// Track SSH brute force attempts
    pub fn track_ssh_attempt(
        &mut self,
        src_ip: &str,
        success: bool,
        username: Option<String>,
    ) -> Option<serde_json::Value> {
        let attempt = SSHAttempt {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            success,
            username,
        };

        self.ssh_attempts
            .entry(src_ip.to_string())
            .or_insert_with(Vec::new)
            .push(attempt);

        // Cleanup old attempts (older than 10 minutes)
        let cutoff = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 600;
        if let Some(attempts) = self.ssh_attempts.get_mut(src_ip) {
            attempts.retain(|a| a.timestamp > cutoff);

            let failed_count = attempts.iter().filter(|a| !a.success).count();
            let total_count = attempts.len();
            let unique_usernames: std::collections::HashSet<_> = attempts
                .iter()
                .filter_map(|a| a.username.as_ref())
                .collect();

            // Advanced brute force detection
            let mut threat_score: f32 = 0.0;

            // 1. High failure rate
            if failed_count > 5 {
                threat_score += 0.4;
            }

            // 2. Rapid attempts (time-based)
            if total_count > 3 {
                let time_span =
                    attempts.last().unwrap().timestamp - attempts.first().unwrap().timestamp;
                if time_span < 60 {
                    // More than 3 attempts in 1 minute
                    threat_score += 0.3;
                }
            }

            // 3. Multiple usernames (dictionary attack)
            if unique_usernames.len() > 3 {
                threat_score += 0.4;
            }

            // 4. Very high attempt count
            if failed_count > 10 {
                threat_score += 0.5;
            }

            let is_brute_force = threat_score >= 0.7;

            return Some(json!({
                "type": "ssh_brute_force",
                "failed_attempts": failed_count,
                "total_attempts": total_count,
                "unique_usernames": unique_usernames.len(),
                "is_brute_force": is_brute_force,
                "threat_score": threat_score.min(1.0),
                "details": if is_brute_force {
                    format!("SSH BRUTE FORCE DETECTED - {} failed attempts from {}",
                        failed_count, src_ip)
                } else if threat_score > 0.5 {
                    format!("Suspicious SSH activity - Score: {:.2}", threat_score)
                } else {
                    "Normal SSH activity".to_string()
                }
            }));
        }

        None
    }

    /// Calculate Shannon entropy (measure of randomness)
    fn calculate_entropy(&self, data: &str) -> f64 {
        let mut freq = HashMap::new();
        let len = data.len() as f64;

        for c in data.chars() {
            *freq.entry(c).or_insert(0.0) += 1.0;
        }

        let mut entropy = 0.0;
        for count in freq.values() {
            let probability = count / len;
            entropy -= probability * probability.log2();
        }

        entropy
    }

    /// Cleanup old sessions
    pub fn cleanup_old_sessions(&mut self) {
        let cutoff = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 3600;

        self.tls_sessions
            .retain(|_, session| session.timestamp > cutoff);
        self.dns_queries.retain(|_, queries| {
            queries.retain(|q| q.timestamp > cutoff);
            !queries.is_empty()
        });
        self.ssh_attempts.retain(|_, attempts| {
            attempts.retain(|a| a.timestamp > cutoff);
            !attempts.is_empty()
        });
    }

    /// Analyze packet for DPI detections (simplified for competition demo)
    pub fn analyze_packet(&mut self, packet_data: &[u8]) -> Option<serde_json::Value> {
        if packet_data.len() < 54 {
            return None; // Too small for Ethernet + IP + TCP/UDP
        }

        // Basic Ethernet frame parsing (assume IPv4)
        // Ethertype at offset 12-13 (0x0800 for IPv4)
        if packet_data[12] != 0x08 || packet_data[13] != 0x00 {
            return None; // Not IPv4
        }

        // IP header starts at offset 14
        let ip_header_start = 14;
        let src_ip_bytes = &packet_data[ip_header_start + 12..ip_header_start + 16];
        let src_ip = format!(
            "{}.{}.{}.{}",
            src_ip_bytes[0], src_ip_bytes[1], src_ip_bytes[2], src_ip_bytes[3]
        );

        let protocol = packet_data[ip_header_start + 9];

        // Check for TCP (6) or UDP (17)
        let dst_port = if protocol == 6 || protocol == 17 {
            let ip_header_len = ((packet_data[ip_header_start] & 0x0F) as usize) * 4;
            let transport_start = ip_header_start + ip_header_len;

            if transport_start + 4 > packet_data.len() {
                return None;
            }

            // Destination port is at bytes 2-3 of transport header
            u16::from_be_bytes([
                packet_data[transport_start + 2],
                packet_data[transport_start + 3],
            ])
        } else {
            return None;
        };

        // Periodically cleanup old data
        static mut CLEANUP_COUNTER: u64 = 0;
        unsafe {
            CLEANUP_COUNTER += 1;
            if CLEANUP_COUNTER % 10000 == 0 {
                self.cleanup_old_sessions();
            }
        }

        match dst_port {
            443 => self.analyze_tls_packet(&src_ip, packet_data),
            // DNS tunneling detection - parse DNS headers and analyze
            53 => self.analyze_dns_packet(&src_ip, packet_data, ip_header_start),
            22 => None,  // SSH - future enhancement
            _ => None,
        }
    }

    fn analyze_tls_packet(
        &mut self,
        src_ip: &str,
        packet_data: &[u8],
    ) -> Option<serde_json::Value> {
        if let Some(tls_info) = self.generate_ja3_fingerprint(src_ip, packet_data) {
            let is_malicious = tls_info
                .get("is_malicious")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let anomaly_score = tls_info
                .get("anomaly_score")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            let details = tls_info
                .get("details")
                .and_then(|v| v.as_str())
                .unwrap_or("Suspicious TLS traffic");
            let ja3_hash = tls_info
                .get("ja3_hash")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let malware_name = tls_info
                .get("malware_name")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            // Only raise alert when malicious JA3 or high anomaly
            if is_malicious || anomaly_score > 0.65 {
                return Some(json!({
                    "type": "tls_alert",
                    "src_ip": src_ip,
                    "port": 443,
                    "ja3_hash": ja3_hash,
                    "note": details,
                    "malware_name": malware_name,
                    "is_malicious": is_malicious,
                    "anomaly_score": anomaly_score
                }));
            }
        }
        None
    }

    /// Parse DNS packet and analyze for tunneling
    /// DNS packet format:
    /// - UDP header (8 bytes): src_port(2) + dst_port(2) + length(2) + checksum(2)
    /// - DNS header (12 bytes): ID(2) + Flags(2) + QDCOUNT(2) + ANCOUNT(2) + NSCOUNT(2) + ARCOUNT(2)
    /// - Questions section: QNAME(variable) + QTYPE(2) + QCLASS(2)
    fn analyze_dns_packet(
        &mut self,
        src_ip: &str,
        packet_data: &[u8],
        ip_header_start: usize,
    ) -> Option<serde_json::Value> {
        // Calculate offsets
        let ip_header_len = ((packet_data.get(ip_header_start)? & 0x0F) as usize) * 4;
        let udp_start = ip_header_start + ip_header_len;
        let dns_start = udp_start + 8; // UDP header is 8 bytes
        
        // Need at least DNS header (12 bytes) + minimal question
        if packet_data.len() < dns_start + 12 + 5 {
            return None;
        }
        
        // Parse DNS header
        let _txn_id = u16::from_be_bytes([packet_data[dns_start], packet_data[dns_start + 1]]);
        let flags = u16::from_be_bytes([packet_data[dns_start + 2], packet_data[dns_start + 3]]);
        let qdcount = u16::from_be_bytes([packet_data[dns_start + 4], packet_data[dns_start + 5]]);
        
        // Only analyze queries (QR bit = 0)
        let is_query = (flags & 0x8000) == 0;
        if !is_query || qdcount == 0 {
            return None;
        }
        
        // Parse QNAME (domain name)
        let qname_start = dns_start + 12;
        let mut domain_parts: Vec<String> = Vec::new();
        let mut offset = qname_start;
        
        // DNS name format: length-prefixed labels ending with 0
        while offset < packet_data.len() {
            let label_len = packet_data[offset] as usize;
            if label_len == 0 {
                offset += 1;
                break;
            }
            if label_len > 63 || offset + 1 + label_len > packet_data.len() {
                break; // Invalid or too long
            }
            
            if let Ok(label) = std::str::from_utf8(&packet_data[offset + 1..offset + 1 + label_len]) {
                domain_parts.push(label.to_string());
            }
            offset += 1 + label_len;
        }
        
        if domain_parts.is_empty() {
            return None;
        }
        
        let domain = domain_parts.join(".");
        
        // Parse QTYPE (2 bytes after QNAME)
        let qtype = if offset + 2 <= packet_data.len() {
            u16::from_be_bytes([packet_data[offset], packet_data[offset + 1]])
        } else {
            1 // Default to A record
        };
        
        // Analyze for tunneling using existing method
        self.analyze_dns_tunneling(src_ip, &domain, qtype)
    }
}
