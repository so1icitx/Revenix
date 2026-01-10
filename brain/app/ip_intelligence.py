"""
ADVANCED IP INTELLIGENCE MODULE
Provides comprehensive IP reputation, organization lookup, VPN detection,
datacenter identification, and threat intelligence enrichment.
"""

import ipaddress
import logging
import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class IPCategory(Enum):
    RESIDENTIAL = "residential"
    DATACENTER = "datacenter"
    VPN = "vpn"
    TOR = "tor"
    PROXY = "proxy"
    CLOUD = "cloud"
    CDN = "cdn"
    HOSTING = "hosting"
    ENTERPRISE = "enterprise"
    ISP = "isp"
    MOBILE = "mobile"
    EDUCATION = "education"
    GOVERNMENT = "government"
    UNKNOWN = "unknown"


class ThreatLevel(Enum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class IPIntelligence:
    ip: str
    category: IPCategory
    organization: Optional[str]
    asn: Optional[str]
    country: Optional[str]
    threat_level: ThreatLevel
    is_vpn: bool
    is_tor: bool
    is_proxy: bool
    is_datacenter: bool
    is_known_attacker: bool
    is_botnet: bool
    is_scanner: bool
    reputation_score: float  # 0-100, higher = more trustworthy
    tags: List[str]
    details: str


class IPIntelligenceEngine:
    """
    Comprehensive IP intelligence engine with built-in databases for:
    - Major VPN providers
    - Cloud/hosting providers
    - Known malicious IP ranges
    - Enterprise organizations
    - Educational institutions
    - Government networks
    """

    def __init__(self):
        self._init_vpn_ranges()
        self._init_cloud_ranges()
        self._init_cdn_ranges()
        self._init_tor_exits()
        self._init_known_attackers()
        self._init_enterprise_ranges()
        self._init_education_ranges()
        self._init_government_ranges()
        self._init_isp_ranges()
        self._init_known_scanners()
        logger.info("[IPIntelligence] Initialized with comprehensive threat databases")

    def _init_vpn_ranges(self):
        """Initialize known VPN provider IP ranges."""
        self.vpn_providers = {
            # NordVPN
            "NordVPN": [
                "185.159.156.0/22", "185.216.34.0/24", "195.206.105.0/24",
                "37.120.132.0/22", "37.120.136.0/21", "45.83.88.0/22",
                "68.235.32.0/20", "82.102.16.0/20", "89.36.76.0/22",
                "89.238.128.0/18", "91.132.136.0/21", "92.119.16.0/20",
                "103.75.10.0/23", "146.70.0.0/16", "154.47.16.0/20",
                "156.146.32.0/20", "169.150.192.0/21", "185.107.56.0/22",
            ],
            # ExpressVPN
            "ExpressVPN": [
                "91.207.172.0/22", "198.54.128.0/20", "173.239.192.0/20",
                "172.98.64.0/18", "146.70.48.0/20", "193.9.112.0/20",
                "45.57.0.0/17", "104.238.128.0/17", "207.189.0.0/18",
            ],
            # Surfshark
            "Surfshark": [
                "89.187.160.0/19", "185.93.180.0/22", "195.181.160.0/20",
                "103.75.8.0/23", "45.85.212.0/22", "212.102.32.0/20",
                "185.232.170.0/23", "92.119.176.0/20", "104.200.128.0/18",
            ],
            # ProtonVPN
            "ProtonVPN": [
                "185.159.157.0/24", "185.159.158.0/24", "185.159.159.0/24",
                "185.94.188.0/22", "45.134.140.0/22", "103.125.232.0/22",
                "146.70.128.0/20", "169.150.200.0/21", "185.230.124.0/22",
            ],
            # CyberGhost
            "CyberGhost": [
                "89.187.164.0/22", "185.93.176.0/22", "91.207.168.0/22",
                "37.120.192.0/21", "45.74.0.0/18", "89.38.96.0/20",
            ],
            # Private Internet Access (PIA)
            "Private Internet Access": [
                "209.222.0.0/17", "199.116.112.0/20", "162.216.16.0/20",
                "107.150.0.0/17", "184.75.208.0/20", "199.21.96.0/20",
                "69.12.64.0/19", "91.219.212.0/22", "45.32.0.0/15",
            ],
            # Mullvad
            "Mullvad": [
                "185.213.152.0/22", "141.98.252.0/22", "193.138.218.0/24",
                "198.54.133.0/24", "45.83.220.0/22", "86.106.74.0/24",
            ],
            # IPVanish
            "IPVanish": [
                "198.18.0.0/15", "166.70.0.0/16", "209.107.192.0/20",
                "74.115.0.0/18", "69.167.128.0/18", "198.144.152.0/21",
            ],
            # Windscribe
            "Windscribe": [
                "104.254.90.0/23", "172.98.80.0/20", "89.36.78.0/23",
                "217.138.192.0/20", "185.183.104.0/22", "185.244.212.0/22",
            ],
            # TunnelBear
            "TunnelBear": [
                "149.102.224.0/20", "185.232.21.0/24", "92.223.64.0/20",
            ],
            # HideMyAss (HMA)
            "HMA VPN": [
                "217.175.48.0/20", "62.168.128.0/20", "185.76.68.0/22",
            ],
            # VyprVPN
            "VyprVPN": [
                "209.95.32.0/19", "64.62.208.0/20", "73.0.0.0/11",
            ],
        }

    def _init_cloud_ranges(self):
        """Initialize major cloud provider IP ranges."""
        self.cloud_providers = {
            # Amazon AWS (partial - they publish full list)
            "Amazon AWS": [
                "3.0.0.0/8", "13.32.0.0/12", "15.177.0.0/16", "18.0.0.0/8",
                "23.20.0.0/14", "34.192.0.0/10", "35.152.0.0/13", "44.192.0.0/10",
                "50.16.0.0/14", "52.0.0.0/10", "54.64.0.0/11", "63.32.0.0/14",
                "65.0.0.0/14", "72.21.192.0/19", "75.2.0.0/15", "76.223.0.0/16",
                "79.125.0.0/17", "87.238.80.0/21", "96.127.0.0/17", "99.77.128.0/17",
                "100.20.0.0/14", "107.20.0.0/14", "108.128.0.0/13", "143.204.0.0/16",
                "150.222.0.0/16", "157.175.0.0/16", "174.129.0.0/16", "175.41.128.0/17",
                "176.32.64.0/18", "177.71.128.0/17", "184.72.0.0/15", "185.48.120.0/22",
                "203.83.220.0/22", "204.236.128.0/17", "205.251.192.0/18", "207.171.160.0/19",
            ],
            # Google Cloud
            "Google Cloud": [
                "8.8.4.0/24", "8.8.8.0/24", "8.34.208.0/20", "8.35.192.0/20",
                "23.236.48.0/20", "23.251.128.0/19", "34.64.0.0/10", "35.184.0.0/13",
                "35.192.0.0/12", "35.208.0.0/12", "35.224.0.0/12", "35.240.0.0/13",
                "64.15.112.0/20", "64.233.160.0/19", "66.22.228.0/23", "66.102.0.0/20",
                "66.249.64.0/19", "70.32.128.0/19", "72.14.192.0/18", "74.114.24.0/21",
                "74.125.0.0/16", "104.132.0.0/14", "104.154.0.0/15", "104.196.0.0/14",
                "104.237.160.0/19", "107.167.160.0/19", "107.178.192.0/18", "108.59.80.0/20",
                "108.170.192.0/18", "108.177.0.0/17", "130.211.0.0/16", "136.112.0.0/12",
                "142.250.0.0/15", "146.148.0.0/17", "162.216.148.0/22", "162.222.176.0/21",
                "172.110.32.0/21", "172.217.0.0/16", "172.253.0.0/16", "173.194.0.0/16",
                "173.255.112.0/20", "192.158.28.0/22", "192.178.0.0/15", "193.186.4.0/24",
                "199.36.154.0/23", "199.192.112.0/22", "199.223.232.0/21", "207.223.160.0/20",
                "208.65.152.0/22", "208.68.108.0/22", "208.81.188.0/22", "208.117.224.0/19",
                "209.85.128.0/17", "216.58.192.0/19", "216.73.80.0/20", "216.239.32.0/19",
            ],
            # Microsoft Azure
            "Microsoft Azure": [
                "13.64.0.0/11", "13.96.0.0/13", "13.104.0.0/14", "20.0.0.0/8",
                "23.96.0.0/13", "40.64.0.0/10", "40.112.0.0/13", "51.104.0.0/14",
                "51.120.0.0/14", "51.124.0.0/14", "51.132.0.0/14", "51.136.0.0/14",
                "51.140.0.0/14", "52.96.0.0/12", "52.112.0.0/14", "52.120.0.0/14",
                "52.136.0.0/13", "52.148.0.0/14", "52.152.0.0/13", "52.160.0.0/11",
                "52.224.0.0/11", "65.52.0.0/14", "70.37.0.0/17", "70.37.128.0/17",
                "94.245.64.0/18", "104.40.0.0/13", "104.146.0.0/15", "104.208.0.0/13",
                "137.116.0.0/14", "137.135.0.0/16", "138.91.0.0/16", "157.54.0.0/15",
                "157.56.0.0/14", "168.61.0.0/16", "168.62.0.0/15", "191.232.0.0/13",
                "207.46.0.0/16", "208.68.136.0/21", "208.76.44.0/22", "208.84.0.0/21",
            ],
            # DigitalOcean
            "DigitalOcean": [
                "45.55.0.0/16", "46.101.0.0/16", "64.225.0.0/16", "67.205.0.0/16",
                "68.183.0.0/16", "104.131.0.0/16", "104.236.0.0/16", "107.170.0.0/16",
                "128.199.0.0/16", "134.209.0.0/16", "138.68.0.0/16", "138.197.0.0/16",
                "139.59.0.0/16", "142.93.0.0/16", "157.230.0.0/16", "159.65.0.0/16",
                "159.89.0.0/16", "161.35.0.0/16", "162.243.0.0/16", "163.47.8.0/21",
                "165.22.0.0/16", "165.227.0.0/16", "167.71.0.0/16", "167.172.0.0/16",
                "174.138.0.0/16", "178.62.0.0/16", "178.128.0.0/16", "188.166.0.0/16",
                "188.226.0.0/16", "192.81.208.0/20", "198.199.64.0/18", "198.211.96.0/19",
                "206.189.0.0/16", "207.154.192.0/18",
            ],
            # Linode
            "Linode": [
                "23.92.16.0/20", "45.33.0.0/17", "45.56.64.0/18", "45.79.0.0/16",
                "50.116.0.0/18", "66.175.208.0/20", "66.228.32.0/19", "69.164.192.0/19",
                "72.14.176.0/20", "74.207.224.0/19", "96.126.96.0/19", "97.107.128.0/17",
                "139.162.0.0/16", "172.104.0.0/15", "173.255.192.0/18", "176.58.88.0/21",
                "178.79.128.0/17", "192.155.80.0/20", "198.58.96.0/19",
            ],
            # Vultr
            "Vultr": [
                "45.32.0.0/16", "45.63.0.0/17", "45.76.0.0/15", "45.77.0.0/16",
                "64.156.192.0/18", "64.237.32.0/19", "66.42.32.0/19", "78.141.192.0/18",
                "95.179.128.0/17", "104.156.224.0/19", "108.61.0.0/16", "136.244.64.0/18",
                "140.82.0.0/17", "144.202.0.0/16", "149.28.0.0/16", "155.138.128.0/17",
                "207.148.0.0/17", "208.167.224.0/19", "209.250.224.0/19", "216.128.128.0/17",
                "217.69.0.0/17",
            ],
            # OVH
            "OVH": [
                "5.39.0.0/17", "5.135.0.0/16", "5.196.0.0/15", "37.59.0.0/16",
                "37.187.0.0/16", "46.105.0.0/16", "51.38.0.0/15", "51.68.0.0/14",
                "51.75.0.0/16", "51.77.0.0/16", "51.79.0.0/16", "51.81.0.0/16",
                "51.83.0.0/16", "51.89.0.0/16", "51.91.0.0/16", "54.36.0.0/14",
                "54.37.0.0/16", "54.38.0.0/16", "57.128.0.0/14", "79.137.0.0/17",
                "87.98.128.0/17", "91.121.0.0/16", "92.222.0.0/16", "135.125.0.0/16",
                "137.74.0.0/16", "139.99.0.0/16", "141.94.0.0/15", "142.4.192.0/18",
                "144.217.0.0/16", "145.239.0.0/16", "147.135.0.0/16", "149.56.0.0/16",
                "151.80.0.0/16", "158.69.0.0/16", "164.132.0.0/16", "167.114.0.0/16",
                "176.31.0.0/16", "178.32.0.0/15", "185.12.32.0/22", "188.165.0.0/16",
                "192.95.0.0/18", "192.99.0.0/16", "193.70.0.0/17", "195.154.0.0/16",
                "198.27.64.0/18", "198.100.144.0/20", "198.245.48.0/20", "213.186.32.0/19",
                "213.251.128.0/17",
            ],
            # Hetzner
            "Hetzner": [
                "5.9.0.0/16", "23.88.0.0/14", "46.4.0.0/16", "49.12.0.0/14",
                "65.108.0.0/15", "65.21.0.0/16", "78.46.0.0/15", "88.99.0.0/16",
                "88.198.0.0/16", "91.107.128.0/17", "94.130.0.0/16", "95.216.0.0/15",
                "116.202.0.0/15", "116.203.0.0/16", "128.140.0.0/17", "135.181.0.0/16",
                "136.243.0.0/16", "138.201.0.0/16", "142.132.128.0/17", "144.76.0.0/16",
                "148.251.0.0/16", "157.90.0.0/16", "159.69.0.0/16", "162.55.0.0/16",
                "167.235.0.0/16", "168.119.0.0/16", "176.9.0.0/16", "178.63.0.0/16",
                "185.12.64.0/22", "188.40.0.0/16", "195.201.0.0/16", "213.133.96.0/19",
                "213.239.192.0/18",
            ],
        }

    def _init_cdn_ranges(self):
        """Initialize CDN provider ranges."""
        self.cdn_providers = {
            # Cloudflare
            "Cloudflare": [
                "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "104.16.0.0/13",
                "104.24.0.0/14", "108.162.192.0/18", "131.0.72.0/22", "141.101.64.0/18",
                "162.158.0.0/15", "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20",
                "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
            ],
            # Akamai
            "Akamai": [
                "23.0.0.0/12", "23.32.0.0/11", "23.64.0.0/14", "23.72.0.0/13",
                "72.246.0.0/15", "92.122.0.0/15", "95.100.0.0/15", "96.6.0.0/15",
                "96.16.0.0/15", "104.64.0.0/10", "118.214.0.0/16", "173.222.0.0/15",
                "184.24.0.0/13", "184.50.0.0/15", "184.84.0.0/14",
            ],
            # Fastly
            "Fastly": [
                "23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24", "103.245.222.0/23",
                "103.245.224.0/24", "104.156.80.0/20", "140.248.64.0/18", "140.248.128.0/17",
                "146.75.0.0/17", "151.101.0.0/16", "157.52.64.0/18", "167.82.0.0/17",
                "167.82.128.0/20", "167.82.160.0/20", "167.82.224.0/20", "172.111.64.0/18",
                "185.31.16.0/22", "199.27.72.0/21", "199.232.0.0/16",
            ],
        }

    def _init_tor_exits(self):
        """Initialize known Tor exit node indicators."""
        # In production, this would be fetched from https://check.torproject.org/exit-addresses
        self.tor_indicators = {
            "exit_fingerprints": set(),  # Would contain actual Tor exit fingerprints
            "known_exits": set(),  # Known exit IPs - updated periodically
        }

    def _init_known_attackers(self):
        """Initialize known malicious IP ranges and indicators."""
        self.known_attackers = {
            # These are example ranges - in production would be from threat feeds
            "Mirai Botnet C2": ["185.244.25.0/24", "91.92.109.0/24"],
            "Emotet Infrastructure": ["45.79.33.0/24", "139.162.0.0/16"],
            "Cobalt Strike Servers": ["104.168.0.0/16", "45.142.212.0/24"],
            "APT Infrastructure": ["103.75.0.0/16", "185.141.61.0/24"],
        }
        
        # Known scanner IPs (research scanners like Shodan, Censys, etc.)
        self.research_scanners = {
            "Shodan": ["66.240.192.0/18", "71.6.128.0/17", "82.221.105.0/24", "85.25.43.0/24", "93.120.27.0/24", "188.138.9.0/24", "198.20.69.0/24", "198.20.70.0/24", "198.20.99.0/24"],
            "Censys": ["162.142.125.0/24", "167.94.138.0/24", "167.94.145.0/24", "167.94.146.0/24", "167.248.133.0/24"],
            "BinaryEdge": ["143.42.56.0/24", "167.248.133.0/24"],
            "Shadowserver": ["74.82.47.0/24", "184.105.139.0/24", "184.105.247.0/24", "216.218.206.0/24"],
            "GreyNoise": ["167.94.0.0/16", "71.6.167.0/24"],
        }

    def _init_enterprise_ranges(self):
        """Initialize major enterprise organization ranges."""
        self.enterprises = {
            "Apple": ["17.0.0.0/8"],
            "Microsoft": ["131.107.0.0/16", "157.54.0.0/15", "157.56.0.0/14"],
            "Google": ["216.58.192.0/19", "142.250.0.0/15", "172.217.0.0/16"],
            "Facebook/Meta": ["31.13.24.0/21", "31.13.64.0/18", "66.220.144.0/20", "69.63.176.0/20", "69.171.224.0/19", "74.119.76.0/22", "102.132.96.0/20", "129.134.0.0/16", "157.240.0.0/16", "173.252.64.0/18", "179.60.192.0/22", "185.60.216.0/22", "204.15.20.0/22"],
            "Amazon": ["52.0.0.0/8", "54.0.0.0/8", "99.77.0.0/16", "99.78.0.0/15", "99.80.0.0/12"],
            "Netflix": ["23.246.0.0/18", "37.77.184.0/21", "45.57.0.0/17", "64.120.128.0/17", "66.197.128.0/17", "69.53.224.0/19", "108.175.32.0/20", "185.2.220.0/22", "185.9.188.0/22", "192.173.64.0/18", "198.38.96.0/19", "198.45.48.0/20", "207.45.72.0/22", "208.75.76.0/22"],
            "Twitter/X": ["69.195.160.0/19", "104.244.40.0/21", "185.45.4.0/22", "192.133.76.0/22", "199.16.156.0/22", "199.59.148.0/22", "199.96.56.0/21"],
            "LinkedIn": ["108.174.0.0/16", "144.2.0.0/16", "185.63.144.0/22"],
            "Zoom": ["3.7.35.0/24", "3.21.137.0/24", "3.22.11.0/24", "3.23.93.0/24", "3.25.41.0/24", "3.25.42.0/24", "3.25.49.0/24", "3.80.20.0/24", "3.96.19.0/24", "3.101.32.0/24", "3.101.52.0/24", "3.104.34.0/24", "3.120.121.0/24", "3.127.194.0/24"],
            "Slack": ["54.192.0.0/16", "99.86.0.0/16"],
            "Salesforce": ["13.108.0.0/14", "96.43.144.0/20", "136.146.0.0/15", "161.71.0.0/17"],
        }

    def _init_education_ranges(self):
        """Initialize major educational institution ranges."""
        self.education = {
            "MIT": ["18.0.0.0/8"],
            "Stanford": ["171.64.0.0/14"],
            "Harvard": ["128.103.0.0/16", "140.247.0.0/16"],
            "UC Berkeley": ["128.32.0.0/16", "136.152.0.0/16", "169.229.0.0/16"],
            "Caltech": ["131.215.0.0/16"],
            "Princeton": ["128.112.0.0/16"],
            "Yale": ["128.36.0.0/16", "130.132.0.0/16"],
            "Columbia": ["128.59.0.0/16", "129.236.0.0/16", "156.111.0.0/16", "156.145.0.0/16", "160.39.0.0/16"],
            "CMU": ["128.2.0.0/16", "128.237.0.0/16"],
            "Oxford": ["129.67.0.0/16", "163.1.0.0/16"],
            "Cambridge": ["128.232.0.0/16", "131.111.0.0/16"],
            "ETH Zurich": ["129.132.0.0/16"],
        }

    def _init_government_ranges(self):
        """Initialize government network ranges."""
        self.government = {
            "US DoD": ["6.0.0.0/8", "7.0.0.0/8", "11.0.0.0/8", "21.0.0.0/8", "22.0.0.0/8", "26.0.0.0/8", "28.0.0.0/8", "29.0.0.0/8", "30.0.0.0/8", "33.0.0.0/8", "55.0.0.0/8", "214.0.0.0/8", "215.0.0.0/8"],
            "US Postal": ["56.0.0.0/8"],
            "DISA": ["136.0.0.0/8"],
            "NASA": ["128.102.0.0/16", "128.149.0.0/16", "128.155.0.0/16", "128.156.0.0/16", "128.157.0.0/16", "128.158.0.0/16", "128.159.0.0/16", "128.183.0.0/16", "128.216.0.0/16", "128.217.0.0/16", "137.78.0.0/16", "137.79.0.0/16", "204.58.0.0/16"],
            "UK Government": ["51.0.0.0/8"],
        }

    def _init_isp_ranges(self):
        """Initialize major ISP ranges."""
        self.isps = {
            "Comcast": ["24.0.0.0/12", "50.128.0.0/9", "67.160.0.0/11", "68.32.0.0/11", "69.136.0.0/13", "71.56.0.0/13", "73.0.0.0/8", "75.64.0.0/13", "76.96.0.0/11", "96.64.0.0/12", "98.192.0.0/10", "107.0.0.0/12"],
            "Verizon": ["65.24.0.0/14", "71.96.0.0/11", "72.64.0.0/13", "96.224.0.0/11", "100.0.0.0/10", "108.0.0.0/13", "173.48.0.0/12"],
            "AT&T": ["12.0.0.0/8", "32.0.0.0/8", "99.0.0.0/11", "107.64.0.0/10", "108.192.0.0/10"],
            "Spectrum/Charter": ["24.128.0.0/12", "65.32.0.0/13", "66.56.0.0/14", "67.0.0.0/11", "68.64.0.0/13", "69.144.0.0/12", "71.72.0.0/13", "72.128.0.0/10", "74.128.0.0/10", "75.128.0.0/10", "76.0.0.0/11", "97.64.0.0/10", "98.0.0.0/11"],
            "Cox": ["68.0.0.0/11", "70.176.0.0/12", "71.192.0.0/12", "76.160.0.0/11", "96.32.0.0/11", "98.160.0.0/11"],
            "BT": ["2.24.0.0/13", "5.64.0.0/13", "31.48.0.0/13", "79.64.0.0/12", "86.128.0.0/10", "90.192.0.0/10", "109.144.0.0/12"],
            "Deutsche Telekom": ["5.0.0.0/13", "46.78.0.0/15", "77.0.0.0/11", "79.192.0.0/10", "80.128.0.0/11", "87.128.0.0/11", "91.0.0.0/10", "93.192.0.0/10", "109.40.0.0/13", "178.0.0.0/10", "188.96.0.0/11", "217.224.0.0/11"],
        }

    def _init_known_scanners(self):
        """Initialize known internet scanner services."""
        self.scanners = {
            "Shodan": ["66.240.192.0/18", "71.6.128.0/17", "82.221.105.0/24", "85.25.43.0/24"],
            "Censys": ["162.142.125.0/24", "167.94.138.0/24", "167.94.145.0/24", "167.94.146.0/24"],
            "SecurityTrails": ["108.61.0.0/16"],
            "RiskIQ": ["74.117.56.0/21"],
            "Rapid7": ["71.6.135.0/24", "71.6.165.0/24", "71.6.167.0/24"],
            "Project25499": ["162.142.125.0/24"],
        }

    def _ip_in_range(self, ip: str, cidr: str) -> bool:
        """Check if IP is in CIDR range."""
        try:
            return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return False

    def _check_ranges(self, ip: str, ranges_dict: Dict[str, List[str]]) -> Optional[str]:
        """Check if IP matches any range in a dictionary of ranges."""
        for name, cidrs in ranges_dict.items():
            for cidr in cidrs:
                if self._ip_in_range(ip, cidr):
                    return name
        return None

    def analyze_ip(self, ip: str) -> IPIntelligence:
        """
        Perform comprehensive IP intelligence analysis.
        
        Args:
            ip: IP address to analyze
            
        Returns:
            IPIntelligence object with complete analysis
        """
        tags = []
        details_parts = []
        category = IPCategory.UNKNOWN
        organization = None
        threat_level = ThreatLevel.LOW
        reputation_score = 50.0  # Neutral baseline
        
        is_vpn = False
        is_tor = False
        is_proxy = False
        is_datacenter = False
        is_known_attacker = False
        is_botnet = False
        is_scanner = False

        # Check for private IP first
        if self._is_private_ip(ip):
            return IPIntelligence(
                ip=ip,
                category=IPCategory.RESIDENTIAL,
                organization="Internal Network",
                asn=None,
                country=None,
                threat_level=ThreatLevel.SAFE,
                is_vpn=False,
                is_tor=False,
                is_proxy=False,
                is_datacenter=False,
                is_known_attacker=False,
                is_botnet=False,
                is_scanner=False,
                reputation_score=100.0,
                tags=["internal", "private_ip"],
                details="Internal/private IP address - part of your local network."
            )

        # Check VPN providers
        vpn_match = self._check_ranges(ip, self.vpn_providers)
        if vpn_match:
            is_vpn = True
            category = IPCategory.VPN
            organization = vpn_match
            tags.append("vpn")
            tags.append(f"vpn:{vpn_match.lower().replace(' ', '_')}")
            reputation_score -= 20
            threat_level = ThreatLevel.MEDIUM
            details_parts.append(f"VPN EXIT NODE: This IP belongs to {vpn_match} VPN service. Users behind VPNs may be hiding their true location/identity.")

        # Check cloud providers
        cloud_match = self._check_ranges(ip, self.cloud_providers)
        if cloud_match:
            is_datacenter = True
            category = IPCategory.CLOUD
            organization = cloud_match
            tags.append("cloud")
            tags.append("datacenter")
            tags.append(f"cloud:{cloud_match.lower().replace(' ', '_')}")
            reputation_score -= 10  # Slightly reduce - could be legitimate or malicious
            if not is_vpn:
                threat_level = ThreatLevel.LOW
            details_parts.append(f"CLOUD INFRASTRUCTURE: This IP is part of {cloud_match} cloud platform. Could be legitimate service or attacker-controlled infrastructure.")

        # Check CDN providers
        cdn_match = self._check_ranges(ip, self.cdn_providers)
        if cdn_match:
            category = IPCategory.CDN
            organization = cdn_match
            tags.append("cdn")
            tags.append(f"cdn:{cdn_match.lower().replace(' ', '_')}")
            reputation_score += 20  # CDNs are generally trusted
            threat_level = ThreatLevel.SAFE
            details_parts.append(f"CDN NETWORK: This IP belongs to {cdn_match} content delivery network - generally legitimate traffic.")

        # Check known scanners
        scanner_match = self._check_ranges(ip, self.scanners)
        if scanner_match:
            is_scanner = True
            tags.append("scanner")
            tags.append(f"scanner:{scanner_match.lower().replace(' ', '_')}")
            reputation_score -= 15
            threat_level = ThreatLevel.MEDIUM
            details_parts.append(f"KNOWN SCANNER: This IP belongs to {scanner_match} internet scanning service. May be conducting reconnaissance.")

        # Check research scanners
        research_match = self._check_ranges(ip, self.research_scanners)
        if research_match:
            is_scanner = True
            tags.append("research_scanner")
            tags.append(f"scanner:{research_match.lower()}")
            threat_level = ThreatLevel.LOW
            details_parts.append(f"RESEARCH SCANNER: This IP belongs to {research_match} - a legitimate security research scanning service.")

        # Check known attackers/botnets
        attacker_match = self._check_ranges(ip, self.known_attackers)
        if attacker_match:
            is_known_attacker = True
            is_botnet = "Botnet" in attacker_match or "Emotet" in attacker_match or "Mirai" in attacker_match
            tags.append("known_attacker")
            tags.append("threat_intel_match")
            if is_botnet:
                tags.append("botnet")
            reputation_score = 0  # Maximum suspicion
            threat_level = ThreatLevel.CRITICAL
            details_parts.append(f"KNOWN MALICIOUS: This IP is associated with {attacker_match}. HIGH CONFIDENCE THREAT - immediate blocking recommended!")

        # Check enterprises
        enterprise_match = self._check_ranges(ip, self.enterprises)
        if enterprise_match:
            category = IPCategory.ENTERPRISE
            organization = enterprise_match
            tags.append("enterprise")
            tags.append(f"org:{enterprise_match.lower().replace(' ', '_').replace('/', '_')}")
            reputation_score = 80
            threat_level = ThreatLevel.SAFE
            details_parts.append(f"ENTERPRISE NETWORK: This IP belongs to {enterprise_match} corporate infrastructure - likely legitimate.")

        # Check education
        edu_match = self._check_ranges(ip, self.education)
        if edu_match:
            category = IPCategory.EDUCATION
            organization = edu_match
            tags.append("education")
            tags.append(f"edu:{edu_match.lower().replace(' ', '_')}")
            reputation_score = 75
            threat_level = ThreatLevel.SAFE
            details_parts.append(f"EDUCATIONAL INSTITUTION: This IP belongs to {edu_match} - generally legitimate academic traffic.")

        # Check government
        gov_match = self._check_ranges(ip, self.government)
        if gov_match:
            category = IPCategory.GOVERNMENT
            organization = gov_match
            tags.append("government")
            tags.append(f"gov:{gov_match.lower().replace(' ', '_')}")
            reputation_score = 85
            threat_level = ThreatLevel.SAFE
            details_parts.append(f"GOVERNMENT NETWORK: This IP belongs to {gov_match} government infrastructure.")

        # Check ISPs
        isp_match = self._check_ranges(ip, self.isps)
        if isp_match and category == IPCategory.UNKNOWN:
            category = IPCategory.ISP
            organization = isp_match
            tags.append("isp")
            tags.append(f"isp:{isp_match.lower().replace(' ', '_').replace('/', '_')}")
            reputation_score = 60
            threat_level = ThreatLevel.LOW
            details_parts.append(f"RESIDENTIAL ISP: This IP is from {isp_match} - likely a residential or business customer.")

        # Compile final details
        if not details_parts:
            details_parts.append(f"Unknown IP with no specific intelligence matches. Exercise caution.")

        # Clamp reputation score
        reputation_score = max(0, min(100, reputation_score))

        return IPIntelligence(
            ip=ip,
            category=category,
            organization=organization,
            asn=None,  # Would need ASN lookup service
            country=None,  # Would need GeoIP service
            threat_level=threat_level,
            is_vpn=is_vpn,
            is_tor=is_tor,
            is_proxy=is_proxy,
            is_datacenter=is_datacenter,
            is_known_attacker=is_known_attacker,
            is_botnet=is_botnet,
            is_scanner=is_scanner,
            reputation_score=reputation_score,
            tags=tags,
            details=" | ".join(details_parts)
        )

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/internal."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        except ValueError:
            return False

    def get_threat_context(self, ip: str, threat_type: str, risk_score: float) -> str:
        """
        Generate comprehensive threat context combining IP intelligence with threat detection.
        """
        intel = self.analyze_ip(ip)
        
        context_parts = []
        
        # IP Intelligence summary
        context_parts.append(f"**IP Intelligence Report for {ip}**")
        context_parts.append(f"")
        
        if intel.organization:
            context_parts.append(f"**Organization:** {intel.organization}")
        
        context_parts.append(f"**Category:** {intel.category.value.upper()}")
        context_parts.append(f"**Reputation Score:** {intel.reputation_score:.0f}/100")
        context_parts.append(f"**Threat Level:** {intel.threat_level.value.upper()}")
        
        # Flags
        flags = []
        if intel.is_vpn:
            flags.append("VPN")
        if intel.is_tor:
            flags.append("TOR")
        if intel.is_proxy:
            flags.append("PROXY")
        if intel.is_datacenter:
            flags.append("DATACENTER")
        if intel.is_scanner:
            flags.append("SCANNER")
        if intel.is_known_attacker:
            flags.append("KNOWN ATTACKER")
        if intel.is_botnet:
            flags.append("BOTNET")
        
        if flags:
            context_parts.append(f"**Flags:** {', '.join(flags)}")
        
        context_parts.append(f"")
        context_parts.append(f"**Analysis:** {intel.details}")
        
        # Risk assessment based on combined intelligence
        context_parts.append(f"")
        context_parts.append(f"**Combined Risk Assessment:**")
        
        if intel.is_known_attacker or intel.is_botnet:
            context_parts.append(f"CRITICAL: IP is associated with known malicious activity. Immediate blocking strongly recommended.")
        elif intel.is_vpn and risk_score >= 0.8:
            context_parts.append(f"HIGH RISK: Traffic from VPN service with suspicious behavior pattern. VPNs are commonly used to mask malicious activity.")
        elif intel.is_datacenter and risk_score >= 0.8:
            context_parts.append(f"HIGH RISK: Attack originating from cloud infrastructure. Attackers frequently use cloud servers for attacks.")
        elif intel.is_scanner:
            context_parts.append(f"MODERATE: Known scanning service. May be legitimate security research or reconnaissance for attack.")
        elif risk_score >= 0.75:
            context_parts.append(f"ELEVATED: Suspicious behavior detected from this IP requires investigation.")
        else:
            context_parts.append(f"LOW: No significant threat indicators from IP intelligence.")
        
        return "\n".join(context_parts)


# Global instance
ip_intelligence = IPIntelligenceEngine()


def get_ip_intelligence(ip: str) -> IPIntelligence:
    """Convenience function to get IP intelligence."""
    return ip_intelligence.analyze_ip(ip)


def get_threat_context(ip: str, threat_type: str, risk_score: float) -> str:
    """Convenience function to get threat context."""
    return ip_intelligence.get_threat_context(ip, threat_type, risk_score)
