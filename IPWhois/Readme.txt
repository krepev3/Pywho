# OSINT IP Lookup Tool v1.00

## Description
PyWho is an **Open-Source Intelligence (OSINT) IP Lookup Tool** that gathers intelligence on an IP address using multiple sources, including **WHOIS, GeoIP, Shodan, and AbuseIPDB**. It provides details such as:
- **ASN, Subnet, and Country** (WHOIS Lookup)
- **ISP and Location Information** (GeoIP Lookup)
- **Open Ports and Services** (Shodan Lookup)
- **Malicious Reports and Reputation** (AbuseIPDB Lookup)

This tool is useful for cybersecurity professionals, SOC analysts, incident responders, penetration testers, and network engineers.

## Based Features
✅ **WHOIS Lookup** – Retrieves ASN, subnet, country, and organization details.
✅ **GeoIP Lookup** – Fetches ISP, country, region, city, and organization.
✅ **Shodan Lookup** – Checks open ports, services, hostnames, and ISP information.
✅ **AbuseIPDB Lookup** – Identifies reported malicious activities associated with the IP.
✅ **Cross-Platform Compatibility** – Runs on Windows, Linux, and macOS.
✅ **Lightweight and Fast** – No heavy dependencies.

## Installation
### Prerequisites
Ensure you have **Python 3.x** installed on your system.

### Install Required Packages
```bash
pip install requests ipwhois
```

## Usage
Run the tool with an IP address as an argument:
```bash
python pywho.py <IP_ADDRESS>
```
Example:
```bash
python pywho.py 8.8.8.8
```

### API Key Setup
To use **Shodan** and **AbuseIPDB**, you must obtain API keys and set them in the script:
- **Shodan API Key:** Get it from [Shodan](https://www.shodan.io/)
- **AbuseIPDB API Key:** Get it from [AbuseIPDB](https://www.abuseipdb.com/)

Replace these values in the script:
```python
SHODAN_API_KEY = "your_shodan_api_key"
ABUSEIPDB_API_KEY = "your_abuseipdb_api_key"
```

## Output Example
### WHOIS Information
```
[ WHOIS Information ]
IP Address: 8.8.8.8
Hostname: dns.google
ASN: AS15169
Subnet: 8.8.8.0/24
Country: US
```

### GeoIP Information
```
[ GeoIP Information ]
Country: United States
Region: California
City: Mountain View
ISP: Google LLC
```

### Shodan Information
```
[ Shodan Information ]
Open Ports: [53]
ISP: Google LLC
Country: United States
```

### AbuseIPDB Information
```
[ AbuseIPDB Information ]
Abuse Confidence Score: 0
Total Reports: 0
Last Reported: N/A
```

## Use Cases
- **Threat Intelligence Analysts** – Investigate suspicious IPs.
- **SOC Analysts** – Check malicious IPs targeting an organization.
- **Incident Responders** – Identify attacker infrastructure.
- **Penetration Testers** – Gather passive intelligence on a target.
- **Network Engineers** – Investigate unusual traffic sources.

## Planned Features 🚀
- **SpiderFoot API Integration** for deeper ASN and subnet analysis.
- **Export results** to CSV or JSON.
- **GUI version** for ease of use.

## Disclaimer
This tool is intended for educational and ethical cybersecurity research **only**. Unauthorized use is strictly prohibited.

## License
MIT License. Feel free to contribute and improve!

## Contributions
Pull requests and feature suggestions are welcome!

