# OSINT IP Lookup Tool v1.03

## Description
OSINT IP Lookup Tool is an **Open-Source Intelligence (OSINT) IP Lookup Tool** that gathers intelligence on an IP address using multiple sources, including **WHOIS, GeoIP, Shodan, AbuseIPDB, and optional Nmap scanning**. It provides details such as:
- **ASN, Subnet, and Country** (WHOIS Lookup)
- **ISP and Location Information** (GeoIP Lookup)
- **Open Ports and Services** (Shodan Lookup)
- **Malicious Reports and Reputation** (AbuseIPDB Lookup)
- **Optional Service and Version Detection** (Nmap Scan)

This tool is useful for cybersecurity professionals, SOC analysts, incident responders, penetration testers, and network engineers before applying to your "NGFW" Allowlisting.

## Features include NEW Option. Major Updates
✅ **(NEW) - Reverse DNS Resolver for target information accuracy.
✅ **(NEW) - Python recently remove cgi within Request, unfortunately you may want to use HTTPX Header, but i recommend to use Python v3.12. You may face some issue according to the Header.

Security Fix (CWE-23 : Path Traversal Vulnerability)

def sanitize_filename(filename):
    """Sanitize filename to prevent Path Traversal (CWE-23)"""
    filename = re.sub(r"[^\w\-.]", "_", filename)  # Allow only safe characters
    return os.path.basename(filename)  # Prevent directory traversal

## Installation
### Prerequisites
Ensure you have **Python 3.x** and the latest version of **Nmap** installed on your system.

### Install Required Packages
  - pip install requests ipwhois

## Usage
pywho -h
usage: pywho [-h] [-w] [-g] [-sd] [-aip] [-n] [-v] [-o OUTPUT] ip

Perform OSINT lookups on an IP address.

positional arguments:
  ip                   Target IP address

options:
  -h, --help           show this help message and exit
  -w, --whois          Perform WHOIS lookup
  -g, --geoip          Perform GeoIP lookup
  -sd, --shodan        Perform Shodan lookup
  -aip, --abuseipdb    Check IP reputation on AbuseIPDB
  -n, --nmap           Run Nmap scan (-sV -Pn --top-ports 100 -T4)
  -v, --verbose        Enable verbose output
  -o, --output OUTPUT  Save results to a file

### API Key Setup
To use **Shodan** and **AbuseIPDB**, you must obtain API keys and set them in the script: (Current Script is Hardcoded, warning !!)
- **Shodan API Key:** Get it from [Shodan](https://www.shodan.io/)
- **AbuseIPDB API Key:** Get it from [AbuseIPDB](https://www.abuseipdb.com/)

Set them as environment variables: (We suggest to use python-dotenv)
Unsecure Option
 - SHODAN_API_KEY = "your_shodan_api_key"
 - ABUSEIPDB_API_KEY = "your_abuseipdb_api_key"

Secure Option
Create a .env File
 - In project directory, create a file named .env and store your API keys:
 - SHODAN_API_KEY=your_shodan_api_key_here
 - ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here


## Output Example
### WHOIS Information
[ WHOIS Information ]
IP Address: 8.8.8.8
Hostname: dns.google
ASN: AS15169
Subnet: 8.8.8.0/24
Country: US


### GeoIP Information
[ GeoIP Information ]
Country: United States
Region: California
City: Mountain View
ISP: Google LLC

### Shodan Information
[ Shodan Information ]
Open Ports: [53]
ISP: Google LLC
Country: United States

### AbuseIPDB Information
[ AbuseIPDB Information ]
Abuse Confidence Score: 0
Total Reports: 0
Last Reported: N/A

### Nmap Scan (Optional)
[ Nmap Scan Results ]
Open Ports: [80, 443]
Services: Apache, OpenSSH

## Use Cases
- **Threat Intelligence Analysts** – Investigate suspicious IPs.
- **SOC Analysts** – Check malicious IPs targeting an organization.
- **Incident Responders** – Identify attacker infrastructure.
- **Penetration Testers** – Gather passive intelligence on a target.
- **Network Engineers** – Investigate unusual traffic sources.

## Planned Features 🚀
- **SpiderFoot API Integration** for deeper ASN and subnet analysis.
    (Some idea in retrieving from WSL (Kali or any pre-installed Linux with Spiderfoot) or VM via http Locally or via 127.0.0.1, and let Spiderfoot do his job)
- **VirusTotal API Integration** for enhanced reputation checking.
- **Export results** to CSV or JSON.
- **GUI version** for ease of use. (I prefer CLI for direct Hardware Communication.

## Disclaimer
This tool is intended for educational and ethical cybersecurity research **only**. Unauthorized use is strictly prohibited.

## License
MIT License. Feel free to contribute and improve!

## Contributions
Pull requests and feature suggestions are welcome!
