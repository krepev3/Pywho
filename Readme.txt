OSINT IP Lookup Tool - (Pre and Post-Compiled)

Description
- This tool gathers intelligence on an IP address using multiple sources, including WHOIS, GeoIP, Shodan, and AbuseIPDB. It provides details like ASN, location, ISP, open ports, and abuse reports.
- Good tools for Network Security tools in enumerating the communicaiton between dmoain and internet.
- In case of Zone Makeup in Firewall, Integrating SpiderFoot API may give you more insight about the ASN and its Malicious Subnet/IP Neighbour to be watch)

Features
WHOIS lookup for ASN and subnet details.
GeoIP lookup to determine country, region, and ISP.
Shodan scan for open ports and associated services.
AbuseIPDB check for malicious activity reports.

Requirements:
Python 3.x

Required Python modules:
  - requests
  - ipwhois

You can install dependencies using:
  - pip install requests ipwhois
-AND Compile it using pyinstaller as binary:
  - pyinstaller.exe --onefile "pywho.py"

API Keys Setup (You may embed your API Keys for more insight about the target for your Reconnaissance Ops)
This tool requires API keys for Shodan and AbuseIPDB. Set them as environment variables before running the script:
  (Or you may design any API Key Platform to be use)

  - SHODAN_API_KEY = ""  # Replace with your Shodan API key
  - ABUSEIPDB_API_KEY = "" # Replace with your AbuseIPDB API key

Usage:
Run the script with an IP address as an argument:
  - pywho.exe <IP_ADDRESS>

Output
The tool will display:
  - WHOIS information (ASN, subnet, country)
  - GeoIP details (location, ISP)
  - Open ports from Shodan
  - Abuse reports from AbuseIPDB
(Suggest to integrate SpiderFoot and VT API for more insight)

Disclaimer
This tool is for educational and research purposes only. Use it responsibly and ensure compliance with local laws and regulations.
__________________________________________________________________________________________________________________________________
Author : Berzerker
