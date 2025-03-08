OSINT IP Lookup Tool v1.01 - (Pre and Post-Compiled)

Description
This tool gathers intelligence on an IP address using multiple sources, including WHOIS, GeoIP, Shodan, AbuseIPDB, and optional Nmap scanning. It provides detailed insights such as ASN, location, ISP, open ports, and abuse reports.

This tool is useful for:
•	Network security professionals performing reconnaissance and enumeration.
•	Identifying malicious IPs in a firewall's zone makeup.
•	Enhancing threat intelligence with integrated API sources.

Features (Previous)
•	WHOIS Lookup: Retrieves ASN and subnet details.
•	GeoIP Lookup: Determines country, region, and ISP.
•	Shodan Scan: Identifies open ports and associated services. (Use yuor own API)
•	AbuseIPDB Check: Fetches malicious activity reports. (Use yuor own API)

New Feature (Current Version)
•	Optional Nmap Scan: Performs service/version detection.
•	-o [Output] save to a file for documentation.

Requirements
•	Python 3.x and Latest Nmap (https://nmap.org/download.html)

Required Python Modules install using pip (For Developer):
  - pip install requests ipwhois

[PRE-COMPILE]
[Pyinstaller as a compiler]
Compilation to Executable (Optional):
You can compile the script using PyInstaller:
  - pyinstaller --onefile "pywho.py"

API Keys Setup
This tool requires API keys for Shodan and AbuseIPDB. You can set them as environment variables or embed them directly into the script (not recommended for production).

Set Environment Variables: This is Hardcoded version, you may use another method to sanitize it.
SHODAN_API_KEY = "" 
ABUSEIPDB_API_KEY = ""

[POST-COMPILED]
Usage
usage: pywho [-h] [-w] [-g] [-sd] [-aip] [-o OUTPUT] [-v] ip

Command Options:
-h, --help	List Option
-w, --whois       Perform WHOIS lookup
-g, --geoip       Perform GeoIP lookup
-sd, --shodan     Perform Shodan lookup
-aip, --abuseipdb Check IP reputation on AbuseIPDB
-o, --output      Save results to a file
-v, --verbose     Enable verbose output

Example:
  - pywho.exe 8.8.8.8 -w -g -sd -aip -v

Upon execution, you will be prompted:
Do you want to scan the target IP with Nmap? (y/n)
Selecting 'y' will initiate an Nmap scan for additional insights.

Output
The tool displays:
•	WHOIS Information: ASN, subnet, country.
•	GeoIP Details: Location, ISP.
•	Open Ports: Identified via Shodan.
•	Abuse Reports: Fetched from AbuseIPDB.
•	Nmap Results (if selected): Service and version details.
  o	Nmap Syntax used : nmap -Sv -Pn -A (For quick recoonnaisance)

________________________________________________________________________________
For Developer suggestion, you may use this sourcecode freely.
To gain deeper insights into ASN and malicious subnet/IP neighbors, consider integrating the SpiderFoot API.

Future Recommended Integrations (Developer)
•	SpiderFoot API: For more in-depth threat intelligence.
•	VirusTotal API: To cross-check IP reputation.
•	Emerging Threat txt.

Disclaimer
This tool is for educational and research purposes only. Use it responsibly and ensure compliance with local laws and regulations.
________________________________________________________________________________
Author: Berzerker

