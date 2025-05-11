# OSINT - IP Lookup [Version 1.03]

This Python script performs a series of OSINT lookups on an IP address or domain. It queries various services such as WHOIS, GeoIP, Shodan, AbuseIPDB, and runs Nmap scans to provide detailed security information. The script also allows you to save the results to a file and provides verbose output for debugging purposes.

## Features:
- **WHOIS Lookup**: Retrieve IP address range, ASN, and country information.
- **GeoIP Lookup**: Get geolocation details such as country, region, city, and ISP.
- **Shodan Lookup**: Query Shodan for open ports and devices related to the IP address.
- **AbuseIPDB Lookup**: Check the reputation of the IP address on AbuseIPDB.
- **Nmap Scan**: Run a full Nmap scan to detect open ports, services, and vulnerabilities.
- **Multithreaded**: Perform lookups in parallel for faster results.
- **File Output**: Save the results to a file in a safe directory, preventing directory traversal attacks.

## Requirements:
- **Python 3.x**: Ensure you have Python 3.x installed on your system.
- **Dependencies**: Install the required libraries:

## Dependencies
  pip install requests ipwhois

## License

This project is open-source and released under the [MIT License](https://mit-license.org/).

- Author : Lyxt
