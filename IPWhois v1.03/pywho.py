# MIT License
# 
# Copyright (c) 2025 [Lyst]
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import sys
import socket
import argparse
import requests
import subprocess
import os
import re
from ipwhois import IPWhois
from concurrent.futures import ThreadPoolExecutor

# Hardcoded API Keys (FOR TESTING ONLY) suggest to use Env Header for security
SHODAN_API_KEY = ""
ABUSEIPDB_API_KEY = ""

# Safe directory for storing output files
OUTPUT_DIR = "outputs"
os.makedirs(OUTPUT_DIR, exist_ok=True)  # Ensure the directory exists

def display_banner():
    return "\nOSINT - IP Lookup [Version 1.02]\n(c) Lyxt. All rights reserved.\n"

def verbose_print(verbose, message):
    if verbose:
        print(f"[INFO] {message}")

def sanitize_filename(filename):
    """Sanitize filename to prevent Path Traversal (CWE-23)"""
    filename = re.sub(r"[^\w\-.]", "_", filename)  # Allow only safe characters
    return os.path.basename(filename)  # Prevent directory traversal

def resolve_domain(target):
    """Resolve domain name to IP address."""
    try:
        verbose_print(True, f"Resolving {target} to an IP address...")
        return socket.gethostbyname(target)
    except socket.gaierror:
        print(f"[ERROR] Unable to resolve {target} to an IP address.")
        sys.exit(1)

def whois_lookup(ip_address, verbose):
    try:
        verbose_print(verbose, f"Performing WHOIS lookup for {ip_address}...")
        obj = IPWhois(ip_address)
        result = obj.lookup_rdap()

        net_start = result.get('network', {}).get('start_address', 'N/A')
        net_end = result.get('network', {}).get('end_address', 'N/A')
        cidr = result.get('network', {}).get('cidr', 'N/A')
        asn = result.get('asn', 'N/A')
        country = result.get('asn_country_code', 'N/A')

        return (f"\n[ WHOIS Information ]\n"
                f"IP Address: {ip_address}\n"
                f"NetRange: {net_start} - {net_end}\n"
                f"CIDR: {cidr}\n"
                f"ASN: AS{asn}\n"
                f"Country: {country}\n")
    except Exception as e:
        return f"[ERROR] WHOIS lookup failed: {e}\n"

def geoip_lookup(ip_address, verbose):
    try:
        verbose_print(verbose, f"Performing GeoIP lookup for {ip_address}...")
        url = f"http://ip-api.com/json/{ip_address}"
        response = requests.get(url).json()
        return (f"\n[ GeoIP Information ]\n"
                f"Country Code: {response.get('countryCode', 'N/A')}\n"
                f"Region: {response.get('regionName', 'N/A')}\n"
                f"City: {response.get('city', 'N/A')}\n"
                f"Zip: {response.get('zip', 'N/A')}\n"
                f"Infra: {response.get('org', 'N/A')}\n"
                f"ISP: {response.get('isp', 'N/A')}\n"
                f"Latitude: {response.get('lat', 'N/A')}\n"
                f"Longitude: {response.get('lon', 'N/A')}\n"
                f"Timezone: {response.get('timezone', 'N/A')}\n")
    except Exception as e:
        return f"[ERROR] GeoIP lookup failed: {e}\n"

def shodan_lookup(ip_address, verbose):
    try:
        verbose_print(verbose, f"Querying Shodan for {ip_address}...")
        url = f"https://api.shodan.io/shodan/host/{ip_address}?key={SHODAN_API_KEY}"
        response = requests.get(url).json()
        if "error" in response:
            return f"\n[ Shodan Information ]\nError: {response['error']}\n"
        return (f"\n[ Shodan Information ]\n"
                f"Open Ports: {response.get('ports', 'N/A')}\n")
    except Exception as e:
        return f"[ERROR] Shodan lookup failed: {e}\n"

def abuseipdb_lookup(ip_address, verbose):
    try:
        verbose_print(verbose, f"Checking AbuseIPDB for {ip_address}...")
        headers = {"Accept": "application/json", "Key": ABUSEIPDB_API_KEY}
        params = {"ipAddress": ip_address, "maxAgeInDays": 90, "verbose": True}
        url = "https://api.abuseipdb.com/api/v2/check"
        response = requests.get(url, headers=headers, params=params)
        if response.status_code != 200:
            return f"\n[ AbuseIPDB Information ]\nError: {response.status_code} - {response.text}\n"
        data = response.json()
        if "data" not in data:
            return "\n[ AbuseIPDB Information ]\nNo data found for this IP.\n"
        abuse_data = data["data"]
        return (f"\n[ AbuseIPDB Information ]\n"
                f"Abuse Confidence Score: {abuse_data.get('abuseConfidenceScore', 'N/A')}\n")
    except Exception as e:
        return f"[ERROR] AbuseIPDB lookup failed: {e}\n"
    
def nmap_scan(ip_address, verbose):
    """Perform an Nmap scan on the target IP."""
    try:
        verbose_print(verbose, f"Running Nmap scan on {ip_address}...")
        command = ["nmap", "-sV", "-Pn", "-A", ip_address]
        result = subprocess.run(command, capture_output=True, text=True)
        return f"\n[ Nmap Scan Results ]\n{result.stdout}\n"
    except FileNotFoundError:
        return "[ERROR] Nmap is not installed or not found in system path.\n"
    except Exception as e:
        return f"[ERROR] Nmap scan failed: {e}\n"

def run_lookups(ip_address, options, verbose):
    results = ""
    with ThreadPoolExecutor() as executor:
        futures = {}
        if options["whois"]:
            futures["whois"] = executor.submit(whois_lookup, ip_address, verbose)
        if options["geoip"]:
            futures["geoip"] = executor.submit(geoip_lookup, ip_address, verbose)
        if options["shodan"]:
            futures["shodan"] = executor.submit(shodan_lookup, ip_address, verbose)
        if options["abuseipdb"]:
            futures["abuseipdb"] = executor.submit(abuseipdb_lookup, ip_address, verbose)
        if options["nmap"]:
            futures["nmap"] = executor.submit(nmap_scan, ip_address, verbose)
        
        for key, future in futures.items():
            results += future.result()
    return results

def main():
    parser = argparse.ArgumentParser(description="Perform OSINT lookups on an IP address or domain.")
    parser.add_argument("target", help="Target IP address or domain")
    parser.add_argument("-w", "--whois", action="store_true", help="Perform WHOIS lookup")
    parser.add_argument("-g", "--geoip", action="store_true", help="Perform GeoIP lookup")
    parser.add_argument("-sd", "--shodan", action="store_true", help="Perform Shodan lookup")
    parser.add_argument("-aip", "--abuseipdb", action="store_true", help="Check IP reputation on AbuseIPDB")
    parser.add_argument("-n", "--nmap", action="store_true", help="Perform an Nmap scan")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-o", "--output", help="Save results to a file")

    args = parser.parse_args()
    print(display_banner())

    ip_address = resolve_domain(args.target)
    options = vars(args)

    results = run_lookups(ip_address, options, args.verbose)
    print(results)

    if args.output:
        with open(os.path.join(OUTPUT_DIR, sanitize_filename(args.output)), "w") as f:
            f.write(results)
        print(f"[INFO] Results saved to {OUTPUT_DIR}/{args.output}")

if __name__ == "__main__":
    main()
