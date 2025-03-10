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

import os
import argparse
import requests
import subprocess
from ipwhois import IPWhois

# Hardcoded API Keys (FOR TESTING ONLY)
SHODAN_API_KEY = ""
ABUSEIPDB_API_KEY = ""


def display_banner():
    return "\nOSINT - IP Lookup [Version 1.01]\n(c) Lyst. All rights reserved.\n"


def verbose_print(verbose, message):
    if verbose:
        print(f"[INFO] {message}")


def save_output(output, filename):
    """ Saves the output safely """
    os.makedirs("outputs", exist_ok=True)
    safe_path = os.path.join("outputs", filename)
    try:
        with open(safe_path, "w", encoding="utf-8") as file:
            file.write(output)
        print(f"\n[+] Results saved to {safe_path}")
    except Exception as e:
        print(f"[ERROR] Failed to save output: {e}")


def whois_lookup(ip_address, verbose):
    try:
        verbose_print(verbose, f"Performing WHOIS lookup for {ip_address}...")
        obj = IPWhois(ip_address)
        result = obj.lookup_rdap()
        return (f"\n[ WHOIS Information ]\n"
                f"IP Address: {ip_address}\n"
                f"ASN: AS{result.get('asn', 'N/A')}\n"
                f"Country: {result.get('asn_country_code', 'N/A')}\n")
    except Exception as e:
        return f"[ERROR] WHOIS lookup failed: {e}\n"


def geoip_lookup(ip_address, verbose):
    try:
        verbose_print(verbose, f"Performing GeoIP lookup for {ip_address}...")
        url = f"http://ip-api.com/json/{ip_address}"
        response = requests.get(url).json()
        return (f"\n[ GeoIP Information ]\n"
                f"Country: {response.get('country', 'N/A')}\n"
                f"City: {response.get('city', 'N/A')}\n")
    except Exception as e:
        return f"[ERROR] GeoIP lookup failed: {e}\n"


def shodan_lookup(ip_address, verbose):
    try:
        verbose_print(verbose, f"Querying Shodan for {ip_address}...")
        url = f"https://api.shodan.io/shodan/host/{ip_address}?key={SHODAN_API_KEY}"
        response = requests.get(url).json()
        return (f"\n[ Shodan Information ]\n"
                f"ISP: {response.get('isp', 'N/A')}\n"
                f"City: {response.get('city', 'N/A')}\n")
    except Exception as e:
        return f"[ERROR] Shodan lookup failed: {e}\n"


def abuseipdb_lookup(ip_address, verbose):
    try:
        verbose_print(verbose, f"Querying AbuseIPDB for {ip_address}...")
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip_address}
        response = requests.get(url, headers=headers, params=params).json()
        return (f"\n[ AbuseIPDB Information ]\n"
                f"Score: {response.get('data', {}).get('abuseConfidenceScore', 'N/A')}\n")
    except Exception as e:
        return f"[ERROR] AbuseIPDB lookup failed: {e}\n"


def nmap_scan(ip_address):
    choice = input(f"\nDo you want to run an Nmap scan on {ip_address}? (y/n): ")
    if choice.lower() == 'y':
        print(f"\n[INFO] Running Nmap scan on {ip_address}...")
        try:
            result = subprocess.run(["nmap", "-sV", "-Pn", "-A", ip_address], capture_output=True, text=True)
            return f"\n[ Nmap Scan Results ]\n{result.stdout}\n"
        except Exception as e:
            return f"[ERROR] Nmap scan failed: {e}\n"
    return "\n[INFO] Nmap scan skipped.\n"


if __name__ == "__main__":
    banner = display_banner()
    print(banner)

    parser = argparse.ArgumentParser(description="Perform OSINT lookups on an IP address.")
    parser.add_argument("ip", help="Target IP address")
    parser.add_argument("-w", "--whois", action="store_true", help="Perform WHOIS lookup")
    parser.add_argument("-g", "--geoip", action="store_true", help="Perform GeoIP lookup")
    parser.add_argument("-sd", "--shodan", action="store_true", help="Perform Shodan lookup")
    parser.add_argument("-aip", "--abuseipdb", action="store_true", help="Check IP reputation on AbuseIPDB")
    parser.add_argument("-o", "--output", help="Save results to a file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

    args = parser.parse_args()
    verbose = args.verbose
    results = banner

    if args.whois:
        results += whois_lookup(args.ip, verbose)

    if args.geoip:
        results += geoip_lookup(args.ip, verbose)

    if args.shodan:
        results += shodan_lookup(args.ip, verbose)
    
    if args.abuseipdb:
        results += abuseipdb_lookup(args.ip, verbose)

    results += nmap_scan(args.ip)
    print(results)

    if args.output:
        save_output(results, args.output)

    if args.output:
        save_output(results, args.output)
