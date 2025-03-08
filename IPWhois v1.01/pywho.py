import sys
import socket
import argparse
import requests
import subprocess
from ipwhois import IPWhois

# Hardcoded API Keys here (FOR TESTING ONLY)
SHODAN_API_KEY = "" 
ABUSEIPDB_API_KEY = ""

def display_banner():
    return "\nOSINT - IP Lookup [Version 1.01]\n(c) Lyxt. All rights reserved.\n"

def verbose_print(verbose, message):
    if verbose:
        print(f"[INFO] {message}")

def save_output(output, filename):
    with open(filename, "w", encoding="utf-8") as file:
        file.write(output)
    print(f"\n[+] Results saved to {filename}")

def whois_lookup(ip_address, verbose):
    try:
        verbose_print(verbose, f"Performing WHOIS lookup for {ip_address}...")
        print("[DEBUG] Running WHOIS lookup...")  # Debugging line
        hostname = socket.gethostbyaddr(ip_address)[0] if socket.gethostbyaddr(ip_address) else "No PTR record found"
        obj = IPWhois(ip_address)
        result = obj.lookup_rdap()
        
        return (f"\n[ WHOIS Information ]\n"
                f"IP Address: {ip_address}\n"
                f"Hostname: {hostname}\n"
                f"ASN: AS{result.get('asn', 'N/A')}\n"
                f"Subnet: {result.get('asn_cidr', 'N/A')}\n"
                f"Country: {result.get('asn_country_code', 'N/A')}\n")
    except Exception as e:
        return f"[ERROR] WHOIS lookup failed: {e}\n"

def geoip_lookup(ip_address, verbose):
    try:
        verbose_print(verbose, f"Performing GeoIP lookup for {ip_address}...")
        print("[DEBUG] Running GeoIP lookup...")  # Debugging line
        url = f"http://ip-api.com/json/{ip_address}"
        response = requests.get(url).json()
        
        return (f"\n[ GeoIP Information ]\n"
                f"Country: {response.get('country', 'N/A')}\n"
                f"Region: {response.get('regionName', 'N/A')}\n"
                f"City: {response.get('city', 'N/A')}\n"
                f"ISP: {response.get('isp', 'N/A')}\n"
                f"Organization: {response.get('org', 'N/A')}\n")
    except Exception as e:
        return f"[ERROR] GeoIP lookup failed: {e}\n"

def shodan_lookup(ip_address, verbose):
    try:
        verbose_print(verbose, f"Querying Shodan for {ip_address}...")
        print("[DEBUG] Running Shodan lookup...")  # Debugging line
        url = f"https://api.shodan.io/shodan/host/{ip_address}?key={SHODAN_API_KEY}"
        response = requests.get(url).json()
        
        if "error" in response:
            return f"\n[ Shodan Information ]\nError: {response['error']}\n"
        
        return (f"\n[ Shodan Information ]\n"
                f"Open Ports: {response.get('ports', 'N/A')}\n"
                f"Hostnames: {response.get('hostnames', 'N/A')}\n"
                f"ISP: {response.get('isp', 'N/A')}\n"
                f"City: {response.get('city', 'N/A')}\n"
                f"Country: {response.get('country_name', 'N/A')}\n")
    except Exception as e:
        return f"[ERROR] Shodan lookup failed: {e}\n"

def abuseipdb_lookup(ip_address, verbose):
    try:
        verbose_print(verbose, f"Checking AbuseIPDB for {ip_address}...")
        print("[DEBUG] Running AbuseIPDB lookup...")  # Debugging line
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
                f"Abuse Confidence Score: {abuse_data.get('abuseConfidenceScore', 'N/A')}\n"
                f"ISP: {abuse_data.get('isp', 'N/A')}\n"
                f"Domain: {abuse_data.get('domain', 'N/A')}\n"
                f"Total Reports: {abuse_data.get('totalReports', 'N/A')}\n"
                f"Last Reported: {abuse_data.get('lastReportedAt', 'N/A')}\n")
    except Exception as e:
        return f"[ERROR] AbuseIPDB lookup failed: {e}\n"

def nmap_scan(ip_address):
    print(f"\n[INFO] Running Nmap scan on {ip_address}...")
    try:
        result = subprocess.run(["nmap", "-sV", "-Pn", "-A", ip_address], capture_output=True, text=True)
        return f"\n[ Nmap Scan Results ]\n{result.stdout}\n"
    except Exception as e:
        return f"[ERROR] Nmap scan failed: {e}\n"

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
        print("[DEBUG] Adding WHOIS results...")  # Debugging line
        results += whois_lookup(args.ip, verbose)
    
    if args.geoip:
        print("[DEBUG] Adding GeoIP results...")  # Debugging line
        results += geoip_lookup(args.ip, verbose)
    
    if args.shodan:
        results += shodan_lookup(args.ip, verbose)
    
    if args.abuseipdb:
        results += abuseipdb_lookup(args.ip, verbose)
    
    user_input = input("Do you want to scan the target IP with Nmap? (y/n): ").strip().lower()
    if user_input == "y":
        results += nmap_scan(args.ip)
    else:
        print("Skipping Nmap scan...")

    print(results)

    if args.output:
        save_output(results, args.output)
