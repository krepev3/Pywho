import sys
import socket
import requests
from ipwhois import IPWhois

# ✅ Set your API keys here
SHODAN_API_KEY = ""  # Replace with your Shodan API key
ABUSEIPDB_API_KEY = ""  # Replace with your AbuseIPDB API key

def whois_lookup(ip_address):
    """ Perform WHOIS lookup using IPWhois. """
    try:
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
        except socket.herror:
            hostname = "No PTR record found"

        try:
            cname = socket.gethostbyname_ex(hostname)[1]
            cname = cname[0] if cname else "No CNAME record found"
        except socket.gaierror:
            cname = "No CNAME record found"

        obj = IPWhois(ip_address)
        result = obj.lookup_rdap()

        asn = result.get("asn", "N/A")
        asn_cidr = result.get("asn_cidr", "N/A")
        country = result.get("asn_country_code", "N/A")

        print(f"\n[ WHOIS Information ]")
        print(f"IP Address: {ip_address}")
        print(f"Hostname: {hostname}")
        print(f"CNAME: {cname}")
        print(f"ASN: AS{asn}")
        print(f"Subnet: {asn_cidr}")
        print(f"Country: {country}")

    except Exception as e:
        print(f"Error retrieving WHOIS data: {e}")

def geoip_lookup(ip_address):
    """ Perform GeoIP lookup using ip-api.com. """
    try:
        url = f"http://ip-api.com/json/{ip_address}"
        response = requests.get(url).json()

        print(f"\n[ GeoIP Information ]")
        print(f"Country: {response.get('country', 'N/A')}")
        print(f"Region: {response.get('regionName', 'N/A')}")
        print(f"City: {response.get('city', 'N/A')}")
        print(f"ISP: {response.get('isp', 'N/A')}")
        print(f"Organization: {response.get('org', 'N/A')}")

    except Exception as e:
        print(f"Error retrieving GeoIP data: {e}")

def shodan_lookup(ip_address):
    """ Perform Shodan lookup for open ports and services. """
    try:
        url = f"https://api.shodan.io/shodan/host/{ip_address}?key={SHODAN_API_KEY}"
        response = requests.get(url).json()

        if "error" in response:
            print("\n[ Shodan Information ]")
            print(f"Error: {response['error']}")
            return

        print(f"\n[ Shodan Information ]")
        print(f"Open Ports: {response.get('ports', 'N/A')}")
        print(f"Hostnames: {response.get('hostnames', 'N/A')}")
        print(f"ISP: {response.get('isp', 'N/A')}")
        print(f"City: {response.get('city', 'N/A')}")
        print(f"Country: {response.get('country_name', 'N/A')}")

    except Exception as e:
        print(f"Error retrieving Shodan data: {e}")

def abuseipdb_lookup(ip_address):
    """ Check if the IP is reported for malicious activities in AbuseIPDB. """
    try:
        headers = {
            "Accept": "application/json",
            "Key": ABUSEIPDB_API_KEY
        }
        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": 90,
            "verbose": True
        }
        url = "https://api.abuseipdb.com/api/v2/check"
        response = requests.get(url, headers=headers, params=params)

        if response.status_code != 200:
            print(f"\n[ AbuseIPDB Information ]")
            print(f"Error: {response.status_code} - {response.text}")
            return

        data = response.json()

        if "data" not in data:
            print("\n[ AbuseIPDB Information ]")
            print("No data found for this IP.")
            return

        abuse_data = data["data"]
        print("\n[ AbuseIPDB Information ]")
        print(f"Abuse Confidence Score: {abuse_data.get('abuseConfidenceScore', 'N/A')}")
        print(f"ISP: {abuse_data.get('isp', 'N/A')}")
        print(f"Domain: {abuse_data.get('domain', 'N/A')}")
        print(f"Total Reports: {abuse_data.get('totalReports', 'N/A')}")
        print(f"Last Reported: {abuse_data.get('lastReportedAt', 'N/A')}")

    except Exception as e:
        print(f"Error retrieving AbuseIPDB data: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python osint.py <IP_ADDRESS>")
        sys.exit(1)

    ip_address = sys.argv[1]

    whois_lookup(ip_address)
    geoip_lookup(ip_address)
    shodan_lookup(ip_address)
    abuseipdb_lookup(ip_address)
