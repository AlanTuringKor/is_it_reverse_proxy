import socket
import dns.resolver  # For DNS lookups
import whois  # For WHOIS lookups
import requests  # For reverse IP lookups
from collections import defaultdict

# List of known reverse proxy/CDN IP ranges or hostnames
KNOWN_PROXY_RANGES = [
    "cloudflare.com",
    "akamai.net",
    "fastly.net",
    "cloudfront.net",
    "incapdns.net",
    "sucuri.net",
    "azureedge.net",
    "googleusercontent.com",
    "awsglobalaccelerator.com",
]

# List of known load balancer keywords
LOAD_BALANCER_KEYWORDS = ["lb", "loadbalancer", "elb", "alb", "glb"]

# List of known shared hosting providers
SHARED_HOSTING_PROVIDERS = [
    "bluehost.com",
    "godaddy.com",
    "hostgator.com",
    "dreamhost.com",
    "siteground.com",
]

# List of known anycast networks
ANYCAST_NETWORKS = [
    "cloudflare.com",
    "akamai.net",
    "fastly.net",
]

def is_reverse_proxy(ip):
    """Check if the IP belongs to a known reverse proxy/CDN."""
    try:
        # Perform a reverse DNS lookup
        hostname, _, _ = socket.gethostbyaddr(ip)
        # Check if the hostname contains any known reverse proxy/CDN domains
        for proxy in KNOWN_PROXY_RANGES:
            if proxy in hostname:
                return "Yes"
        return "No"
    except socket.herror:
        return "No"

def is_load_balancer(ip):
    """Check if the IP belongs to a load balancer."""
    try:
        # Perform a reverse DNS lookup
        hostname, _, _ = socket.gethostbyaddr(ip)
        # Check if the hostname contains load balancer keywords
        for keyword in LOAD_BALANCER_KEYWORDS:
            if keyword in hostname:
                return "Yes"
        return "Possible"
    except socket.herror:
        return "No"

def is_shared_hosting(ip):
    """Check if the IP belongs to a shared hosting provider."""
    try:
        # Perform a reverse IP lookup using an external service
        url = f"https://api.viewdns.info/reverseip/?host={ip}&apikey=demo&output=json"
        response = requests.get(url)
        data = response.json()
        if data["response"]["domains"]:
            # If multiple domains are hosted on the same IP, it's likely shared hosting
            return "Yes"
        return "No"
    except Exception:
        return "Possible"

def is_anycast_network(ip):
    """Check if the IP belongs to an anycast network."""
    try:
        # Perform a WHOIS lookup
        whois_info = whois.whois(ip)
        # Check if the organization is a known anycast network
        for network in ANYCAST_NETWORKS:
            if network in str(whois_info):
                return "Yes"
        return "Possible"
    except Exception:
        return "No"

def has_cname_flattening(domain):
    """Check if the domain uses CNAME flattening or DNS aliasing."""
    try:
        # Perform a DNS lookup for CNAME records
        answers = dns.resolver.resolve(domain, "CNAME")
        if answers:
            return "Yes"
        return "No"
    except dns.resolver.NoAnswer:
        return "No"
    except Exception:
        return "Possible"

def resolve_domains(domains, output_file):
    """Resolve domains and categorize them based on the five scenarios."""
    results = []
    none_of_the_above = []  # Domains that don't match any scenario

    for domain in domains:
        domain = domain.strip()  # Remove any leading/trailing whitespace
        if not domain:
            continue  # Skip empty lines

        print(f"Processing: {domain}")  # Show real-time progress

        try:
            # Resolve the domain to an IP address
            ip = socket.gethostbyname(domain)
            print(f"Resolved IP: {ip}")

            # Check for each scenario
            reverse_proxy = is_reverse_proxy(ip)
            load_balancer = is_load_balancer(ip)
            shared_hosting = is_shared_hosting(ip)
            anycast_network = is_anycast_network(ip)
            cname_flattening = has_cname_flattening(domain)

            # Store the results
            result = {
                "Domain": domain,
                "IP": ip,
                "Reverse Proxy": reverse_proxy,
                "Load Balancer": load_balancer,
                "Shared Hosting": shared_hosting,
                "Anycast Network": anycast_network,
                "CNAME Flattening": cname_flattening,
            }
            results.append(result)

            # Print real-time results
            print(f"Reverse Proxy: {reverse_proxy}")
            print(f"Load Balancer: {load_balancer}")
            print(f"Shared Hosting: {shared_hosting}")
            print(f"Anycast Network: {anycast_network}")
            print(f"CNAME Flattening: {cname_flattening}")
            print()

        except socket.gaierror:
            print(f"Domain: {domain} could not be resolved.\n")

    # Categorize domains
    categorized_results = defaultdict(list)
    for result in results:
        # Check if the domain matches any scenario
        if (
            result["Reverse Proxy"] == "Yes"
            or result["Load Balancer"] == "Yes"
            or result["Shared Hosting"] == "Yes"
            or result["Anycast Network"] == "Yes"
            or result["CNAME Flattening"] == "Yes"
        ):
            # Add to the appropriate category
            if result["Reverse Proxy"] == "Yes":
                categorized_results["Reverse Proxy"].append(result)
            if result["Load Balancer"] == "Yes":
                categorized_results["Load Balancer"].append(result)
            if result["Shared Hosting"] == "Yes":
                categorized_results["Shared Hosting"].append(result)
            if result["Anycast Network"] == "Yes":
                categorized_results["Anycast Network"].append(result)
            if result["CNAME Flattening"] == "Yes":
                categorized_results["CNAME Flattening"].append(result)
        else:
            # Add to "None of the Above"
            none_of_the_above.append(result)

    # Write results to the output file
    with open(output_file, "w") as outfile:
        # Write categorized results
        for category, items in categorized_results.items():
            outfile.write(f"=== {category} ===\n")
            for item in items:
                outfile.write(f"Domain: {item['Domain']}\n")
                outfile.write(f"IP: {item['IP']}\n")
                outfile.write(f"Reverse Proxy: {item['Reverse Proxy']}\n")
                outfile.write(f"Load Balancer: {item['Load Balancer']}\n")
                outfile.write(f"Shared Hosting: {item['Shared Hosting']}\n")
                outfile.write(f"Anycast Network: {item['Anycast Network']}\n")
                outfile.write(f"CNAME Flattening: {item['CNAME Flattening']}\n")
                outfile.write("\n")

        # Write "None of the Above" results
        outfile.write("=== None of the Above ===\n")
        for item in none_of_the_above:
            outfile.write(f"Domain: {item['Domain']}\n")
            outfile.write(f"IP: {item['IP']}\n")
            outfile.write(f"Reverse Proxy: {item['Reverse Proxy']}\n")
            outfile.write(f"Load Balancer: {item['Load Balancer']}\n")
            outfile.write(f"Shared Hosting: {item['Shared Hosting']}\n")
            outfile.write(f"Anycast Network: {item['Anycast Network']}\n")
            outfile.write(f"CNAME Flattening: {item['CNAME Flattening']}\n")
            outfile.write("\n")

    # Print summary at the end
    print("\n=== Summary ===")
    for category, items in categorized_results.items():
        print(f"=== {category} ===")
        for item in items:
            print(f"Domain: {item['Domain']}")
            print(f"IP: {item['IP']}")
            print(f"Reverse Proxy: {item['Reverse Proxy']}")
            print(f"Load Balancer: {item['Load Balancer']}")
            print(f"Shared Hosting: {item['Shared Hosting']}")
            print(f"Anycast Network: {item['Anycast Network']}")
            print(f"CNAME Flattening: {item['CNAME Flattening']}")
            print()

    print("=== None of the Above ===")
    for item in none_of_the_above:
        print(f"Domain: {item['Domain']}")
        print(f"IP: {item['IP']}")
        print(f"Reverse Proxy: {item['Reverse Proxy']}")
        print(f"Load Balancer: {item['Load Balancer']}")
        print(f"Shared Hosting: {item['Shared Hosting']}")
        print(f"Anycast Network: {item['Anycast Network']}")
        print(f"CNAME Flattening: {item['CNAME Flattening']}")
        print()

if __name__ == "__main__":
    # Set up argument parsing
    parser = argparse.ArgumentParser(description="Resolve domains and categorize them based on five scenarios.")
    parser.add_argument("input_file", help="Path to the text file containing the list of domains.")
    parser.add_argument("output_file", help="Path to the output file where results will be saved.")
    args = parser.parse_args()

    # Read the list of domains from the input file
    with open(args.input_file, "r") as infile:
        domains = infile.readlines()

    # Resolve domains and save results
    resolve_domains(domains, args.output_file)