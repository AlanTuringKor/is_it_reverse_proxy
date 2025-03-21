🕵️‍♀️ is_it_reverse_proxy

is_it_reverse_proxy is a Python tool to help you analyze domains and figure out if you’re dealing with the real origin server — or just talking to a reverse proxy, CDN, load balancer, or shared hosting environment.

Perfect for deciding if it’s worth running a port scan (like Nmap) or if you’re wasting time probing a fronting service.
📌 Features

    ✅ Detects reverse proxies (Cloudflare, Akamai, etc.)
    ✅ Checks for load balancer signatures
    ✅ Identifies shared hosting (via reverse IP)
    ✅ Flags anycast network usage
    ✅ Detects CNAME flattening

📂 File Structure

/is_it_reverse_proxy.py

This script does all the work — no modules, no BS.
⚙️ Requirements

Install dependencies with pip:

pip install dnspython python-whois requests

🚀 Usage

python is_it_reverse_proxy.py domains.txt output.txt

    domains.txt: List of domains (one per line)
    output.txt: File to write the categorized results

📊 Output

For each domain, the script checks:
Check	Values
Reverse Proxy	Yes / No
Load Balancer	Yes / Possible / No
Shared Hosting	Yes / Possible / No
Anycast Network	Yes / Possible / No
CNAME Flattening	Yes / Possible / No

Results are written to your output file and printed in real-time to the console.
📘 Example

Input (domains.txt):

cloudflare.com
example.com
google.com

Command:

python is_it_reverse_proxy.py domains.txt results.txt

Output (results.txt):

=== Reverse Proxy ===
Domain: cloudflare.com
IP: 104.16.132.229
Reverse Proxy: Yes
...

=== None of the Above ===
Domain: example.com
IP: 93.184.216.34
Reverse Proxy: No
...

⚠️ Notes

    Uses the ViewDNS API with a demo key — rate limited. Swap in your own for better results.
    WHOIS data can be fuzzy depending on the provider.
    Heuristics aren’t bulletproof but good enough to guide your recon.

🧠 Why?

If you're like:

    "Do I Nmap this or am I just hitting Cloudflare again?"

This script helps answer that — fast.
