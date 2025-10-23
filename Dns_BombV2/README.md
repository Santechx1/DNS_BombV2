# DNS Inspector

A small Python 3 CLI tool that inspects a website's DNS information:

- Extracts the domain from a URL
- Resolves A and AAAA records for the domain
- Queries NS records for the domain
- Resolves NS hostnames to their A/AAAA addresses
- Checks basic TCP/53 reachability of those DNS servers
- Retrieves domain registration information (WHOIS) including:
  - Registrar details
  - Organization info
  - Contact details (when public)
  - Registration dates
  - Domain status

Requirements

- Python 3.7+
- Install dependencies:

```bash
pip3 install -r requirements.txt
```

Usage

```bash
python3 dns_inspector.py https://example.com
```

Or run without an argument and enter the URL when prompted:

```bash
python3 dns_inspector.py
Enter website URL or hostname: example.com
```

Notes

- The script prefers dnspython for DNS queries; if it's not installed the script will fail when attempting to query NS records and will advise installing dnspython.
- Reachability checks use TCP port 53; some resolvers accept only UDP — TCP check may fail even if DNS is served over UDP. This is a lightweight check for basic responsiveness.

License: MIT
