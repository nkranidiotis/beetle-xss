import subprocess
import requests
import json
import dns.resolver
from urllib.parse import urlparse
import time
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def is_resolvable(subdomain):
    try:
        dns.resolver.resolve(subdomain, 'A')
        return True
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
        return False

def enumerate_subdomains(domain, brute_file='subdomains.txt'):
    subdomains = set()
    resolvable_subdomains = set()

    try:
        # Use a custom brute file
        with open(brute_file, 'r') as file:
            for line in file:
                subdomain = line.strip()
                full_subdomain = f"{subdomain}.{domain}"
                subdomains.add(full_subdomain)

        # Use a public database like `crt.sh` to find subdomains
        response = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json")
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                subdomains.add(entry['name_value'])

        # Filter resolvable subdomains
        for subdomain in subdomains:
            if is_resolvable(subdomain):
                resolvable_subdomains.add(subdomain)

    except Exception as e:
        logging.error(f"Failed to enumerate subdomains: {e}")

    return list(resolvable_subdomains)