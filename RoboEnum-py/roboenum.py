import httpx
import argparse
from concurrent.futures import ThreadPoolExecutor
import re
import ssl
import socket
from urllib.parse import urlparse
import hashlib
from colorama import Fore, Style, init
import base64
import logging
import sys
import os
import time
import xml.etree.ElementTree as ET

ansi_escape = re.compile(r'\x1B\[0-?]*[ -/]*[@-~]')

class NoColorFormmatter(logging.Formatter):
    def format(self, record):
        message = super().format(record)
        return ansi_escape.sub('', message)

if not logging.getLogger("RoboEnum").hasHandlers():
    logger = logging.getLogger("RoboEnum")
    logger.setLevel(logging.DEBUG)

    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    # Console
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    # File
    file_handler = logging.FileHandler("roboenum.log")
    file_handler.setLevel(logging.DEBUG)
    file_formatter = NoColorFormmatter('%(asctime)s - %(levelame)s - %(message)s')
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)
else:
    logger = logging.getLogger("RoboEnum")

# JSON Schema
results = {
    "target": "",
    "found_files": [],
    "discovered_endpoints": [],
    "tls_info": {},
    "favicon_hashes": {},
    "errors": [],
    "fingerprints": [],
    "http_methods": []
}

init(autoreset=True)

#Default wordlist for optional --brute
COMMON_PATHS = [
    "robots.txt",
    "security.txt",
    "sitemap.xml",
    ".git/",
    ".env",
    "admin/",
    "config/",
    "hidden/"
]

# Regex dictionary
FINGERPRINT_REGEXES = {
    "WordPress": r'wp-content|wordpress|wp-includes',
    "Drupal": r'Drupal.settings|drupal.js',
    "Joomla": r'Joomla|\/components\/com_|\/modules\/mod_',
    "PHP": r'\.php',
    "ASP.NET": r'ASP\.NET|\.aspx',
    "nginx": r'nginx',
    "Apache": r'Apache',
    "Node.js": r'Node\.js|Express',
    "BackDrop CMS": r'backdrop cms',
    "CMS": r'cms'
}

# Error Detection Signatures Dictionary = {}
ERROR_SIGS = {
    "Apache": r"Apache\/[\d\.]+|Apache Server at",
    "Nginx": r"nginx\/[\d\.]+|Welcome to nginx!",
    "IIS": r"IIS\/[\d\.]+|Microsoft Internet Information Services",
    "Tomcat": r"Apache Tomcat\/[\d\.]+",
    "Cloudflare": r"cloudflare",
    "Generic 404": r"404 Not Found|Page Not Found",
    "Generic 403": r"403 Forbidden|Access Denied",
    "Generic 500": r"500 Internal Server Error"
}

def get_cn(field_list):
    for sublist in field_list:
        for key, value in sublist:
            if key == 'commonName':
                return value
    return None

def httpx_client_g():
    context = ssl.create_default_context()
    context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
    
    return httpx.Client(http2=False, verify=context, follow_redirects=True, headers={
        "User-Agent": "RoboEnum/1.0 (+https://github.com/QTShade/RoboEnum)"
    })

def validate_input(url, wordlist):
    parsed_url = urlparse(url)
    if not parsed_url.scheme or not parsed_url.netloc:
        print(f"{Fore.RED}[!] Invalid URL: {url}{Style.RESET_ALL}")
        sys.exit(1)
        
    if not os.path.isfile(wordlist):
        print(f"{Fore.RED}[!] Wordlist file not found: {wordlist}{Style.RESET_ALL}")
        sys.exit(1)

def print_status(status_code, message):
    if 200 <= status_code < 300:
        color = Fore.GREEN
    elif 300 <= status_code < 400:
        color = Fore.CYAN
    elif 400 <= status_code < 500:
        color = Fore.MAGENTA
    elif 500 <= status_code < 600:
        color = Fore.RED
    else:
        color = Fore.WHITE
    
    print(f"{color}{message}{Style.RESET_ALL}")

#Fetch File Function
def fetch_file(client, url, path):
    #Fetech specific file from url
    full_url = f"{url.rstrip('/')}/{path.lstrip('/')}"
    try:
        response = client.get(full_url)
        if response.status_code in [200, 301, 302]:
            print(f"{Fore.LIGHTCYAN_EX}[+] Found: {full_url} (Status: {response.status_code}){Style.RESET_ALL}")
            return (path, response.text)
        else:
            logger.warning(f"{Fore.LIGHTRED_EX}[-] Not Found: {full_url} (Status: {response.status_code}){Style.RESET_ALL}")
    except httpx.HTTPError as e:
        logger.error(f"{Fore.RED}[!] Error fetching {full_url}: {e}{Style.RESET_ALL}")
    return (path, None)

def brute_force_files(client, url, wordlist):
    #--brute option for bruteforcing paths on server.
    print("[*] Stating brute-force scan...")
    results = {}
    
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(fetch_file, client, url, path): path for path in wordlist}
        for future in futures:
            path, content = future.result()
            if content:
                results[path] = content
        
    print("[*] Brute-force scan complete.")
    return results

def parse_robots_text(content):
    #Parse robots.txt content and extract disallow/allowed paths.
    endpoints = []
    lines = content.splitlines()
    for line in lines:
        line = line.strip()
        if line.lower().startswith(('disallow:', 'allow:', 'sitemap:')):
            parts = line.split(':', 1)
            if len(parts) > 1:
                endpoint = parts[1].strip().split()
                endpoints.extend(endpoint)
    return endpoints

def probe_endpoint(client, base_url, endpoint):
    # Probe discovered endpoints and report status code.
    full_url = f"{base_url.rstrip('/')}/{endpoint.lstrip('/')}"
    try:
        response = client.get(full_url)
        if response.status_code == 200:
            print_status(response.status_code, f"{Fore.LIGHTCYAN_EX}[+]Accessible: {full_url}, (Status: {response.status_code}){Style.RESET_ALL}")
            fingerprints = fingerprint_service(response)
            if fingerprints:
                print("    ↳ Fingerprints:")
                for fp in fingerprints:
                    print(f"        {Fore.YELLOW}- {fp}{Style.RESET_ALL}")
                    time.sleep(2)
        
                
        # HTTP Method Discovery 
        discover_http_methods(client, full_url)
        
        # If it's a directory
        if full_url.endswith('/') or response.url.path.endswith('/'):
            print(f"     {Fore.LIGHTMAGENTA_EX}↳ Directory endpoint - checking for index files....{Style.RESET_ALL}")
            index_candidates = ['index.html', 'index.php', 'default.html', 'home.html']
            for file in index_candidates:
                file_url = f"{full_url.rstrip('/')}/{file}"
                try:
                    index_response = client.get(file_url)
                    if index_response.status_code == 200:
                        print_status(index_response.status_code, f"{Fore.CYAN}        [+] Found: {file_url} (Status: {index_response.status_code}){Style.RESET_ALL}")
                        file_fingerprints = fingerprint_service(index_response)
                        if file_fingerprints:
                            print(f"         {Fore.WHITE}↳ Fingerprints:{Style.RESET_ALL}")
                            for ffp in file_fingerprints:
                                print(f"               {Fore.GREEN} - {ffp}{Style.RESET_ALL}")
                                time.sleep(0.3)
                except httpx.HTTPError as e:
                    logger.error(f"        {Fore.RED}[!] Error checking {file_url}: {e}{Style.RESET_ALL}")
                        
        elif response.status_code in [301, 302]:
            print_status(response.status_code, f"[+] Endpoint found - Redirect: {full_url} (Status: {response.status_code})")
        elif response.status_code in [403, 401, 500]:
            error_matches = detect_error_page(response)
            if error_matches:
                print(f"{Fore.MAGENTA}[!] Default error page detected: {', '.join(error_matches)}{Style.RESET_ALL}")
        else:
            logger.error(f"{Fore.RED}[-] Not Found: {full_url} (Status: {response.status_code}){Style.RESET_ALL}")
                
    except httpx.RequestError as e:
        logger.error(f"{Fore.RED}[!] Error probing {full_url}: {e}{Style.RESET_ALL}")
        
def fingerprint_service(response):
    fingerprints = []
    headers = response.headers
    
    header_checks = [
        'Server',
        'X-Powered-By',
        'X-AspNet-Version',
        'X-AspNetMvc-Version',
        'X-Drupal-Cache',
        'X-Generator',
        'X-Backend-Server',
        'X-CDN',
        'Via',
        'Strict-Transport-Security',
        'Content-Security-Policy',
        'Set-Cookie',
        'Link',
        'X-Pingback',
        'X-Runtime',
        'X-Version'
    ]
    
    # Headers
    for header in header_checks:
        value = headers.get(header)
        if value:
            fingerprints.append(f"{header}: {value}")
            
    # Cookies
    cookies = headers.get_list('Set-Cookie')
    for cookie in cookies:
        if 'PHPSESSID' in cookie:
            fingerprints.append("Cookie: PHP Sessions ID detected")
        if 'wordpress_logged_in' in cookie:
            fingerprints.append("Cookie: Wordpress login session detected")
        if 'JSESSIONID' in cookie:
            fingerprints.append("Cookie: Java session detected")
    
    
    # Body Content
    body = response.text.lower()
    
    # Regex Driven Fingerprinting
    for name, pattern in FINGERPRINT_REGEXES.items():
        if re.search(pattern, body, re.IGNORECASE):
            fingerprints.append(f"Detected: {name}")
        
    # Title Tags
    title = re.search(r'<title>(.*?)<\/title>', response.text.lower(), re.IGNORECASE)
    if title:
        fingerprints.append(f"Page Title: {title.group(1).strip()}")
    
    results["fingerprints"].append(fingerprints)
    return fingerprints
    

def tls_fetch(target_url):
    parsed_url = urlparse(target_url)
    hostname = parsed_url.hostname
    port = 443
    
    
    try:
        context = ssl.create.default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                der_cert = ssl.DER_cert_to_PEM_cert(cert)
                
                # SHA-256 Fingerprint
                sha256fp = hashlib.sha256(cert).hexdigest()
                
                # Parsed cert details
                x509 = ssl._ssl._test_decode_cert(ssock.getpeercert(True))
                
                subject = get_cn(x509['subject'])
                issuer = get_cn(x509['issuer'])
                not_before = x509['notBefore']
                not_after = x509['notAfter']
                
                print(f"\n[*] TLS Certificate for {hostname}:")
                print(f"     ↳ Subject CN: {subject.get('commonName')}")
                print(f"     ↳ Issuer CN: {issuer.get('commonName')}")
                print(f"     ↳ Valid From: {not_before}")
                print(f"     ↳ Valid To: {not_after}")
                print(f"     ↳ SHA-256 Fingeprint: {sha256fp}\n")
                results.setdefault("tls_info", {}).setdefault("Subject CN", []).append(subject.get("commonName"))
                results.setdefault("tls_info", {}).setdefault("Issuer CN", []).append(issuer.get("commonName"))
                results.setdefault("tls_info", {}).setdefault("Valid From", []).append(not_before)
                results.setdefault("tls_info", {}).setdefault("Valid To", []).append(not_after)
                results.setdefault("tls_info", {}).setdefault("SHA-256 Fingerprint", []).append(sha256fp)
                
    except (socket.timeout, ConnectionRefusedError, ssl.SSLError, OSError) as e:
        logger.warning(f"[!] Error fetching certificate from {hostname}: {e}")
        results["errors"].append(str(e))
        
def favicon_fetch(client, target_url):
    favicon_url = f"{target_url.rstrip('/')}/favicon.ico"
    try:
        response = client.get(favicon_url)
        time.sleep(0.3)
        if response.status_code == 200 and response.content:
            content = response.content
            
            md5_hash = hashlib.md5(content).hexdigest()
            sha256_hash = hashlib.sha256(content).hexdigest()
            
            print(f"\n[*] Favicon found at: {favicon_url}")
            print(f"     {Fore.LIGHTMAGENTA_EX}↳ MD5:     {md5_hash}{Style.RESET_ALL}")
            print(f"     {Fore.LIGHTMAGENTA_EX}↳ SHA256:      {sha256_hash}{Style.RESET_ALL}")
            results.setdefault("favicon_hashes", {}).setdefault("MD5", []).append(md5_hash)
            results.setdefault("favicon_hashes", {}).setdefault("SHA256", []).append(sha256_hash)
            return content
        else:
            print(f"{Fore.YELLOW}[-] No favicon found at {favicon_url} (Status: {response.status_code}){Style.RESET_ALL}")
            
    except httpx.HTTPError as e:
        logger.warning(f"{Fore.RED}Error fetching favicon.ico {e} - File does not exist or is not reachable from {favicon_url}{Style.RESET_ALL}")
        results["errors"].append(str(e))
    return None
        
def detect_error_page(response):
    matches = []
    body = response.text
    for name, pattern in ERROR_SIGS.items():
        if re.search(pattern, body, re.IGNORECASE):
            matches.append(name)
    return matches

def parse_sitemap(content):
    endpoints = []
    loc_tags = re.findall(r'<loc>(.*?)<\/loc>', content, re.IGNORECASE)
    for url in loc_tags:
        path = re.sub(r'^https?:\/\/[^\/]+', '', url)
        endpoints.append(path)
    return endpoints

def discover_http_methods(client, url):
    try:
        response = client.options(url)
        allow = response.headers.get("Allow")
        if allow:
            print(f"       {Fore.YELLOW} ↳ Supported Methods: {allow}{Style.RESET_ALL}")
            methods = [method.strip() for method in allow.split(',')]
            print(f"   ↳{Fore.CYAN}Supported HTTP Methods: {Style.RESET_ALL}", end="")
            time.sleep(0.3)
            
            for method in methods:
                if method in ["GET", "POST", "HEAD"]:
                    color = Fore.GREEN
                elif method in ["PUT", "DELETE", "PATCH"]:
                    color = Fore.YELLOW
                elif method in ["TRACE", "CONNECT"]:
                    color = Fore.RED
                else:
                    color = Fore.LIGHTWHITE_EX
                    
                print(f"{color}{method}{Style.RESET_ALL} ", end="")
                results["http_methods"].append(method)
                
            print()
        else:
            print(f"       {Fore.LIGHTBLACK_EX}↳ No 'Allow' header present. {Style.RESET_ALL}")
    except httpx.HTTPError as e:
        logger.warning(f"        {Fore.RED}[!] Error performing OPTIONS on {url}: {e}{Style.RESET_ALL}")
        results["errors"].append(str(e))
        
def shodan_favi_match(content):
    favicon_bytes = content
    time.sleep(0.3)
    try:
        if favicon_bytes:
            #B64 raw content
            b64_content = base64.b64encode(favicon_bytes)
            #Calc hash of b64
            hash_value = hashlib.md5(b64_content).hexdigest()
            logger.info(f"{Fore.CYAN}[+] Favicon MD5 Hash: {hash_value}{Style.RESET_ALL}")
            return hash_value
        else:
            print(f"{Fore.LIGHTYELLOW_EX}[-] Favicon content not present. Cannot hash.{Style.RESET_ALL}")
    except Exception as e:
        logger.warning(f"{Fore.RED}[!] Error hashing favicon: {e}{Style.RESET_ALL}")
        results["errors"].append(str(e))
    return None
    
        
        
        
        

def main():
    parser = argparse.ArgumentParser(description="robots.txt Enumerator", add_help=True, usage="python roboenum.py --url [[[--brute] [--wordlist]] [--verbose | -v]]")
    parser.add_argument("--url", required=True, help="Target URL (e,g., https://example.com)")
    parser.add_argument("--brute", action="store_true", help="Enables brute-force mode for common files")
    parser.add_argument("--wordlist", help="Path to custom wordlist file for brute-force scan")
    parser.add_argument("--verbose", "-v", action="store_true", help="Add additional detail output")
    parser.add_argument("--json", help="Path to save output JSON report", default=None)
    args = parser.parse_args()

    endpoints = []
    
    if args.verbose:
        console_handler.setLevel(logging.DEBUG)
        logger.debug("Verbose mode enabled. Set logging level to DEBUG.")
    
    with httpx.Client(timeout=5, follow_redirects=True, headers={
        "User-Agent": "RoboEnum/1.0 (+https://github.com/QTShade/RoboEnum)"
    }) as client:
        
        if args.brute:
            custom_paths = []
            if args.wordlist:
                try:
                    with open(args.wordlist, 'r') as f:
                        custom_paths = [line.strip() for line in f if line.strip()]
                    logger.info(f"{Fore.WHITE}[*] Loaded {len(custom_paths)} paths from {args.wordlist}{Style.RESET_ALL}")
                except Exception as e:
                    logger.warning(f"{Fore.RED}[!] Failed to load wordlist: {e}{Style.RESET_ALL}")
                
            # Combine default COMMON_PATH with any custom ones
            wordlist_to_use = COMMON_PATHS + custom_paths
            logger.info(f"{Fore.WHITE}[-] Running brute-force scan with {len(wordlist_to_use)} total paths...{Style.RESET_ALL}")
            brute_force_files(client, args.url, wordlist_to_use)
    
        logger.info(f"{Fore.WHITE}[*] Fetching robots.txt from {args.url}...{Style.RESET_ALL}")
        _, robots_content = fetch_file(client, args.url, "robots.txt")
        
        if robots_content:
            time.sleep(0.4)
            logger.info(f"{Fore.WHITE}[*] Parsing robots.txt...{Style.RESET_ALL}")
            #Create variable to store endpoints found from robots.txt(e,g. '/uri' '/config')
            endpoints = parse_robots_text(robots_content)
            logger.info(f"{Fore.GREEN}[*] Discovered entries in robots.txt:{Style.RESET_ALL}")
            for ep in endpoints:
                logger.info(f"{Fore.YELLOW}    {ep}{Style.RESET_ALL}")
                #Reach out to the endpoints discovered
            logger.info(f"{Fore.CYAN}[*] Probing discovered endpoint...{Style.RESET_ALL}")
            for ep in endpoints:
                time.sleep(0.4)
                path, robots_content = fetch_file(client, args.url, ep)
                if robots_content:
                    logger.info(f"{Fore.LIGHTGREEN_EX}    [+] {ep} exists!{Style.RESET_ALL}")
                else:
                    logger.warning(f"{Fore.RED}    [-] {ep} missing or inaccessible.{Style.RESET_ALL}")
            
        else:
            logger.error(f"{Fore.RED}[-] robots.txt not found.{Style.RESET_ALL}")
            
        # Fetch favicon and conduct shodan-compatiable hashing
        favicon_bytes = favicon_fetch(client, args.url)
        if favicon_bytes:
            logger.info(f"{Fore.CYAN}Converting hash into shodan-compatible hash...{Style.RESET_ALL}")
            time.sleep(0.4)
            shodan_hash = shodan_favi_match(favicon_bytes)
            if shodan_hash:
                logger.info(f"{Fore.GREEN}Shodan-Compatible Favicon Hash: {shodan_hash}{Style.RESET_ALL}")
            
         # Fetch sitemap.xml   
        logger.info(f"{Fore.CYAN}[*] Fetching sitemap.xml from {args.url}...{Style.RESET_ALL}")
        time.sleep(0.4)
        _, sitemap_content = fetch_file(client, args.url, "sitemap.xml")
        if sitemap_content:
            logger.info(f"{Fore.CYAN}[*] Parsing sitemap.xml...\n{Style.RESET_ALL}")
            sitemap_endpoints = parse_sitemap(sitemap_content)
            logger.info(f"{Fore.CYAN}[*] Discovered entries in sitemap.xml:\n{Style.RESET_ALL}")
            for ep in sitemap_endpoints:
                time.sleep(0.5)
                logger.info(f"{Fore.LIGHTGREEN_EX}     {ep}{Style.RESET_ALL}")
            endpoints.extend(sitemap_endpoints)
            results["discovered_endpoints"].append(endpoints)
        else:
            logger.warning("[-] sitemap.xml not found.")
        
        # Check for TLS certs - Recon Baby Yeah
        if args.url.startswith("https://"):
            tls_fetch(args.url)
            time.sleep(0.4)
            
        
        #Endpoint Probing starts here.
        if endpoints:
            logger.info(f"{Fore.WHITE}[*] Probing discovered endpoints...{Style.RESET_ALL}\n")
            for ep in endpoints:
                probe_endpoint(client, args.url, ep)
                time.sleep(0.4)
        else:
                logger.warning(f"{Fore.MAGENTA}[-] No endpoints to probe.{Style.RESET_ALL}")
    
    # Save results to JSON Schema
    results["target"].append(args.url)
    
    
        

if __name__ == "__main__":
    main()