import httpx
import argparse
from concurrent.futures import ThreadPoolExecutor
import re
import ssl
import socket
from urllib.parse import urlparse
import hashlib
from colorama import Fore, Style, init
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

#Fetch File Function
def fetch_file(url, path):
    #Fetech specific file from url
    full_url = f"{url.rstrip('/')}/{path.lstrip('/')}"
    try:
        response = httpx.get(full_url, timeout=5, follow_redirects=True)
        if response.status_code in [200, 301, 302]:
            print(f"[+] Found: {full_url} (Status: {response.status_code})")
            return (path, response.text)
        else:
            print(f"[-] Not Found: {full_url} (Status: {response.status_code})")
    except Exception as e:
        print(f"[!] Error fetching {full_url}: {e}")
    return (path, None)

def brute_force_files(url, wordlist):
    #--brute option for bruteforcing paths on server.
    print("[*] Stating brute-force scan...")
    results = {}
    
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(fetch_file, url, path): path for path in wordlist}
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

def probe_endpoint(base_url, endpoint):
    # Probe discovered endpoints and report status code.
    full_url = f"{base_url.rstrip('/')}/{endpoint.lstrip('/')}"
    try:
        response = httpx.get(full_url, timeout=5, follow_redirects=True)
        if response.status_code == 200:
            print(f"[+] Accessible: {full_url} (Status: 200)")
            fingerprints = fingerprint_service(response)
            if fingerprints:
                print("    ↳ Fingerprints:")
                for fp in fingerprints:
                    print(f"        - {fp}")
                    
            # HTTP Method Discovery 
            discover_http_methods(full_url)
            
            # If it's a directory
            if full_url.endswith('/') or response.url.path.endswith('/'):
                print("     ↳ Directory endpoint - checking for index files....")
                index_candidates = ['index.html', 'index.php', 'default.html', 'home.html']
                for file in index_candidates:
                    file_url = f"{full_url.rstrip('/')}/{file}"
                    try:
                        index_response = httpx.get(file_url, timeout=5, follow_redirects=True)
                        if index_response.status_code == 200:
                            print(f"        [+] Found: {file_url} (Status: 200)")
                            file_fingerprints = fingerprint_service(index_response)
                            if file_fingerprints:
                                print("         ↳ Fingerprints:")
                                for ffp in file_fingerprints:
                                    print(f"                - {ffp}")
                    except Exception as e:
                        print(f"                [!] Error checking {file_url}: {e}")
                        
        
                        
        elif response.status_code in [301, 302]:
            print(f"[+] Endpoint found - Redirect: {full_url} (Status: {response.status_code})")
        elif response.status_code in [403, 401, 404, 500]:
            error_matches = detect_error_page(response)
            if error_matches:
                print(f"[!] Default error page detected: {', '.join(error_matches)}")
        else:
            print(f"[-] Not Found: {full_url} (Status: {response.status_code})")
    except httpx.RequestError as e:
        print(f"[!] Error probing {full_url}: {e}")
        
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
        if 'PHPSESSID' in cookies:
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
        
    return fingerprints

def tls_fetch(target_url):
    parsed_url = urlparse(target_url)
    hostname = parsed_url.hostname
    port = 443
    
    
    try:
        context = ssl.create.default_context()
        with socket.create_connection((hostname, port), time=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                der_cert = ssl.DER_cert_to_PEM_cert(cert)
                
                # SHA-256 Fingerprint
                sha256fp = hashlib.sha256(cert).hexdigest()
                
                # Parsed cert details
                x509 = ssl._ssl._test_decode_cert(ssock.getpeercert(True))
                
                subject = dict(x509['subject'])
                issuer = dict(x509['issuer'])
                not_before = x509['notBefore']
                not_after = x509['notAfter']
                
                print(f"\n[*] TLS Certificate for {hostname}:")
                print(f"     ↳ Subject CN: {subject.get('commonName')}")
                print(f"     ↳ Issuer CN: {issuer.get('commonName')}")
                print(f"     ↳ Valid From: {not_before}")
                print(f"     ↳ Valid To: {not_after}")
                print(f"     ↳ SHA-256 Fingeprint: {sha256fp}\n")
                
    except Exception as e:
        print(f"[!] Error fetching certificate from {hostname}: {e}")
        
def favicon_fetch(target_url):
    favicon_url = f"{target_url.rstrip('/')}/favicon.ico"
    try:
        response = httpx.get(favicon_url, timeout=5, follow_redirects=True)
        if response.status_code == 200 and response.content:
            content = response.content
            
            md5_hash = hashlib.md5(content).hexdigest
            sha256_hash = hashlib.sha256(content).hexdigest
            
            print(f"\n[*] Favicon found at: {favicon_url}")
            print(f"     ↳ MD5:     {md5_hash}")
            print(f"     ↳ SHA256:      {sha256_hash}")
        else:
            print(f"[-] No favicon found at {favicon_url} (Status: {response.status_code})")
            
    except Exception as e:
        print(f"Error fetching favicon.ico - File does not exist or is not reachable from {favicon_url}")
        
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

def discover_http_methods(url):
    try:
        response = httpx.options(url, timeout=5, follow_redirects=True)
        allow = response.headers.get("Allow")
        if allow:
            print(f"        ↳ Supported Methods: {allow}")
        else:
            print(f"       ↳ No 'Allow' header present. ")
    except Exception as e:
        print(f"    [!] Error performing OPTIONS on {url}: {e}")
        
        
        
        

def main():
    parser = argparse.ArgumentParser(description="robots.txt Enumerator", add_help=True, usage="python roboenum.py --url [--brute]")
    parser.add_argument("--url", required=True, help="Target URL (e,g., https://example.com)")
    parser.add_argument("--brute", action="store_true", help="Enables brute-force mode for common files")
    parser.add_argument("--wordlist", help="Path to custom wordlist file for brute-force scan")
    args = parser.parse_args()
    
    endpoints = []
    
    print(f"[*] Fetching robots.txt from {args.url}...")
    _, robots_content = fetch_file(args.url, "robots.txt")
    
    if robots_content:
        print("[*] Parsing robots.txt...\n")
        #Create variable to store endpoints found from robots.txt(e,g. '/uri' '/config')
        endpoints = parse_robots_text(robots_content)
        print("[*] Discovered entries in robots.txt:\n")
        for ep in endpoints:
            print(f"    {ep}")
            #Reach out to the endpoints discovered
        print("\n[*] Probing discovered endpoint...\n")
        for ep in endpoints:
            path, robots_content = fetch_file(args.url, ep)
            if robots_content:
                print(f"    [+] {ep} exists!\n")
            else:
                print(f"    [-] {ep} missing or inaccessible.\n")
        
    else:
        print("[-] robots.txt not found.")
        
    print(f"[*] Fetching sitemap.xml from {args.url}...")
    _, sitemap_content = fetch_file(args.url, "sitemap.xml")
    if sitemap_content:
        print("[*] Parsing sitemap.xml...\n")
        sitemap_endpoints = parse_sitemap(sitemap_content)
        print("[*] Discovered entries in sitemap.xml:\n")
        for ep in sitemap_endpoints:
            print(f"     {ep}")
        endpoints.extend(sitemap_endpoints)
    else:
        print("[-] sitemap.xml not found.")
    
    # Check for TLS certs - Recon Baby Yeah
    if args.url.startswith("https://"):
        tls_fetch(args.url)
        
    # Now check for some favicon files yo
    favicon_fetch(args.url)
    
    #Endpoint Probing starts here.
    if endpoints:
        print("[*] Probing discovered endpoints...")
        for ep in endpoints:
            probe_endpoint(args.url, ep)
    else:
            print("[-] No endpoints to probe.")
    
    
    if args.brute:
        custom_paths = []
        if args.wordlist:
            try:
                with open(args.wordlist, 'r') as f:
                    custom_paths = [line.strip() for line in f if line.strip()]
                print(f"[*] Loaded {len(custom_paths)} paths from {args.wordlist}")
            except Exception as e:
                print(f"[!] Failed to load wordlist: {e}")
                
        # Combine default COMMON_PATH with any custom ones
        wordlist_to_use = COMMON_PATHS + custom_paths
        print("[-] Running brute-force scan with {len(wordlist_to_use)} total paths...")
        brute_force_files(args.url, COMMON_PATHS)
        

if __name__ == "__main__":
    main()