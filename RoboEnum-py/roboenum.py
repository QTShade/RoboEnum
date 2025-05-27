import httpx
import argparse
from concurrent.futures import ThreadPoolExecutor

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
        elif response.status_code in [301, 302]:
            print(f"[+] Endpoint found - Redirect: {full_url} (Status: {response.status_code})")
        elif response.status_code in [403, 401]:
            print(f"[!] Restricted: {full_url} (Status: {response.status_code})")
        else:
            print(f"[-] Not Found: {full_url} (Status: {response.status_code})")
    except httpx.RequestError as e:
        print(f"[!] Error probing {full_url}: {e}")
        
def fingerprint_service(response):
    fingerprints = []
    
    # Headers
    server = response.headers.get('Server')
    if server:
        fingerprints.append(f"Server: {server}")
        
    
    powered_by = response.headers.get('X-Powered-By')
    if powered_by:
        fingerprints.append(f"Powered-By: {powered_by}")
        
    user_agent = response.headers.get('User-Agent')
    if user_agent:
        fingerprints.append(f"User-Agent: {user_agent}")
        
    content_type = response.headers.get('Content-Type')
    if content_type:
        fingerprints.append(f"Content-type: {content_type}")
    
    
    # Body Content
    body = response.text.lower()
    if "wordpress" in body:
        fingerprints.append("Possible WordPress site")
    if "drupal" in body:
        fingerprints.append("Possible Drupal site")
    if "cms" in body:
        fingerprints.append("Possible CMS site")
    if "backdrop cms" in body:
        fingerprints.append("Possible Backdrop CMS site")
        
    return fingerprints

def main():
    parser = argparse.ArgumentParser(description="robots.txt Enumerator", add_help=True, usage="python roboenum.py --url [--brute]")
    parser.add_argument("--url", required=True, help="Target URL (e,g., https://example.com)")
    parser.add_argument("--brute", action="store_true", help="Enables brute-force mode for common files")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    
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
    
    #Endpoint Probing starts here.
    if endpoints:
        print("[*] Probing discovered endpoints...")
        for ep in endpoints:
            probe_endpoint(args.url, ep)
        else:
            print("[-] No endpoints to probe.")
    
    
    if args.brute:
        print("[-] Running brute-force scan for common files...")
        brute_force_files(args.url, COMMON_PATHS)
        

if __name__ == "__main__":
    main()