import subprocess
import json
import os
import requests
import re
import socket
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
import ipaddress

# Configuration
CAMERA_PORTS = "80,81,82,90,443,554,8000,8080,37777"  # Camera-specific ports
IP_FILE = input("Enter the input file ")  # Input file for IPs/ranges
RATE = "1000000"  # 1M packets/second; increase to 10M+ on fast hardware
CAMERA_OUTPUT_FILE = "camera_ips.txt"  # Camera IPs with signatures
ALL_OPEN_OUTPUT_FILE = "all_open_ips.txt"  # All open ports
MASSCAN_OUTPUT = "masscan_output.json"
EXCLUDE_FILE = "exclude.txt"

# Camera-specific signatures
CAMERA_BANNERS = [
    r"Hikvision", r"Dahua", r"Axis", r"IP Camera", r"Webcam", r"Login",
    r"Video Surveillance", r"Camera", r"RTSP", r"ONVIF", r"Vivotek", r"ACTi"
]
CAMERA_PATHS = ["/", "/login", "/mjpg/video.mjpg", "/ISAPI/Security/userCheck", "/snap.jpg", "/video"]

def parse_ip_file(filename):
    """Parse IPs, CIDR ranges, or hyphenated ranges from file."""
    ip_ranges = []
    try:
        with open(filename, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    # Try CIDR (e.g., 192.168.1.0/24)
                    ip_network = ipaddress.ip_network(line, strict=False)
                    ip_ranges.append(line)
                    print(f"Parsed CIDR: {line}")
                except ValueError:
                    # Try hyphenated range (e.g., 192.168.1.1-192.168.1.255)
                    if "-" in line:
                        start_ip, end_ip = line.split("-")
                        try:
                            ipaddress.ip_address(start_ip.strip())
                            ipaddress.ip_address(end_ip.strip())
                            ip_ranges.append(line)
                            print(f"Parsed range: {line}")
                        except ValueError:
                            print(f"Invalid IP range: {line}")
                    else:
                        # Try single IP
                        try:
                            ipaddress.ip_address(line)
                            ip_ranges.append(line)
                            print(f"Parsed single IP: {line}")
                        except ValueError:
                            print(f"Invalid IP: {line}")
        if not ip_ranges:
            print(f"Error: No valid IPs/ranges in {filename}")
        return ip_ranges
    except FileNotFoundError:
        print(f"Error: {filename} not found")
        return []
    except Exception as e:
        print(f"Error parsing {filename}: {str(e)}")
        return []

def run_masscan(ip_ranges):
    """Run Masscan using IP file input."""
    cmd = [
        "sudo", "masscan", "-iL", IP_FILE,
        f"-p{CAMERA_PORTS}",
        f"--rate={RATE}",
        "--excludefile", EXCLUDE_FILE,
        "-oJ", MASSCAN_OUTPUT,
        "--banners"  # Grab banners for camera detection
    ]
    print(f"Running Masscan: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        print("Masscan completed successfully")
        if result.stdout:
            print(result.stdout[:500] + "..." if len(result.stdout) > 500 else result.stdout)
        if result.stderr:
            print(f"Masscan warnings: {result.stderr}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Masscan failed: {e.stderr}")
        return False

def check_rtsp_tcp(ip, port):
    """Simple TCP probe for RTSP ports."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0  # True if port is open (likely RTSP)
    except Exception:
        return False

def check_camera(ip, port, banner=None):
    """Check if IP:port is likely a camera based on HTTP/RTSP signatures."""
    try:
        # Check Masscan banner first (if available)
        if banner and any(b.lower() in banner.lower() for b in CAMERA_BANNERS):
            return f"{ip}:{port} (Banner: {banner})"

        # HTTP/HTTPS checks
        if port in [80, 81, 82, 90, 443, 8000, 8080]:
            proto = "https" if port == 443 else "http"
            for path in CAMERA_PATHS:
                url = f"{proto}://{ip}:{port}{path}"
                try:
                    response = requests.get(url, timeout=3, allow_redirects=True, verify=False)
                    if response.status_code in [200, 401, 403]:
                        content = response.text.lower()
                        for b in CAMERA_BANNERS:
                            if b.lower() in content:
                                return f"{ip}:{port} (HTTP: {b})"
                except requests.RequestException:
                    continue

        # RTSP checks (TCP probe)
        if port in [554, 37777]:
            if check_rtsp_tcp(ip, port):
                return f"{ip}:{port} (RTSP)"
    except Exception as e:
        print(f"Error checking {ip}:{port}: {str(e)}")
    return None

def parse_and_filter_cameras():
    """Parse Masscan JSON output and separate camera IPs from other open ports."""
    camera_ips = []
    all_open_ips = []
    try:
        with open(MASSCAN_OUTPUT) as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"Error: {MASSCAN_OUTPUT} not found")
        return camera_ips, all_open_ips
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in {MASSCAN_OUTPUT}")
        return camera_ips, all_open_ips

    tasks = []
    for host in data.get("hosts", []):
        ip = host["ip"]
        for port_info in host["ports"]:
            if port_info["status"] == "open":
                port = port_info["port"]
                banner = port_info.get("banner", "")
                tasks.append((ip, port, banner))
                all_open_ips.append(f"{ip}:{port}")

    with ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(lambda x: check_camera(*x), tasks)
        for (ip, port, _), result in zip(tasks, results):
            if result:
                camera_ips.append(result)
                print(f"Found camera: {result}")

    return camera_ips, all_open_ips

def save_results(camera_ips, all_open_ips):
    """Save camera IPs and all open ports to separate files."""
    try:
        with open(CAMERA_OUTPUT_FILE, "w") as f:
            for ip in camera_ips:
                f.write(f"{ip}\n")
        print(f"Saved {len(camera_ips)} camera IPs to {CAMERA_OUTPUT_FILE}")
    except Exception as e:
        print(f"Error saving to {CAMERA_OUTPUT_FILE}: {str(e)}")

    try:
        with open(ALL_OPEN_OUTPUT_FILE, "w") as f:
            for ip in all_open_ips:
                f.write(f"{ip}\n")
        print(f"Saved {len(all_open_ips)} open ports to {ALL_OPEN_OUTPUT_FILE}")
    except Exception as e:
        print(f"Error saving to {ALL_OPEN_OUTPUT_FILE}: {str(e)}")

def main():
    # Create exclude file for private/reserved IPs
    exclude_content = """
0.0.0.0/8
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
127.0.0.0/8
"""
    try:
        with open(EXCLUDE_FILE, "w") as f:
            f.write(exclude_content)
        print(f"Created {EXCLUDE_FILE}")
    except Exception as e:
        print(f"Error creating {EXCLUDE_FILE}: {str(e)}")
        return

    # Parse IP file
    ip_ranges = parse_ip_file(IP_FILE)
    if not ip_ranges:
        print("No valid IPs to scan. Exiting.")
        return

    # Run Masscan
    if not run_masscan(ip_ranges):
        return

    # Filter and save results
    camera_ips, all_open_ips = parse_and_filter_cameras()
    save_results(camera_ips, all_open_ips)

if __name__ == "__main__":
    main()
