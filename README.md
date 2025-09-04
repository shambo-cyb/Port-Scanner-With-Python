# Port-Scanner-With-Python
This Python port scanner lets me quickly and safely check multiple targets for open ports, known vulnerabilities, and important services. It supports IP ranges, hostnames, and custom ports, and generates reports in text, CSV, or detailed formats. Perfect for hands-on learning in network security and practical cybersecurity labs.

## Overview

This Python port scanner is designed to help me explore network security in a practical, hands-on way. It allows scanning multiple targets—IP addresses, ranges, or hostnames—for open ports, known vulnerabilities, and essential services. The project is perfect for learning real-world cybersecurity techniques in a controlled environment.

## Key Features
- Supports both quick scans for common ports and thorough scans with custom ranges.
- Validates and resolves hostnames or IP addresses safely.
- Checks for important vulnerabilities on ports like FTP, Telnet, SMB, RDP, and HTTP.
- Uses multithreading for faster scanning.
- Exports results to text files, CSVs, or detailed report formats for easy analysis.

## Why I Built It
- Hands-on practice with networking and cybersecurity fundamentals.
- Understanding port-based vulnerabilities and their implications.
- Sharpening Python scripting skills in a practical project.
- Prepares for real-world penetration testing and security monitoring scenarios.

## Learning Outcome 
This port scanner is a practical tool for cybersecurity learning and practice. It can be used for network reconnaissance, identifying open ports, detecting potential vulnerabilities, and generating actionable reports. Security professionals and students alike can leverage it to strengthen defensive strategies and prepare for real-world penetration testing scenarios.

## Code 
```bash
import socket
import ipaddress
import re
from concurrent.futures import ThreadPoolExecutor
import subprocess
import os
import csv


def validate_hostname_or_ip(remote_server):
    """
    Validates if the input is a valid hostname or IP address.
    """
    ip_regex = re.compile(
        r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    )
    hostname_regex = re.compile(
        r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$'
    )
    try:
        if ip_regex.match(remote_server):
            return True
        if all(hostname_regex.match(label) for label in remote_server.split('.')):
            return True
        return False
    except Exception as e:
        print(f"Validation error: {e}")
        return False


def resolve_hostname(remote_server):
    """
    Resolves a hostname to an IP address.
    """
    if not validate_hostname_or_ip(remote_server):
        print(f"Invalid hostname or IP address: {remote_server}")
        return None

    try:
        try:
            ipaddress.ip_address(remote_server)
            return remote_server  # Already a valid IP
        except ValueError:
            addr_info = socket.getaddrinfo(remote_server, None)
            return addr_info[0][4][0]
    except Exception as e:
        print(f"Error resolving {remote_server}: {e}")
        return None


def validate_port_ranges(port_input):
    """
    Validates and parses custom port input into a list of unique ports.
    """
    ports = set()
    try:
        ranges = port_input.split(',')
        for r in ranges:
            if '-' in r:
                start, end = map(int, r.split('-'))
                if start < 1 or end > 65535 or start > end:
                    raise ValueError("Invalid port range.")
                ports.update(range(start, end + 1))
            else:
                port = int(r)
                if port < 1 or port > 65535:
                    raise ValueError("Port out of range.")
                ports.add(port)
        return sorted(ports)
    except Exception as e:
        print(f"Error parsing ports: {e}")
        return []


def is_host_alive(remote_server_ip):
    """
    Pings the server to check if it's alive.
    """
    try:
        command = ["ping", "-n", "1", remote_server_ip] if os.name == "nt" else ["ping", "-c", "1", remote_server_ip]
        result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return result.returncode == 0
    except Exception as e:
        print(f"Ping error for {remote_server_ip}: {e}")
        return False


def scan_port(remote_server_ip, port):
    """
    Scans a specific port on a remote server and checks for known vulnerabilities.
    """
    vulnerabilities = {
        23: "Telnet is insecure and unencrypted. Consider disabling or using SSH.",
        21: "FTP is insecure and transmits data in plaintext. Consider using SFTP or FTPS.",
        80: "HTTP traffic is not encrypted. Use HTTPS instead.",
        139: "NetBIOS is an outdated protocol. Disable if not required.",
        445: "SMBv1 may be vulnerable to ransomware attacks. Update or disable.",
        3389: "RDP may be exposed. Ensure it is secured with strong credentials and 2FA."
    }

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((remote_server_ip, port))
            if result == 0:
                # Check for known vulnerabilities
                vuln_message = vulnerabilities.get(port, "No known vulnerability.")
                return port, f"Open ({vuln_message})"
            else:
                return port, "Closed"
    except socket.timeout:
        return port, "Timeout"
    except Exception as e:
        return port, f"Error: {e}"


def parse_targets(target_input):
    """
    Parses the target input to handle ranges and disconnected IPs.
    """
    targets = []
    entries = target_input.split(',')
    for entry in entries:
        entry = entry.strip()
        if '-' in entry:  # Handle range of IPs
            try:
                start_ip, end_ip = entry.split('-')
                start_ip = ipaddress.IPv4Address(start_ip.strip())
                end_ip = ipaddress.IPv4Address(end_ip.strip())
                targets.extend(str(ipaddress.IPv4Address(ip)) for ip in range(int(start_ip), int(end_ip) + 1))
            except Exception as e:
                print(f"Invalid IP range {entry}: {e}")
        else:  # Handle individual IP
            if validate_hostname_or_ip(entry):
                targets.append(entry)
            else:
                print(f"Invalid IP address: {entry}")
    return targets


def filter_results(results, filter_type, important_ports):
    """
    Filters scan results based on the user's choice and adds service names and vulnerabilities for important ports.
    """
    # Define services for important ports
    port_services = {
        20: "FTP (Data)",
        21: "FTP (Control)",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        161: "SNMP",
        443: "HTTPS",
        445: "SMB",
        8080: "HTTP Proxy"
    }

    filtered_results = []
    for ip, ports in results.items():
        for port, status in ports.items():
            # Add service name if it's an important port
            service = f" - Service: {port_services[port]}" if port in port_services else ""
            if "Open" in status:
                vuln_info = status.split("(")[1].rstrip(")") if "(" in status else ""
                filtered_results.append(f"{ip}: Port {port} is Open{service} - {vuln_info}")
            elif filter_type == "closed" and status == "Closed":
                filtered_results.append(f"{ip}: Port {port} is {status}{service}")
            elif filter_type == "important" and port in important_ports:
                filtered_results.append(f"{ip}: Port {port} is {status}{service}")
            elif filter_type == "none":
                filtered_results.append(f"{ip}: Port {port} is {status}{service}")
    return filtered_results


def log_results(file_path, results):
    """
    Logs scan results to a specified file.
    """
    with open(file_path, 'w') as file:
        file.write("\n".join(results))


def export_to_csv(file_path, results):
    """
    Exports results to a CSV file.
    """
    with open(file_path, 'w', newline='') as csvfile:
        fieldnames = ['IP Address', 'Port', 'Status']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for ip, ports in results.items():
            for port, status in ports.items():
                writer.writerow({'IP Address': ip, 'Port': port, 'Status': status})


def generate_report(file_path, results, scan_mode, total_targets):
    """
    Generates a detailed report of the scan results.
    """
    with open(file_path, 'w') as report_file:
        report_file.write("Port Scanner Report\n")
        report_file.write("=" * 40 + "\n")
        report_file.write(f"Scan Mode: {scan_mode.capitalize()}\n")
        report_file.write(f"Total Targets: {total_targets}\n")
        report_file.write("=" * 40 + "\n\n")

        for ip, ports in results.items():
            report_file.write(f"Target: {ip}\n")
            for port, status in ports.items():
                report_file.write(f"  Port {port}: {status}\n")
            report_file.write("\n")


def scan_target(remote_server, ports, important_ports):
    """
    Scans a single target for the specified ports.
    """
    resolved_ip = resolve_hostname(remote_server)
    if not resolved_ip:
        print(f"Failed to resolve {remote_server}. Skipping.")
        return {}

    if not is_host_alive(resolved_ip):
        print(f"{remote_server} ({resolved_ip}) is unreachable. Skipping.")
        return {}

    print(f"Scanning {remote_server} ({resolved_ip})...")
    results = {}
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_port = {executor.submit(scan_port, resolved_ip, port): port for port in ports}
        for future in future_to_port:
            port, status = future.result()
            results[port] = status

    return {resolved_ip: results}


def main():
    important_ports = {20, 21, 22, 23, 25, 53, 80, 161, 443, 445, 8080}

    scan_mode = input("Choose scan mode (Quick/Thorough): ").lower()
    if scan_mode == "quick":
        ports = list(important_ports)
    elif scan_mode == "thorough":
        port_input = input("Enter ports/ranges to scan (e.g., 20-25,80,443): ")
        ports = validate_port_ranges(port_input)
        if not ports:
            print("No valid ports provided. Exiting.")
            return
    else:
        print("Invalid mode. Exiting.")
        return

    target_input = input("Enter target(s) (e.g., single IP, range 192.168.1.1-192.168.1.5, or comma-separated): ")
    targets = parse_targets(target_input)
    if not targets:
        print("No valid targets provided. Exiting.")
        return

    filter_type = input("Filter output (open, closed, important, none): ").lower()
    filter_type = filter_type if filter_type in {"open", "closed", "important", "none"} else "none"

    results = {}
    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_target = {executor.submit(scan_target, target, ports, important_ports): target for target in targets}
        for future in future_to_target:
            results.update(future.result())

    filtered_results = filter_results(results, filter_type, important_ports)
    for line in filtered_results:
        print(line)

    # Ask for the file name and file type
    file_name = input("Enter file name (without extension): ").strip()
    file_type = input("Choose file type (text, csv, report): ").strip().lower()

    # Get the current script directory
    current_script_directory = os.path.dirname(os.path.abspath(__file__))

    # Construct the full file path with the provided name and type
    file_path = os.path.join(current_script_directory, f"{file_name}.{file_type}")

    if file_type == "text":
        log_results(file_path, filtered_results)
    elif file_type == "csv":
        export_to_csv(file_path, results)
    elif file_type == "report":
        generate_report(file_path, results, scan_mode, len(targets))

    print(f"File saved at: {file_path}")


if __name__ == "__main__":
    main()
```
