import ipaddress
import subprocess
import platform
import socket
import csv
import sys
import time
from typing import Optional, Tuple


def validate_cidr(cidr: str) -> ipaddress.IPv4Network:
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        if not isinstance(network, ipaddress.IPv4Network):
            raise ValueError("Only IPv4 networks are supported.")
        return network
    except ValueError as e:
        raise ValueError(f"Invalid CIDR notation: {e}")


def ping_host(ip: str, timeout: int = 1) -> Tuple[str, Optional[float], Optional[str]]:
  
    system = platform.system().lower()

    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(timeout), ip]

    try:
        start = time.time()
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        end = time.time()

        if result.returncode == 0:
            response_time = round((end - start) * 1000, 2)
            return "UP", response_time, None
        else:
            return "DOWN", None, "No response"

    except Exception as e:
        return "ERROR", None, str(e)


def reverse_dns_lookup(ip: str) -> Optional[str]:
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except socket.herror:
        return None
    except Exception:
        return None


def export_to_csv(filename: str, results: list):
    with open(filename, mode="w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["IP Address", "Status", "Response Time (ms)", "Hostname"])

        for row in results:
            writer.writerow(row)

    print(f"\nResults exported to {filename}")


def scan_network(network: ipaddress.IPv4Network):
    print(f"\nScanning network {network}...\n")

    active_hosts = 0
    down_hosts = 0
    error_hosts = 0
    results = []

    for ip in network.hosts():
        ip_str = str(ip)

        status, response_time, error = ping_host(ip_str)

        print(f"{ip_str:15} - {status}", end="")

        hostname = None

        if status == "UP":
            active_hosts += 1
            print(f" ({response_time} ms)")
            hostname = reverse_dns_lookup(ip_str)
            if hostname:
                print(f"{'':15}   Hostname: {hostname}")

        elif status == "DOWN":
            down_hosts += 1
            print(" (No response)")

        else:
            error_hosts += 1
            print(f" (Error: {error})")

        results.append([ip_str, status, response_time, hostname])

    print("\nScan complete.")
    print(f"Found {active_hosts} active hosts, {down_hosts} down, {error_hosts} error(s).")

    return results


def main():
    if len(sys.argv) != 2:
        print("Usage: python ip_freely.py <CIDR>")
        print("Example: python ip_freely.py 192.168.1.0/24")
        sys.exit(1)

    cidr_input = sys.argv[1]

    try:
        network = validate_cidr(cidr_input)
    except ValueError as e:
        print(e)
        sys.exit(1)

    results = scan_network(network)

    export_to_csv("scan_results.csv", results)


if __name__ == "__main__":
    main()