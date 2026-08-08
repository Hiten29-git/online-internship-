"""
Port Status Checker
--------------------
Scans a target host across a range of TCP ports and reports whether
each is open or closed. Useful for basic network security auditing
(e.g. checking which services are exposed on your own host).

Usage:
    python port_checker.py <host> [--start 1] [--end 1024] [--timeout 0.5] [--threads 100]

Example:
    python port_checker.py 127.0.0.1 --start 1 --end 1024

Author: Hiten G
"""

import argparse
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed


def scan_port(host: str, port: int, timeout: float = 0.5) -> bool:
    """Returns True if the given TCP port on host is open."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        return result == 0


def service_name(port: int) -> str:
    """Best-effort lookup of the common service name for a port."""
    try:
        return socket.getservbyport(port)
    except OSError:
        return "unknown"


def scan_range(host: str, start_port: int, end_port: int,
                timeout: float = 0.5, max_threads: int = 100):
    """
    Scans host from start_port to end_port (inclusive) concurrently.
    Returns a sorted list of open ports.
    """
    open_ports = []
    ports = range(start_port, end_port + 1)

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_to_port = {
            executor.submit(scan_port, host, port, timeout): port
            for port in ports
        }
        for future in as_completed(future_to_port):
            port = future_to_port[future]
            try:
                if future.result():
                    open_ports.append(port)
            except socket.gaierror:
                raise
            except Exception:
                # treat unreachable/errored ports as closed
                pass

    return sorted(open_ports)


def main():
    parser = argparse.ArgumentParser(description="Simple TCP port status checker.")
    parser.add_argument("host", help="Target hostname or IP address")
    parser.add_argument("--start", type=int, default=1, help="Start port (default: 1)")
    parser.add_argument("--end", type=int, default=1024, help="End port (default: 1024)")
    parser.add_argument("--timeout", type=float, default=0.5, help="Per-port timeout in seconds")
    parser.add_argument("--threads", type=int, default=100, help="Max concurrent threads")
    args = parser.parse_args()

    try:
        resolved_ip = socket.gethostbyname(args.host)
    except socket.gaierror:
        print(f"Could not resolve host: {args.host}")
        return

    print(f"Scanning {args.host} ({resolved_ip}) ports {args.start}-{args.end} ...\n")

    open_ports = scan_range(args.host, args.start, args.end, args.timeout, args.threads)

    if not open_ports:
        print("No open ports found in the given range.")
    else:
        print(f"{'PORT':<10}{'STATE':<10}{'SERVICE'}")
        for port in open_ports:
            print(f"{port:<10}{'open':<10}{service_name(port)}")

    print(f"\nScan complete: {len(open_ports)} open port(s) out of "
          f"{args.end - args.start + 1} scanned.")


if __name__ == "__main__":
    main()
