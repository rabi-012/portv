import nmap

def port_version_scan(target, ports):
    scanner = nmap.PortScanner()

    print(f"Scanning {target} on ports {ports} for version info...\n")

    try:
        # Scan the specified ports with version detection (-sV)
        scanner.scan(hosts=target, ports=ports, arguments='-sV')

        for host in scanner.all_hosts():
            print(f"Host: {host} ({scanner[host].hostname()})")
            print(f"Status: {scanner[host].state()}\n")

            for proto in scanner[host].all_protocols():
                scanned_ports = scanner[host][proto].keys()

                for port in sorted(scanned_ports):
                    service = scanner[host][proto][port]
                    name = service.get('name', 'unknown')
                    product = service.get('product', '')
                    version = service.get('version', '')
                    extrainfo = service.get('extrainfo', '')

                    print(f"Port {port}/{proto} - {name}")
                    version_info = f"{product} {version}".strip()
                    if extrainfo:
                        version_info += f" ({extrainfo})"
                    if version_info:
                        print(f"  Version: {version_info}")
                    else:
                        print("  Version: Unknown")
                    print()

    except nmap.PortScannerError as e:
        print(f"Nmap error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

if __name__ == "__main__":
    target = input("Enter target IP or domain: ").strip()
    ports = input("Enter port number(s) (e.g. 80,443 or 20-25): ").strip()

    if target and ports:
        port_version_scan(target, ports)
    else:
        print("Please provide both target and port(s).")
