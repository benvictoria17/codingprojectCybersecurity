import nmap

def nmap_vulnerability_scan(target_ip):
    nm = nmap.PortScanner()

    print(f"Scanning {target_ip} for common vulnerabilities...")

    # Perform a vulnerability scan using Nmap
    nm.scan(hosts=target_ip, arguments="-sV --script vulners")

    # Check if the target IP is up
    if target_ip in nm.all_hosts():
        print(f"\nScan results for {target_ip}:\n")
        for host in nm.all_hosts():
            print(f"Host: {host}")
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in lport:
                    print(f"Port: {port}\tState: {nm[host][proto][port]['state']}")
                    if 'vulners' in nm[host][proto][port]['script']:
                        vulnerabilities = nm[host][proto][port]['script']['vulners']
                        print("Vulnerabilities:")
                        for vuln in vulnerabilities:
                            print(f"\t- {vuln}")
            print()
    else:
        print(f"{target_ip} is not responding to the scan.")

if __name__ == "__main__":
    target_ip = input("Enter the target IP address: ")
    nmap_vulnerability_scan(target_ip)
