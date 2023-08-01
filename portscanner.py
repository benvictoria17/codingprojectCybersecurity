import nmap

def scan_network(ip_address):
    nm = nmap.PortScanner()
    nm.scan(hosts=ip_address, arguments='-F')  # Fast scan, scans only the most common 100 ports

    for host in nm.all_hosts():
        print(f"Host: {host}")
        if nm[host].state() == 'up':
            print("Status: Up")
            print("Open Ports:")
            for port in nm[host]['tcp'].keys():
                print(f"\tPort: {port}")

if __name__ == "__main__":
    target_ip = input("Enter the IP address or domain to scan: ")
    scan_network(target_ip)
