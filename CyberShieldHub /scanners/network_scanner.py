# Network scanner module for the cybersecurity educational application
import logging
import ipaddress
import socket
import time
import random
import re
from utils.helpers import is_ip_address, format_severity

logger = logging.getLogger(__name__)

def scan_network(target):
    """
    Scan a network for active hosts and potential vulnerabilities.
    
    Args:
        target (str): The network address (e.g., 192.168.1.0/24) or a single IP address
        
    Returns:
        dict: Results of the network scan
    """
    logger.debug(f"Starting network scan for: {target}")
    
    # Initialize results dictionary
    results = {
        "target": target,
        "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "hosts": [],
        "findings": [],
        "recommendations": []
    }
    
    # Validate and parse the target
    try:
        # Check if target is a CIDR notation network (e.g., 192.168.1.0/24)
        if '/' in target:
            network = ipaddress.ip_network(target, strict=False)
            is_network = True
            results["network_size"] = network.num_addresses
            if network.num_addresses > 256:
                return {
                    "error": "Network size too large to scan. Please use a smaller network (maximum /24 or 256 addresses)."
                }
        else:
            # Single IP address
            if not is_ip_address(target):
                return {
                    "error": f"Invalid IP address format: {target}. Please enter a valid IP address."
                }
            network = [ipaddress.ip_address(target)]
            is_network = False
    
    except ValueError:
        return {
            "error": f"Invalid network address format: {target}. Please use CIDR notation (e.g., 192.168.1.0/24) or a single IP."
        }
    
    # Generate simulated network scan for educational purposes
    hosts_found = []
    
    # For a single IP, just check if it's reachable
    if not is_network:
        host_info = check_host(str(network[0]))
        if host_info:
            hosts_found.append(host_info)
    else:
        # For a network, scan several hosts (simulation)
        # In a real scanner, we would scan every IP in the network
        # Here we'll simulate finding a few active hosts
        
        # Get the base of the network (e.g., "192.168.1." for 192.168.1.0/24)
        if isinstance(network, ipaddress.IPv4Network):
            network_base = str(network.network_address).rsplit('.', 1)[0] + '.'
            
            # Common host addresses to check
            common_hosts = [1, 100, 101, 102, 254]  # Common addresses like gateway, DHCP server, etc.
            
            # Simulate finding 3-8 hosts
            num_active = min(random.randint(3, 8), len(common_hosts))
            active_hosts = random.sample(common_hosts, num_active)
            
            for host_suffix in active_hosts:
                host_ip = network_base + str(host_suffix)
                host_info = check_host(host_ip)
                if host_info:
                    hosts_found.append(host_info)
    
    results["hosts"] = hosts_found
    
    # Add findings based on discovered hosts
    if hosts_found:
        # Check for default gateway
        gateway = next((host for host in hosts_found if host.get("is_gateway", False)), None)
        if gateway:
            results["findings"].append({
                "message": f"Found default gateway at {gateway['ip']}",
                "severity": "low"
            })
        
        # Check for potentially vulnerable devices
        vulnerable_hosts = []
        for host in hosts_found:
            if "vulnerabilities" in host and host["vulnerabilities"]:
                vulnerable_hosts.append(host)
        
        if vulnerable_hosts:
            for host in vulnerable_hosts:
                for vuln in host.get("vulnerabilities", []):
                    results["findings"].append({
                        "message": f"Host {host['ip']} ({host.get('type', 'Unknown Device')}) may have vulnerability: {vuln['name']}",
                        "severity": vuln["severity"]
                    })
    else:
        results["findings"].append({
            "message": "No active hosts found on the network",
            "severity": "low"
        })
    
    # Generate recommendations
    results["recommendations"] = generate_recommendations(hosts_found, is_network)
    
    logger.debug(f"Completed network scan for: {target}")
    return results

def check_host(ip):
    """Check if a host is active and gather basic information"""
    # This is a simulation for educational purposes
    # In a real scanner, we would use techniques like ping and port scanning
    
    # Simulate some common host types
    host_types = {
        "1": {"type": "Router/Gateway", "is_gateway": True, "os": "Router OS"},
        "100": {"type": "Desktop Computer", "is_gateway": False, "os": "Windows 10"},
        "101": {"type": "Laptop", "is_gateway": False, "os": "macOS"},
        "102": {"type": "Smart TV", "is_gateway": False, "os": "Android TV"},
        "254": {"type": "Network Printer", "is_gateway": False, "os": "Printer Firmware"}
    }
    
    # Try to determine the host type based on the last octet
    last_octet = ip.split('.')[-1]
    
    # Simulate the host being active or not (for educational purposes)
    # In a real app, we would check if the host responds to ping or other probes
    is_active = True
    
    if not is_active:
        return None
    
    # Create the host info
    host_info = {
        "ip": ip,
        "status": "active",
        "open_ports": []
    }
    
    # Add type info if we recognize this host pattern
    if last_octet in host_types:
        host_info.update(host_types[last_octet])
        
        # Add some simulated open ports based on the device type
        if host_types[last_octet]["type"] == "Router/Gateway":
            host_info["open_ports"] = [
                {"port": 80, "service": "HTTP (Web Interface)"},
                {"port": 443, "service": "HTTPS (Secure Web Interface)"}
            ]
        elif host_types[last_octet]["type"] == "Desktop Computer":
            host_info["open_ports"] = [
                {"port": 445, "service": "SMB (File Sharing)"}
            ]
        elif host_types[last_octet]["type"] == "Network Printer":
            host_info["open_ports"] = [
                {"port": 9100, "service": "Printer Port"},
                {"port": 80, "service": "HTTP (Printer Web Interface)"}
            ]
        elif host_types[last_octet]["type"] == "Smart TV":
            host_info["open_ports"] = [
                {"port": 8008, "service": "HTTP (Smart TV Interface)"}
            ]
    else:
        # Generic device type for unrecognized patterns
        host_info["type"] = "Unknown Device"
        
        # Add some random open ports
        common_ports = [80, 443, 22, 21]
        num_open = random.randint(0, 2)
        if num_open > 0:
            open_ports = random.sample(common_ports, num_open)
            host_info["open_ports"] = [{"port": p, "service": get_service_name(p)} for p in open_ports]
    
    # Add vulnerabilities for some devices (for educational purposes)
    if "type" in host_info:
        if host_info["type"] == "Router/Gateway":
            # Simulate finding router with default password vulnerability
            if random.random() < 0.3:
                host_info["vulnerabilities"] = [{
                    "name": "Default admin credentials may be in use",
                    "severity": "high"
                }]
        elif host_info["type"] == "Network Printer":
            # Simulate finding printer with firmware vulnerability
            if random.random() < 0.5:
                host_info["vulnerabilities"] = [{
                    "name": "Outdated printer firmware",
                    "severity": "medium"
                }]
        elif host_info["type"] == "Smart TV":
            # Simulate finding Smart TV with outdated software
            if random.random() < 0.4:
                host_info["vulnerabilities"] = [{
                    "name": "Smart TV software not updated",
                    "severity": "medium"
                }]
    
    return host_info

def get_service_name(port):
    """Get the service name for a port number"""
    common_services = {
        20: "FTP Data",
        21: "FTP Control",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        3306: "MySQL",
        3389: "RDP",
        8008: "HTTP Alt",
        8080: "HTTP Proxy",
        9100: "Printer"
    }
    
    return common_services.get(port, "Unknown")

def generate_recommendations(hosts, is_network):
    """Generate recommendations based on scan findings"""
    recommendations = []
    
    if not hosts:
        if is_network:
            recommendations.append("No active hosts found in the scanned network range")
        else:
            recommendations.append("The specified host is not responding")
        return recommendations
    
    # Check for vulnerable devices
    vulnerable_hosts = [host for host in hosts if "vulnerabilities" in host and host["vulnerabilities"]]
    
    if vulnerable_hosts:
        recommendations.append("Update firmware/software on all network devices regularly")
        recommendations.append("Change default passwords on all network devices")
    
    # Check for potentially dangerous open ports
    risky_ports = []
    for host in hosts:
        for port_info in host.get("open_ports", []):
            port = port_info["port"]
            if port in [21, 23, 3389]:
                risky_ports.append(f"{host['ip']}:{port} ({port_info['service']})")
    
    if risky_ports:
        recommendations.append(f"Consider securing or closing these risky ports: {', '.join(risky_ports)}")
    
    # Router recommendations
    router = next((host for host in hosts if host.get("is_gateway", False)), None)
    if router:
        recommendations.append("Ensure your router firmware is up to date")
        recommendations.append("Use WPA3 encryption for your Wi-Fi network if supported")
    
    # General recommendations
    recommendations.append("Use a firewall to protect your network")
    recommendations.append("Create a separate guest Wi-Fi network for visitors")
    
    return recommendations
