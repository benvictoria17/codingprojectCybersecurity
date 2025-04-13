# Server scanner module for the cybersecurity educational application
import logging
import socket
import time
import random
from utils.helpers import is_ip_address, format_severity

logger = logging.getLogger(__name__)

def scan_server(hostname, port=None):
    """
    Scan a server for open ports and potential vulnerabilities.
    
    Args:
        hostname (str): The hostname or IP address of the server to scan
        port (int, optional): A specific port to scan. If None, scans common ports.
        
    Returns:
        dict: Results of the server scan
    """
    logger.debug(f"Starting server scan for: {hostname}, port: {port}")
    
    # Initialize results dictionary
    results = {
        "hostname": hostname,
        "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "ports": [],
        "findings": [],
        "recommendations": []
    }
    
    # Resolve hostname to IP if it's not already an IP
    try:
        if not is_ip_address(hostname):
            ip_address = socket.gethostbyname(hostname)
            results["ip_address"] = ip_address
        else:
            ip_address = hostname
            results["ip_address"] = ip_address
    except socket.gaierror:
        return {
            "error": f"Could not resolve hostname: {hostname}. Please check the spelling and try again."
        }
    
    # Define common ports to scan
    common_ports = {
        20: "FTP data",
        21: "FTP control",
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
        5432: "PostgreSQL",
        8080: "HTTP Alternate"
    }
    
    # If a specific port is provided, only scan that port
    if port:
        ports_to_scan = [port]
        port_info = common_ports.get(port, "Unknown")
        if port not in common_ports:
            results["findings"].append({
                "message": f"Port {port} is not a commonly used port",
                "severity": "low"
            })
    else:
        # Otherwise, scan the most common ports
        ports_to_scan = list(common_ports.keys())
    
    # Perform port scan
    open_ports = []
    for port in ports_to_scan:
        port_open = check_port(ip_address, port)
        if port_open:
            service = common_ports.get(port, "Unknown")
            open_ports.append({
                "port": port,
                "service": service,
                "status": "open"
            })
            
            # Add findings for potentially risky open ports
            if port in [21, 23, 3389]:
                results["findings"].append({
                    "message": f"Port {port} ({service}) is open and potentially risky",
                    "severity": "high",
                    "reason": "This service may have security vulnerabilities or allow unencrypted connections"
                })
            elif port in [20, 25, 110, 143]:
                results["findings"].append({
                    "message": f"Port {port} ({service}) is open and may transmit data unencrypted",
                    "severity": "medium",
                    "reason": "This service might send information without encryption"
                })
    
    results["ports"] = open_ports
    
    # Generate recommendations based on findings
    if open_ports:
        if any(p["port"] in [21, 23] for p in open_ports):
            results["recommendations"].append("Consider using secure alternatives to FTP and Telnet (like SFTP and SSH)")
        
        if any(p["port"] == 3389 for p in open_ports):
            results["recommendations"].append("Limit RDP access to trusted IP addresses only")
        
        results["recommendations"].append("Close any ports that are not necessary for your server to function")
        results["recommendations"].append("Use a firewall to restrict access to open ports")
    else:
        results["findings"].append({
            "message": "No open ports found on common ports",
            "severity": "low"
        })
        
        if port:
            results["recommendations"].append(f"Port {port} appears to be closed or filtered")
        else:
            results["recommendations"].append("Server appears well-protected with no commonly open ports exposed")
    
    logger.debug(f"Completed server scan for: {hostname}")
    return results

def check_port(ip, port):
    """Check if a port is open on a given IP address"""
    try:
        # Create a socket object
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Set a timeout so the scan doesn't hang
        s.settimeout(0.5)
        
        # Try to connect to the port
        result = s.connect_ex((ip, port))
        s.close()
        
        # If result is 0, the port is open
        return result == 0
    
    except (socket.gaierror, socket.error, OverflowError):
        # If there's an error, assume port is closed
        return False
