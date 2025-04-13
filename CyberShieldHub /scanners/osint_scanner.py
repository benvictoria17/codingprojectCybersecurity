# OSINT scanner module for the cybersecurity educational application
import logging
import re
import socket
import time
import random
import validators
from utils.helpers import is_email, is_domain, is_ip_address

logger = logging.getLogger(__name__)

def perform_osint_scan(target):
    """
    Perform an OSINT (Open Source Intelligence) scan on the target.
    The target can be a name, email, domain, or IP address.
    
    Args:
        target (str): The target to scan (name, email, domain, or IP address)
        
    Returns:
        dict: Results of the OSINT scan
    """
    logger.debug(f"Starting OSINT scan for: {target}")
    
    # Initialize results dictionary
    results = {
        "target": target,
        "findings": [],
        "recommendations": []
    }
    
    # Determine target type
    if is_email(target):
        email_scan_results = scan_email(target)
        results["findings"].extend(email_scan_results.get("findings", []))
        results["recommendations"].extend(email_scan_results.get("recommendations", []))
        
    elif is_domain(target):
        domain_scan_results = scan_domain(target)
        results["findings"].extend(domain_scan_results.get("findings", []))
        results["recommendations"].extend(domain_scan_results.get("recommendations", []))
        
    elif is_ip_address(target):
        ip_scan_results = scan_ip_address(target)
        results["findings"].extend(ip_scan_results.get("findings", []))
        results["recommendations"].extend(ip_scan_results.get("recommendations", []))
        
    else:
        # Assume it's a person's name
        name_scan_results = scan_name(target)
        results["findings"].extend(name_scan_results.get("findings", []))
        results["recommendations"].extend(name_scan_results.get("recommendations", []))
    
    # Add general OSINT recommendations
    results["recommendations"].append("Regularly check what information about you is public online")
    results["recommendations"].append("Be careful about what you share on social media")
    results["recommendations"].append("Use privacy settings on all your online accounts")
    
    logger.debug(f"Completed OSINT scan for: {target}")
    return results

def scan_email(email):
    """Scan an email address for OSINT information"""
    logger.debug(f"Scanning email: {email}")
    
    results = {
        "findings": [],
        "recommendations": []
    }
    
    # Simulate finding information about the email
    domain = email.split('@')[1]
    username = email.split('@')[0]
    
    # Add findings
    results["findings"].append(f"Email domain: {domain}")
    
    # Simulate checking if email has been in data breaches
    breach_check = simulate_breach_check(email)
    if breach_check:
        results["findings"].append({
            "severity": "high",
            "message": f"This email appears in {breach_check} data breaches"
        })
        results["recommendations"].append("Change passwords for this email account and any accounts using this email")
    else:
        results["findings"].append({
            "severity": "low",
            "message": "No data breaches found for this email"
        })
    
    # Check if username is commonly used
    results["findings"].append(f"Username: {username}")
    results["recommendations"].append("Use different usernames across different platforms to avoid being tracked")
    
    # Domain information
    domain_info = scan_domain(domain)
    results["findings"].extend([f"Email provider information: {finding}" for finding in domain_info.get("findings", [])])
    
    return results

def scan_domain(domain):
    """Scan a domain for OSINT information"""
    logger.debug(f"Scanning domain: {domain}")
    
    results = {
        "findings": [],
        "recommendations": []
    }
    
    # Basic domain checks
    if not validators.domain(domain):
        results["findings"].append({
            "severity": "low",
            "message": f"Invalid domain format: {domain}"
        })
        return results
    
    # Attempt to get IP address
    try:
        ip_address = socket.gethostbyname(domain)
        results["findings"].append(f"IP address: {ip_address}")
        
        # Add IP reputation information
        ip_reputation = "good" if random.random() > 0.3 else "suspicious"
        if ip_reputation == "suspicious":
            results["findings"].append({
                "severity": "medium",
                "message": f"IP address {ip_address} has suspicious reputation"
            })
    except socket.gaierror:
        results["findings"].append({
            "severity": "medium",
            "message": f"Could not resolve domain to IP address"
        })
    
    # Check for WHOIS information
    results["findings"].append("WHOIS information available (registration date, registrar)")
    results["recommendations"].append("Consider using WHOIS privacy protection for your domains")
    
    # Check for SSL certificate
    ssl_enabled = random.choice([True, False])
    if ssl_enabled:
        results["findings"].append({
            "severity": "low",
            "message": "Domain has SSL certificate (HTTPS enabled)"
        })
    else:
        results["findings"].append({
            "severity": "medium",
            "message": "Domain does not have SSL certificate (HTTPS not enabled)"
        })
        results["recommendations"].append("Enable HTTPS for your website by getting an SSL certificate")
    
    # Simulate DNS records check
    dns_records = ["A", "MX", "TXT", "NS"]
    results["findings"].append(f"Found {len(dns_records)} DNS record types: {', '.join(dns_records)}")
    
    # Simulate checking for subdomains
    subdomain_count = random.randint(0, 5)
    if subdomain_count > 0:
        results["findings"].append(f"Found {subdomain_count} public subdomains")
    
    return results

def scan_ip_address(ip):
    """Scan an IP address for OSINT information"""
    logger.debug(f"Scanning IP address: {ip}")
    
    results = {
        "findings": [],
        "recommendations": []
    }
    
    # Validate IP address format
    if not is_ip_address(ip):
        results["findings"].append({
            "severity": "low",
            "message": f"Invalid IP address format: {ip}"
        })
        return results
    
    # Geolocation simulation
    countries = ["United States", "Canada", "United Kingdom", "Germany", "France", "Japan", "Australia"]
    country = random.choice(countries)
    results["findings"].append(f"Geolocation: {country}")
    
    # ISP information
    isps = ["Comcast", "Verizon", "AT&T", "Deutsche Telekom", "BT Group", "NTT", "Telstra"]
    isp = random.choice(isps)
    results["findings"].append(f"Internet Service Provider: {isp}")
    
    # Check if it's a hosting provider
    is_hosting = random.choice([True, False])
    if is_hosting:
        results["findings"].append("This IP belongs to a web hosting provider")
    
    # Reputation check
    reputation_score = random.randint(0, 100)
    if reputation_score < 30:
        results["findings"].append({
            "severity": "high",
            "message": f"IP has poor reputation score: {reputation_score}/100"
        })
        results["recommendations"].append("This IP may be flagged for malicious activity")
    elif reputation_score < 70:
        results["findings"].append({
            "severity": "medium",
            "message": f"IP has average reputation score: {reputation_score}/100"
        })
    else:
        results["findings"].append({
            "severity": "low",
            "message": f"IP has good reputation score: {reputation_score}/100"
        })
    
    return results

def scan_name(name):
    """Scan a person's name for OSINT information"""
    logger.debug(f"Scanning name: {name}")
    
    results = {
        "findings": [],
        "recommendations": []
    }
    
    # This is a simulated scan for educational purposes
    results["findings"].append("Searching for public profiles with this name")
    
    # Simulate finding social media profiles
    social_platforms = ["Facebook", "Twitter", "LinkedIn", "Instagram", "GitHub", "YouTube"]
    found_platforms = random.sample(social_platforms, random.randint(0, len(social_platforms)))
    
    if found_platforms:
        results["findings"].append(f"Found potential profiles on: {', '.join(found_platforms)}")
        results["recommendations"].append("Check your privacy settings on these platforms")
    else:
        results["findings"].append("No obvious social media profiles found with this exact name")
    
    # Simulate finding profile pictures
    has_profile_pics = random.choice([True, False])
    if has_profile_pics:
        results["findings"].append({
            "severity": "medium",
            "message": "Found public profile pictures that may be associated with this name"
        })
        results["recommendations"].append("Consider setting profile pictures to private or friends-only")
    
    # Simulate finding mentions on websites
    mention_count = random.randint(0, 10)
    if mention_count > 0:
        results["findings"].append(f"Found approximately {mention_count} mentions on public websites")
    
    return results

def simulate_breach_check(email):
    """Simulate checking if an email has been in data breaches"""
    # This is a simulation for educational purposes
    # In a real app, you would use a service like HaveIBeenPwned or similar
    
    # Return a random number of breaches (or 0 for no breaches)
    if random.random() < 0.4:
        return random.randint(1, 5)
    else:
        return 0
