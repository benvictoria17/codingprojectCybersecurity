"""
Helper functions for the cybersecurity educational application
"""
import re
import html
import logging
import socket
import validators

logger = logging.getLogger(__name__)

def format_severity(severity_level):
    """
    Format a severity level with color and icon
    
    Args:
        severity_level (str): Severity level (low, medium, high)
        
    Returns:
        dict: Formatted severity with color, icon, and description
    """
    severity_levels = {
        'low': {
            'color': 'success',
            'icon': 'check-circle',
            'description': 'Low Risk'
        },
        'medium': {
            'color': 'warning',
            'icon': 'exclamation-circle',
            'description': 'Medium Risk'
        },
        'high': {
            'color': 'danger',
            'icon': 'exclamation-triangle',
            'description': 'High Risk'
        }
    }
    
    # Default to medium if unknown severity level
    return severity_levels.get(severity_level.lower(), severity_levels['medium'])

def is_email(email):
    """
    Check if a string is a valid email address
    
    Args:
        email (str): String to check
        
    Returns:
        bool: True if valid email, False otherwise
    """
    return validators.email(email) if email else False

def is_domain(domain):
    """
    Check if a string is a valid domain name
    
    Args:
        domain (str): String to check
        
    Returns:
        bool: True if valid domain, False otherwise
    """
    return validators.domain(domain) if domain else False

def is_ip_address(ip):
    """
    Check if a string is a valid IP address
    
    Args:
        ip (str): String to check
        
    Returns:
        bool: True if valid IP address, False otherwise
    """
    return validators.ip_address.ipv4(ip) or validators.ip_address.ipv6(ip) if ip else False

def is_url(url):
    """
    Check if a string is a valid URL
    
    Args:
        url (str): String to check
        
    Returns:
        bool: True if valid URL, False otherwise
    """
    return validators.url(url) if url else False

def sanitize_input(text):
    """
    Sanitize user input to prevent XSS attacks
    
    Args:
        text (str): Text to sanitize
        
    Returns:
        str: Sanitized text
    """
    if not text:
        return ""
    
    # Convert HTML entities
    text = html.escape(text)
    
    # Remove potentially dangerous patterns
    text = re.sub(r'javascript:', '', text, flags=re.IGNORECASE)
    text = re.sub(r'on\w+\s*=', '', text, flags=re.IGNORECASE)
    
    return text

def is_valid_email(email):
    """
    Check if an email address is valid
    
    Args:
        email (str): Email address to check
        
    Returns:
        bool: True if valid, False otherwise
    """
    # Basic email validation pattern
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def truncate_text(text, max_length=100):
    """
    Truncate text to a maximum length
    
    Args:
        text (str): Text to truncate
        max_length (int): Maximum length of the text
        
    Returns:
        str: Truncated text
    """
    if not text:
        return ""
    
    if len(text) <= max_length:
        return text
    
    return text[:max_length].rstrip() + "..."

def get_recommendations(findings, category):
    """
    Generate recommendations based on findings
    
    Args:
        findings (list): List of findings
        category (str): Category of the scan
        
    Returns:
        list: List of recommendations
    """
    # Basic recommendations that apply to all categories
    basic_recommendations = [
        "Keep all software and systems updated with the latest security patches.",
        "Use strong, unique passwords for all accounts and consider a password manager.",
        "Enable two-factor authentication whenever possible.",
        "Regularly back up important data using the 3-2-1 rule: 3 copies, 2 different media types, 1 off-site."
    ]
    
    # Category-specific recommendations
    category_recommendations = {
        'website': [
            "Implement HTTPS across your entire website.",
            "Set up proper security headers like Content-Security-Policy and X-XSS-Protection.",
            "Remove any unnecessary information disclosure from HTTP headers."
        ],
        'server': [
            "Close unnecessary open ports and disable unused services.",
            "Implement a firewall to restrict access to required services only.",
            "Set up intrusion detection and prevention systems."
        ],
        'network': [
            "Segment your network to limit the impact of potential breaches.",
            "Use a VPN for remote access instead of direct connections.",
            "Monitor network traffic for unusual patterns."
        ],
        'database': [
            "Limit database access to only the necessary users and applications.",
            "Encrypt sensitive data stored in the database.",
            "Implement proper input validation to prevent SQL injection."
        ],
        'cloud': [
            "Follow the principle of least privilege for all cloud resources.",
            "Enable logging and monitoring for all cloud services.",
            "Use encryption for data at rest and in transit."
        ],
        'password': [
            "Use a different password for each account.",
            "Consider using a password manager to generate and store strong passwords.",
            "Change passwords regularly, especially for critical accounts."
        ],
        'phishing': [
            "Be cautious of emails asking for personal information.",
            "Verify the sender's email address for any suspicious messages.",
            "Don't click on links in suspicious emails; type the URL directly."
        ]
    }
    
    # Get category-specific recommendations
    specific_recommendations = category_recommendations.get(category, [])
    
    # Combine and return unique recommendations
    all_recommendations = basic_recommendations + specific_recommendations
    
    # If there are specific findings, add more targeted recommendations
    if findings:
        for finding in findings:
            if 'ssl' in finding.lower() or 'tls' in finding.lower():
                all_recommendations.append("Update SSL/TLS certificates and configurations to use the latest secure versions.")
            if 'header' in finding.lower():
                all_recommendations.append("Implement missing security headers and review current header configurations.")
            if 'password' in finding.lower():
                all_recommendations.append("Review password policies and implement stronger requirements.")
    
    # Return unique recommendations
    return list(set(all_recommendations))