# Website scanner module for the cybersecurity educational application
import logging
import requests
import time
import random
import validators
from bs4 import BeautifulSoup
import re
from urllib.parse import urlparse
from utils.helpers import is_url, format_severity

logger = logging.getLogger(__name__)

def scan_website(url):
    """
    Scan a website for security vulnerabilities.
    
    Args:
        url (str): The URL of the website to scan
        
    Returns:
        dict: Results of the website scan
    """
    logger.debug(f"Starting website scan for: {url}")
    
    # Validate URL format
    if not is_url(url):
        return {
            "error": f"Invalid URL format: {url}. Please enter a valid URL (e.g., https://example.com)"
        }
    
    # Initialize results dictionary
    results = {
        "url": url,
        "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "security_headers": [],
        "ssl_tls": {},
        "content_findings": [],
        "recommendations": []
    }
    
    # Parse domain from URL
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    
    try:
        # Make request to the website
        headers = {
            "User-Agent": "CyberKidz-SecurityScanner/1.0 (Educational Purpose Only)"
        }
        response = requests.get(url, headers=headers, timeout=10, verify=True)
        
        # Check HTTP status
        results["status_code"] = response.status_code
        
        # Check security headers
        security_headers = check_security_headers(response.headers)
        results["security_headers"] = security_headers
        
        # Check SSL/TLS
        ssl_info = check_ssl_tls(parsed_url.scheme, domain)
        results["ssl_tls"] = ssl_info
        
        # Check for common web vulnerabilities
        content_findings = check_web_content(response.text, url)
        results["content_findings"] = content_findings
        
        # Generate recommendations based on findings
        recommendations = generate_recommendations(security_headers, ssl_info, content_findings)
        results["recommendations"] = recommendations
        
    except requests.exceptions.SSLError:
        results["ssl_tls"] = {
            "secure": False,
            "message": "SSL/TLS certificate validation failed",
            "severity": "high"
        }
        results["recommendations"].append("Fix your SSL/TLS certificate as it's not valid or trusted")
    
    except requests.exceptions.ConnectionError:
        return {
            "error": f"Could not connect to {url}. Please check the URL and try again."
        }
    
    except requests.exceptions.Timeout:
        return {
            "error": f"Connection to {url} timed out. The website might be slow or unavailable."
        }
    
    except requests.exceptions.RequestException as e:
        return {
            "error": f"Error scanning website: {str(e)}"
        }
    
    logger.debug(f"Completed website scan for: {url}")
    return results

def check_security_headers(headers):
    """Check for security-related HTTP headers"""
    security_headers = []
    
    # Important security headers to check
    headers_to_check = {
        "Strict-Transport-Security": {
            "description": "HSTS ensures the browser always uses HTTPS for your site",
            "severity": "medium"
        },
        "Content-Security-Policy": {
            "description": "CSP helps prevent cross-site scripting (XSS) attacks",
            "severity": "medium"
        },
        "X-Content-Type-Options": {
            "description": "Prevents browsers from interpreting files as a different MIME type",
            "severity": "low"
        },
        "X-Frame-Options": {
            "description": "Prevents your site from being put in a frame/iframe (clickjacking protection)",
            "severity": "medium"
        },
        "X-XSS-Protection": {
            "description": "Helps protect against cross-site scripting (XSS) attacks",
            "severity": "medium"
        },
        "Referrer-Policy": {
            "description": "Controls how much referrer information is sent with requests",
            "severity": "low"
        }
    }
    
    # Check if each security header is present
    for header, info in headers_to_check.items():
        if header in headers:
            security_headers.append({
                "header": header,
                "value": headers[header],
                "present": True,
                "description": info["description"],
                "severity": "low"
            })
        else:
            security_headers.append({
                "header": header,
                "present": False,
                "description": info["description"],
                "severity": info["severity"],
                "message": f"Missing {header} security header"
            })
    
    return security_headers

def check_ssl_tls(scheme, domain):
    """Check SSL/TLS configuration"""
    if scheme != "https":
        return {
            "secure": False,
            "message": "Website is not using HTTPS",
            "severity": "high"
        }
    
    # Since we can't do a full SSL/TLS scan safely and simply within this app,
    # we'll just check that HTTPS is available and working
    return {
        "secure": True, 
        "message": "Website is using HTTPS",
        "severity": "low"
    }

def check_web_content(html_content, url):
    """Check web content for potential security issues"""
    findings = []
    
    # Parse HTML
    soup = BeautifulSoup(html_content, 'html.parser')
    
    # Check for password fields in non-HTTPS pages
    if url.startswith("http://"):
        password_fields = soup.find_all("input", {"type": "password"})
        if password_fields:
            findings.append({
                "type": "password_over_http",
                "message": "Password input field found on a non-HTTPS page",
                "severity": "high"
            })
    
    # Check for forms with insecure methods or actions
    forms = soup.find_all("form")
    for form in forms:
        # Check if form submits to HTTP instead of HTTPS
        action = form.get("action", "")
        if action.startswith("http://"):
            findings.append({
                "type": "insecure_form_action",
                "message": f"Form submits data to an insecure (HTTP) URL: {action}",
                "severity": "high"
            })
    
    # Check for mixed content (HTTP resources on HTTPS page)
    if url.startswith("https://"):
        # Check scripts, images, links, iframes for http:// URLs
        for tag_type, attr in [("script", "src"), ("img", "src"), ("link", "href"), ("iframe", "src")]:
            for tag in soup.find_all(tag_type):
                if attr in tag.attrs and tag[attr].startswith("http://"):
                    findings.append({
                        "type": "mixed_content",
                        "message": f"Mixed content: {tag_type} loads over insecure HTTP on an HTTPS page",
                        "severity": "medium"
                    })
    
    # Check for potentially dangerous JavaScript event handlers 
    dangerous_events = ["onclick", "onload", "onmouseover"]
    for event in dangerous_events:
        tags_with_event = soup.find_all(attrs={event: True})
        if tags_with_event:
            findings.append({
                "type": "javascript_event_handlers",
                "message": f"Found {len(tags_with_event)} HTML elements with {event} event handlers",
                "severity": "low" 
            })
    
    # Look for comments that might contain sensitive information
    comments = soup.find_all(string=lambda text: isinstance(text, str) and text.strip().startswith("<!--"))
    if comments:
        suspicious_terms = ["password", "api", "key", "secret", "token", "TODO", "FIXME"]
        for comment in comments:
            comment_text = comment.strip()
            for term in suspicious_terms:
                if term.lower() in comment_text.lower():
                    findings.append({
                        "type": "sensitive_comment",
                        "message": f"HTML comment may contain sensitive information (contains '{term}')",
                        "severity": "medium"
                    })
                    break
    
    return findings

def generate_recommendations(security_headers, ssl_info, content_findings):
    """Generate recommendations based on scan findings"""
    recommendations = []
    
    # SSL/TLS recommendations
    if not ssl_info.get("secure", False):
        recommendations.append("Enable HTTPS for your website by getting an SSL certificate")
    
    # Security header recommendations
    for header in security_headers:
        if not header.get("present", False):
            recommendations.append(f"Add the {header['header']} security header to your website")
    
    # Content findings recommendations
    for finding in content_findings:
        if finding["type"] == "password_over_http":
            recommendations.append("Move all pages with password forms to HTTPS")
        elif finding["type"] == "insecure_form_action":
            recommendations.append("Update form 'action' attributes to use HTTPS URLs")
        elif finding["type"] == "mixed_content":
            recommendations.append("Fix mixed content issues by ensuring all resources use HTTPS")
        elif finding["type"] == "sensitive_comment":
            recommendations.append("Remove sensitive information from HTML comments")
    
    # General recommendations if we don't have any specific ones
    if not recommendations:
        recommendations.append("Regularly update your website software and plugins")
        recommendations.append("Consider implementing a Content Security Policy (CSP)")
    
    return recommendations
