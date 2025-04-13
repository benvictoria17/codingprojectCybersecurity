# Google dorking module for the cybersecurity educational application
import logging
import time
import random
import re
from utils.helpers import format_severity, sanitize_input

logger = logging.getLogger(__name__)

def perform_google_dork(dork_type, keyword):
    """
    Perform a Google dork search simulation for educational purposes.
    
    Args:
        dork_type (str): The type of dork (site, filetype, inurl, intitle, intext)
        keyword (str): The keyword or value to search for
        
    Returns:
        dict: Results of the Google dork search
    """
    logger.debug(f"Starting Google dork search: {dork_type}:{keyword}")
    
    # Sanitize inputs to prevent any injection
    dork_type = sanitize_input(dork_type)
    keyword = sanitize_input(keyword)
    
    # Initialize results dictionary
    results = {
        "dork_type": dork_type,
        "keyword": keyword,
        "search_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "query": f"{dork_type}:{keyword}",
        "results": [],
        "educational_notes": [],
        "recommendations": []
    }
    
    # Validate dork type
    valid_dork_types = ["site", "filetype", "inurl", "intitle", "intext"]
    if dork_type.lower() not in valid_dork_types:
        return {
            "error": f"Invalid dork type: {dork_type}. Supported types are: {', '.join(valid_dork_types)}"
        }
    
    # Check if keyword is empty
    if not keyword:
        return {
            "error": "Keyword cannot be empty. Please enter a search keyword."
        }
    
    # Add educational notes based on dork type
    results["educational_notes"] = get_educational_notes(dork_type)
    
    # Generate simulated search results
    simulated_results = simulate_dork_results(dork_type, keyword)
    results["results"] = simulated_results
    
    # Generate recommendations to protect against this type of dorking
    results["recommendations"] = generate_recommendations(dork_type, keyword)
    
    logger.debug(f"Completed Google dork search: {dork_type}:{keyword}")
    return results

def get_educational_notes(dork_type):
    """Get educational notes for each dork type"""
    notes = {
        "site": [
            "The 'site:' dork restricts search results to a specific website or domain.",
            "Example: 'site:example.com password' would search for the word 'password' only on example.com.",
            "Hackers use this to find sensitive information on specific websites.",
            "Website owners can use this to check what information is exposed on their site."
        ],
        "filetype": [
            "The 'filetype:' dork finds specific types of files like PDF, XLS, DOC, etc.",
            "Example: 'filetype:pdf confidential' would find PDF files containing the word 'confidential'.",
            "Hackers use this to find documents that might contain sensitive information.",
            "Common targets include PDF, XLS, DOC, CFG, and LOG files."
        ],
        "inurl": [
            "The 'inurl:' dork finds pages with specific text in the URL.",
            "Example: 'inurl:admin' would find pages that have 'admin' in their URL.",
            "Hackers use this to find admin pages, login portals, and other sensitive areas.",
            "It's useful for finding specific sections of websites that might not be well-protected."
        ],
        "intitle": [
            "The 'intitle:' dork finds pages with specific text in the title.",
            "Example: 'intitle:\"index of\"' would find directory listing pages.",
            "Hackers use this to find pages that might expose file directories or sensitive information.",
            "Directory listings can reveal files that shouldn't be publicly accessible."
        ],
        "intext": [
            "The 'intext:' dork finds pages with specific text in their content.",
            "Example: 'intext:\"username password\"' might find pages with login credentials.",
            "This is one of the broadest dorks and can find information throughout a website's content.",
            "Hackers use this to find specific pieces of information like error messages, passwords, or configuration details."
        ]
    }
    
    return notes.get(dork_type.lower(), ["No specific educational notes for this dork type."])

def simulate_dork_results(dork_type, keyword):
    """
    Simulate Google dork search results for educational purposes.
    This is a simulation to show what kinds of results might be found.
    """
    # Define sample result templates for each dork type
    result_templates = {
        "site": [
            {
                "title": "Login Portal - {keyword}",
                "url": "https://{keyword}/login",
                "description": "Login to access your account. Enter your username and password to continue."
            },
            {
                "title": "Admin Dashboard - {keyword}",
                "url": "https://{keyword}/admin",
                "description": "Administrative control panel for site management and configuration."
            },
            {
                "title": "Internal Documents - {keyword}",
                "url": "https://{keyword}/docs/internal",
                "description": "Repository of internal company documents and resources."
            },
            {
                "title": "User Guide - {keyword}",
                "url": "https://{keyword}/support/guide",
                "description": "User documentation and help resources for customers."
            }
        ],
        "filetype": [
            {
                "title": "Company Financial Report 2023.{keyword}",
                "url": "https://example.com/reports/financial_2023.{keyword}",
                "description": "Annual financial report containing revenue, expenses, and projections."
            },
            {
                "title": "Employee Handbook.{keyword}",
                "url": "https://example.com/hr/handbook.{keyword}",
                "description": "Internal company policies, procedures, and employee guidelines."
            },
            {
                "title": "System Configuration.{keyword}",
                "url": "https://example.com/it/config.{keyword}",
                "description": "Technical configuration documentation for IT systems and infrastructure."
            },
            {
                "title": "Project Proposal - Confidential.{keyword}",
                "url": "https://example.com/projects/proposal.{keyword}",
                "description": "Detailed project proposal including timelines, budgets, and objectives."
            }
        ],
        "inurl": [
            {
                "title": "Admin Login - Example Corp",
                "url": "https://example.com/{keyword}/login",
                "description": "Administrative login portal for system management."
            },
            {
                "title": "User Management - Example Corp",
                "url": "https://example.com/{keyword}/users",
                "description": "User account management interface for administrators."
            },
            {
                "title": "Configuration Settings - Example Corp",
                "url": "https://example.com/{keyword}/config",
                "description": "System configuration settings and parameters."
            },
            {
                "title": "Security Settings - Example Corp",
                "url": "https://example.com/{keyword}/security",
                "description": "Security parameters and settings for system protection."
            }
        ],
        "intitle": [
            {
                "title": "{keyword} - Login Portal",
                "url": "https://example.com/login",
                "description": "Enter your credentials to access the system."
            },
            {
                "title": "{keyword} - Configuration Panel",
                "url": "https://example.com/config",
                "description": "System configuration and settings management interface."
            },
            {
                "title": "{keyword} - Error Log",
                "url": "https://example.com/logs/error",
                "description": "System error logs and debugging information."
            },
            {
                "title": "{keyword} - User Database",
                "url": "https://example.com/users",
                "description": "Database of user information and account details."
            }
        ],
        "intext": [
            {
                "title": "System Documentation - Example Corp",
                "url": "https://example.com/docs/system",
                "description": "...detailed system architecture. The {keyword} must be kept secure at all times..."
            },
            {
                "title": "Configuration Guide - Example Corp",
                "url": "https://example.com/guides/config",
                "description": "...follow these steps to configure the system. Make sure the {keyword} is properly set..."
            },
            {
                "title": "Error Logs - Example Corp",
                "url": "https://example.com/logs",
                "description": "...error occurred during authentication. Invalid {keyword} provided by user..."
            },
            {
                "title": "Security Policy - Example Corp",
                "url": "https://example.com/security/policy",
                "description": "...all employees must protect their {keyword} and not share it with anyone..."
            }
        ]
    }
    
    # Get templates for the specified dork type
    templates = result_templates.get(dork_type.lower(), [])
    
    # If no templates are available, return empty results
    if not templates:
        return []
    
    # Generate random number of results (1-4)
    num_results = random.randint(1, len(templates))
    
    # Select random templates
    selected_templates = random.sample(templates, num_results)
    
    # Fill in the templates with the keyword
    results = []
    for template in selected_templates:
        result = {
            "title": template["title"].format(keyword=keyword),
            "url": template["url"].format(keyword=keyword),
            "description": template["description"].format(keyword=keyword)
        }
        results.append(result)
    
    return results

def generate_recommendations(dork_type, keyword):
    """Generate recommendations to protect against this type of Google dorking"""
    # Common recommendations for all dork types
    common_recommendations = [
        "Use robots.txt to prevent search engines from indexing sensitive areas of your website",
        "Regularly search for your own website using Google dorks to find exposed information",
        "Implement proper authentication and authorization for all sensitive resources",
        "Don't rely on 'security through obscurity' - assume all public URLs can be discovered"
    ]
    
    # Specific recommendations based on dork type
    specific_recommendations = {
        "site": [
            "Review all content on your website to ensure sensitive information isn't publicly accessible",
            "Use a content management system (CMS) that supports access controls",
            "Consider putting sensitive information behind a login page"
        ],
        "filetype": [
            "Don't store sensitive documents on publicly accessible servers",
            "Password-protect PDF and Office documents containing sensitive information",
            "Use a secure file sharing solution rather than public web servers for documents",
            f"Check if any sensitive {keyword} files are publicly accessible on your website"
        ],
        "inurl": [
            f"Change URLs that contain '{keyword}' if they lead to sensitive areas",
            "Use randomized URL parameters instead of predictable names for sensitive functions",
            "Implement proper access controls regardless of URL structure"
        ],
        "intitle": [
            "Make sure page titles don't reveal sensitive information",
            "Disable directory listings on your web server",
            "Use proper HTTP headers to prevent pages from being indexed"
        ],
        "intext": [
            "Review webpage content for sensitive information like credentials, API keys, or internal data",
            "Use data loss prevention tools to scan for sensitive information",
            "Implement proper error handling that doesn't reveal system details"
        ]
    }
    
    # Combine common and specific recommendations
    recommendations = common_recommendations.copy()
    recommendations.extend(specific_recommendations.get(dork_type.lower(), []))
    
    return recommendations
