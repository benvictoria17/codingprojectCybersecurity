# Phishing detector module for the cybersecurity educational application
import logging
import time
import re
import os
import hashlib
import json
from utils.helpers import format_severity, sanitize_input

logger = logging.getLogger(__name__)

# If OpenAI API key is available, use it to analyze emails
try:
    from openai import OpenAI
    openai_available = True
    OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
    if OPENAI_API_KEY:
        openai_client = OpenAI(api_key=OPENAI_API_KEY)
    else:
        openai_available = False
        logger.warning("OpenAI API key not found. Using simulated phishing detection only.")
except ImportError:
    openai_available = False
    logger.warning("OpenAI module not available. Using simulated phishing detection only.")

def analyze_email_for_phishing(subject, content, sender=None, include_links=True):
    """
    Analyze an email for phishing indicators.
    
    Args:
        subject (str): Email subject line
        content (str): Email content/body
        sender (str, optional): Email sender address
        include_links (bool): Whether to analyze links in the email
        
    Returns:
        dict: Analysis results including phishing indicators, score, and recommendations
    """
    logger.debug("Analyzing email for phishing indicators")
    
    # Sanitize inputs
    subject = sanitize_input(subject)
    content = sanitize_input(content)
    if sender:
        sender = sanitize_input(sender)
    
    # Initialize results dictionary
    results = {
        "is_phishing": False,
        "confidence": 0.0,
        "indicators": [],
        "safe_indicators": [],
        "analysis_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "severity": format_severity("low"),
        "educational_notes": get_educational_notes(),
        "recommendations": []
    }
    
    # First, check if OpenAI is available for AI-powered analysis
    ai_analysis = None
    if openai_available and OPENAI_API_KEY:
        ai_analysis = analyze_with_openai(subject, content, sender)
        if ai_analysis and not "error" in ai_analysis:
            results.update(ai_analysis)
            return results
    
    # If OpenAI analysis failed or is unavailable, fall back to rule-based analysis
    rule_based_analysis = analyze_with_rules(subject, content, sender, include_links)
    results.update(rule_based_analysis)
    
    return results

def analyze_with_openai(subject, content, sender=None):
    """
    Use OpenAI's API to analyze an email for phishing indicators.
    
    Args:
        subject (str): Email subject line
        content (str): Email content/body
        sender (str, optional): Email sender address
        
    Returns:
        dict: Analysis results from OpenAI or None if an error occurred
    """
    try:
        # Skip if no API key is available
        if not OPENAI_API_KEY:
            return None
        
        # Prepare the prompt
        email_text = f"Subject: {subject}\n"
        if sender:
            email_text += f"From: {sender}\n"
        email_text += f"\n{content}"
        
        prompt = f"""
        Please analyze this email for signs of phishing. Analyze the content carefully for:
        - Urgency or threatening language
        - Requests for personal information
        - Suspicious links or attachments
        - Grammar errors or unusual wording
        - Inconsistencies in sender information
        - Other red flags
        
        Return your analysis in JSON format with the following fields:
        - "is_phishing": boolean indicating if this is likely a phishing email
        - "confidence": number between 0 and 1 indicating confidence level
        - "indicators": array of strings describing phishing indicators found
        - "safe_indicators": array of strings describing factors that suggest the email is legitimate
        - "recommendations": array of strings with recommendations for the user
        
        Here is the email:
        {email_text}
        """
        
        # Call OpenAI API
        response = openai_client.chat.completions.create(
            model="gpt-3.5-turbo", # the newest OpenAI model is "gpt-4o" which was released May 13, 2024. do not change this unless explicitly requested by the user
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert specializing in phishing email detection. Analyze emails and provide detailed assessments."},
                {"role": "user", "content": prompt}
            ],
            response_format={"type": "json_object"}
        )
        
        # Process the response
        response_text = response.choices[0].message.content
        analysis = json.loads(response_text)
        
        # Format the response
        severity = "high" if analysis.get("is_phishing", False) else "low"
        if analysis.get("confidence", 0) > 0.5 and analysis.get("confidence", 0) < 0.8:
            severity = "medium"
            
        return {
            "is_phishing": analysis.get("is_phishing", False),
            "confidence": analysis.get("confidence", 0.0),
            "indicators": analysis.get("indicators", []),
            "safe_indicators": analysis.get("safe_indicators", []),
            "recommendations": analysis.get("recommendations", []),
            "severity": format_severity(severity),
            "ai_powered": True
        }
        
    except Exception as e:
        logger.error(f"Error with OpenAI analysis: {str(e)}")
        return {"error": f"AI analysis failed: {str(e)}", "ai_powered": False}

def analyze_with_rules(subject, content, sender=None, include_links=True):
    """
    Use rule-based analysis to check an email for phishing indicators.
    
    Args:
        subject (str): Email subject line
        content (str): Email content/body
        sender (str, optional): Email sender address
        include_links (bool): Whether to analyze links in the email
        
    Returns:
        dict: Analysis results based on rule-based detection
    """
    indicators = []
    safe_indicators = []
    recommendations = []
    
    # Check subject line for common phishing patterns
    if re.search(r'urgent|immediate|alert|attention|verify|suspend|update|account|password|security|unusual', subject, re.IGNORECASE):
        indicators.append("Subject line contains urgent or alarming language.")
        recommendations.append("Be skeptical of emails with urgent or alarming subject lines.")
    
    if re.search(r'bank|account|paypal|amazon|netflix|apple|microsoft|google', subject, re.IGNORECASE):
        indicators.append("Subject references a major company or financial service.")
        recommendations.append("Verify emails from companies by contacting them directly through their official website.")
    
    # Check for suspicious content patterns
    if re.search(r'verify.{1,20}account|confirm.{1,20}details|update.{1,20}information|suspicious.{1,20}activity', content, re.IGNORECASE):
        indicators.append("Email asks you to verify your account or confirm personal details.")
        
    if re.search(r'click.{1,30}link|follow.{1,30}link', content, re.IGNORECASE):
        indicators.append("Email encourages you to click on a link.")
        recommendations.append("Hover over links to check their true destination before clicking.")
    
    if re.search(r'password|username|login|ssn|social security|credit card|bank account', content, re.IGNORECASE):
        indicators.append("Email mentions sensitive information like passwords or financial details.")
        recommendations.append("Legitimate organizations usually don't ask for sensitive information via email.")
    
    if re.search(r'limited time|offer expires|act now|won|winner|lottery|prize|million', content, re.IGNORECASE):
        indicators.append("Email contains offers that are too good to be true or creates urgency.")
        
    if re.search(r'dear customer|dear user|valued customer', content, re.IGNORECASE):
        indicators.append("Email uses generic greetings instead of your name.")
        
    # Check for poor grammar and spelling
    spelling_errors = check_for_spelling_errors(content)
    if spelling_errors:
        indicators.append("Email contains spelling or grammar errors.")
        
    # Check sender address if provided
    if sender:
        if check_suspicious_sender(sender):
            indicators.append("Sender email address looks suspicious or doesn't match the claimed organization.")
            recommendations.append("Check the exact email address of the sender, not just the display name.")
    
    # Check for URL manipulation if requested
    if include_links:
        suspicious_links = extract_suspicious_links(content)
        if suspicious_links:
            indicators.append("Email contains suspicious links that may lead to fake websites.")
            recommendations.append("Never click on suspicious links. Type the official URL directly in your browser.")
    
    # If no suspicious indicators found, add some safe indicators
    if not indicators:
        safe_indicators.append("No obvious phishing indicators were detected.")
    
    # Add default recommendations if none were added
    if not recommendations:
        if indicators:
            recommendations.append("Be cautious with this email and verify its authenticity through official channels.")
        else:
            recommendations.append("Always maintain email security practices even with seemingly safe emails.")
    
    # Calculate phishing probability based on number of indicators
    is_phishing = len(indicators) >= 2
    confidence = min(0.95, len(indicators) * 0.2)
    
    # Determine severity
    severity = "low"
    if is_phishing:
        severity = "medium" if confidence < 0.7 else "high"
    
    return {
        "is_phishing": is_phishing,
        "confidence": confidence,
        "indicators": indicators,
        "safe_indicators": safe_indicators,
        "recommendations": recommendations,
        "severity": format_severity(severity),
        "ai_powered": False
    }

def check_for_spelling_errors(text):
    """
    Simple check for obvious spelling and grammar errors.
    This is a simplified version for educational purposes.
    
    Args:
        text (str): Text to check for errors
        
    Returns:
        bool: True if obvious errors are found
    """
    common_errors = [
        (r'\b(teh|adn|taht|wiht|thier|recieve|beleive|seperate|accomodate|occured)\b', 'Misspelled words'),
        (r'\b(i|we|they|he|she) (is|are|was|were) been\b', 'Grammar error'),
        (r'\byour the\b', 'Grammar error'),
        (r'\bplease to\b', 'Grammar error')
    ]
    
    for pattern, _ in common_errors:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    
    return False

def check_suspicious_sender(sender):
    """
    Check if the sender email looks suspicious.
    
    Args:
        sender (str): Email sender address
        
    Returns:
        bool: True if the sender looks suspicious
    """
    # Check for common patterns in phishing sender addresses
    suspicious = False
    
    # Check for misspellings of major domains
    major_domains = ['gmail', 'yahoo', 'hotmail', 'outlook', 'aol', 'icloud', 'microsoft', 'apple', 'amazon', 'facebook', 'paypal']
    for domain in major_domains:
        # Look for misspellings like "gmaii" or "yahooo"
        if re.search(rf'(?<!@){domain}(?=\.)[a-z]+\.com', sender, re.IGNORECASE):
            suspicious = True
            
    # Check for excessive subdomains or unusual top-level domains
    if re.search(r'@.+\..+\..+\..+', sender) or re.search(r'\.(?!com|org|net|edu|gov|io|co|us|uk|ca|au|de|fr|jp)\w+$', sender):
        suspicious = True
        
    # Check for numeric domains that often indicate temporary domains
    if re.search(r'@[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+', sender):
        suspicious = True
        
    return suspicious

def extract_suspicious_links(content):
    """
    Extract and check for suspicious links in the email content.
    
    Args:
        content (str): Email content/body
        
    Returns:
        list: List of suspicious links found
    """
    suspicious_links = []
    
    # Extract links from the content
    # This is a simplified regex for URLs, a real implementation would be more complex
    url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
    links = re.findall(url_pattern, content)
    
    for link in links:
        # Check for IP addresses instead of domain names
        if re.search(r'https?://\d+\.\d+\.\d+\.\d+', link):
            suspicious_links.append(link)
            
        # Check for URL obfuscation techniques
        if re.search(r'https?://(?!www\.)[^/]+\.[^/]+\.[^/]+/(?=.*@)', link):
            suspicious_links.append(link)
            
        # Check for shortened URLs
        if re.search(r'https?://(?:bit\.ly|tinyurl\.com|goo\.gl|t\.co|is\.gd|cli\.gs|ow\.ly|tr\.im)/\w+', link):
            suspicious_links.append(link)
            
        # Check for misleading domain names
        major_companies = ['paypal', 'amazon', 'apple', 'microsoft', 'netflix', 'google', 'facebook', 'instagram', 'twitter']
        for company in major_companies:
            if company in link.lower() and not re.search(rf'https?://(?:www\.)?{company}\.com', link.lower()):
                suspicious_links.append(link)
                
    return suspicious_links

def get_educational_notes():
    """Get educational notes about phishing emails"""
    return [
        "Phishing emails try to trick you into giving away your personal information or downloading malware.",
        "Real organizations never ask for your password or personal information through email.",
        "Be suspicious of urgent requests or threats in emails.",
        "Check the sender's email address carefully, not just the display name.",
        "Hover over links (without clicking) to see where they really go.",
        "When in doubt, contact the organization directly using their official website or phone number.",
        "Many phishing emails have spelling and grammar mistakes.",
        "Be wary of attachments you weren't expecting, even if they look important."
    ]