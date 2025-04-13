# Password tools module for the cybersecurity educational application
import logging
import random
import string
import time
import re
import json
import hashlib
import requests
from utils.helpers import sanitize_input, format_severity

logger = logging.getLogger(__name__)

# List of common words for passphrase generation
COMMON_WORDS = [
    "apple", "banana", "orange", "grape", "melon", "cherry", "strawberry", 
    "dog", "cat", "bird", "fish", "tiger", "elephant", "dolphin", "shark",
    "blue", "red", "green", "yellow", "purple", "orange", "pink", "black",
    "book", "pencil", "paper", "school", "friend", "family", "house", "tree",
    "water", "fire", "earth", "wind", "star", "moon", "sun", "sky", "cloud",
    "happy", "funny", "smart", "brave", "kind", "strong", "fast", "quiet",
    "mountain", "river", "ocean", "forest", "desert", "island", "beach", "cave"
]

def generate_password(length=12, include_uppercase=True, include_lowercase=True, 
                      include_numbers=True, include_symbols=True):
    """
    Generate a secure random password with specified parameters.
    
    Args:
        length (int): Length of the password (default: 12)
        include_uppercase (bool): Include uppercase letters (default: True)
        include_lowercase (bool): Include lowercase letters (default: True)
        include_numbers (bool): Include numbers (default: True)
        include_symbols (bool): Include special symbols (default: True)
    
    Returns:
        dict: Generated password and password strength information
    """
    logger.debug(f"Generating password with length {length}")
    
    # Validate length
    if length < 8:
        length = 8  # Minimum password length for security
    elif length > 64:
        length = 64  # Maximum reasonable length
        
    # Create character sets based on parameters
    characters = ""
    
    if include_lowercase:
        characters += string.ascii_lowercase
    if include_uppercase:
        characters += string.ascii_uppercase
    if include_numbers:
        characters += string.digits
    if include_symbols:
        characters += string.punctuation
        
    # Ensure at least one character set is selected
    if not characters:
        characters = string.ascii_lowercase  # Default to lowercase if nothing selected
    
    # Generate password
    password = ''.join(random.choice(characters) for _ in range(length))
    
    # Check password strength
    strength = check_password_strength(password)
    
    return {
        "password": password,
        "length": length,
        "strength": strength["strength"],
        "strength_score": strength["score"],
        "feedback": strength["feedback"],
        "generation_time": time.strftime("%Y-%m-%d %H:%M:%S")
    }

def check_password_strength(password):
    """
    Evaluate the strength of a password.
    
    Args:
        password (str): The password to evaluate
        
    Returns:
        dict: Password strength information
    """
    # Initialize score
    score = 0
    feedback = []
    
    # Check length
    if len(password) < 8:
        score -= 2
        feedback.append("Password is too short. It should be at least 8 characters.")
    elif len(password) >= 12:
        score += 2
        feedback.append("Good password length.")
    elif len(password) >= 16:
        score += 3
        feedback.append("Excellent password length.")
    
    # Check for character types
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)
    
    character_types = sum([has_lower, has_upper, has_digit, has_symbol])
    
    if character_types == 4:
        score += 3
        feedback.append("Excellent character variety (lowercase, uppercase, numbers, and symbols).")
    elif character_types == 3:
        score += 2
        feedback.append("Good character variety.")
    elif character_types == 2:
        score += 1
        feedback.append("Moderate character variety.")
    else:
        score -= 1
        feedback.append("Poor character variety. Use a mix of character types.")
    
    # Check for repeating characters
    if re.search(r'(.)\1\1', password):
        score -= 1
        feedback.append("Password contains repeating characters.")
    
    # Check for sequential characters
    if re.search(r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|012|123|234|345|456|567|678|789)', password.lower()):
        score -= 1
        feedback.append("Password contains sequential characters.")
    
    # Check for common words
    for word in COMMON_WORDS:
        if word in password.lower() and len(word) > 3:
            score -= 1
            feedback.append(f"Password contains a common word ('{word}').")
            break
    
    # Determine overall strength
    strength = ""
    if score <= 0:
        strength = "weak"
    elif score <= 2:
        strength = "moderate"
    elif score <= 4:
        strength = "good"
    else:
        strength = "strong"
    
    return {
        "strength": strength,
        "score": score,
        "feedback": feedback
    }

def generate_passphrase(num_words=4, separator="-", capitalize=True, include_number=True):
    """
    Generate a random passphrase using common words.
    
    Args:
        num_words (int): Number of words in the passphrase (default: 4)
        separator (str): Character to separate words (default: "-")
        capitalize (bool): Capitalize the first letter of each word (default: True)
        include_number (bool): Include a random number in the passphrase (default: True)
    
    Returns:
        dict: Generated passphrase and information
    """
    logger.debug(f"Generating passphrase with {num_words} words")
    
    # Validate num_words
    if num_words < 3:
        num_words = 3  # Minimum for security
    elif num_words > 10:
        num_words = 10  # Maximum reasonable length
    
    # Select random words
    words = random.sample(COMMON_WORDS, num_words)
    
    # Apply transformations
    if capitalize:
        words = [word.capitalize() for word in words]
        
    if include_number:
        # Insert a random number at a random position
        position = random.randint(0, len(words))
        number = str(random.randint(1, 999))
        words.insert(position, number)
    
    # Join words with separator
    passphrase = separator.join(words)
    
    # Check passphrase strength
    strength = check_password_strength(passphrase)
    
    return {
        "passphrase": passphrase,
        "num_words": num_words,
        "separator": separator,
        "words": words,
        "strength": strength["strength"],
        "strength_score": strength["score"],
        "feedback": strength["feedback"],
        "generation_time": time.strftime("%Y-%m-%d %H:%M:%S")
    }

def check_leaked_password(password):
    """
    Check if a password has been found in data breaches using the k-anonymity model.
    This uses the "Have I Been Pwned" API without sending the full password.
    
    Args:
        password (str): The password to check
        
    Returns:
        dict: Information about whether the password appeared in known data breaches
    """
    logger.debug("Checking if password has been leaked")
    
    # Hash the password with SHA-1
    password_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = password_hash[:5]
    suffix = password_hash[5:]
    
    try:
        # Send only the first 5 characters of the hash to the API
        response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
        if response.status_code != 200:
            return {
                "error": f"Couldn't check if password has been leaked. API returned status code {response.status_code}."
            }
        
        # Check if the suffix is in the response
        hashes = (line.split(':') for line in response.text.splitlines())
        count = next((int(count) for hash_suffix, count in hashes if hash_suffix == suffix), 0)
        
        if count > 0:
            return {
                "is_leaked": True,
                "breach_count": count,
                "message": f"This password has been found in {count} data breaches. Do not use it!",
                "severity": format_severity("high")
            }
        else:
            return {
                "is_leaked": False,
                "breach_count": 0,
                "message": "Good news! This password hasn't been found in any known data breaches.",
                "severity": format_severity("low")
            }
            
    except Exception as e:
        logger.error(f"Error checking leaked password: {str(e)}")
        return {
            "error": "Couldn't check if password has been leaked due to an error.",
            "details": str(e)
        }

def check_leaked_email(email):
    """
    Check if an email has appeared in known data breaches.
    This is a simulation for educational purposes.
    
    Args:
        email (str): The email to check
        
    Returns:
        dict: Information about potential email leaks
    """
    logger.debug(f"Checking if email has been leaked: {email}")
    
    # Sanitize input
    email = sanitize_input(email)
    
    # Validate email format (basic check)
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return {
            "error": "Please enter a valid email address."
        }
    
    # Simulate a random result for educational purposes
    # In a real app, you would call a service like HaveIBeenPwned API
    breach_count = random.randint(0, 5)
    
    if breach_count > 0:
        # Generate some fake breach sites for educational purposes
        breaches = []
        possible_breaches = [
            {
                "name": "ExampleSite",
                "breach_date": "2020-01-15",
                "data_types": ["Email", "Password", "Username"]
            },
            {
                "name": "FakeShop",
                "breach_date": "2021-05-22",
                "data_types": ["Email", "Password", "Name", "Phone"]
            },
            {
                "name": "SocialMediaX",
                "breach_date": "2019-11-03",
                "data_types": ["Email", "Password Hash", "Profile Info"]
            },
            {
                "name": "GamerPortal",
                "breach_date": "2022-02-14",
                "data_types": ["Email", "Username", "Password"]
            },
            {
                "name": "OnlineForumA",
                "breach_date": "2018-07-30",
                "data_types": ["Email", "Password Hash", "IP Address"]
            }
        ]
        
        # Select random breaches
        breaches = random.sample(possible_breaches, min(breach_count, len(possible_breaches)))
        
        return {
            "is_leaked": True,
            "breach_count": breach_count,
            "breaches": breaches,
            "message": f"This email was found in {breach_count} data breaches. Consider changing your passwords.",
            "severity": format_severity("high" if breach_count > 1 else "medium")
        }
    else:
        return {
            "is_leaked": False,
            "breach_count": 0,
            "message": "Good news! This email hasn't been found in any known data breaches.",
            "severity": format_severity("low")
        }

def check_password_breach_database(password_hash_prefix):
    """
    Simulate checking a password hash prefix against a breach database.
    This is for educational demonstrations of how password breach checking works.
    
    Args:
        password_hash_prefix (str): First 5 characters of a SHA-1 password hash
        
    Returns:
        dict: Simulated database response with hash suffixes and counts
    """
    # This is a simulated response that mimics the HaveIBeenPwned API format
    # In reality, this would come from a real API call
    
    # Generate some random hash suffixes and counts
    hash_entries = []
    for _ in range(random.randint(10, 30)):
        # Generate a random hash suffix (35 characters to complete the 40-char SHA-1 hash)
        hash_suffix = ''.join(random.choices(string.hexdigits.upper(), k=35))
        # Random count of how many times this hash appeared in breaches
        count = random.randint(1, 50000)
        hash_entries.append((hash_suffix, count))
    
    # Format the response like the HaveIBeenPwned API
    response_lines = [f"{suffix}:{count}" for suffix, count in hash_entries]
    
    return {
        "prefix": password_hash_prefix,
        "hash_entries": hash_entries,
        "response": "\n".join(response_lines)
    }

def get_educational_notes():
    """Get educational notes about password security"""
    return [
        "A strong password is long and complex, with different types of characters.",
        "Never reuse passwords across different websites or services.",
        "Consider using a password manager to create and store unique passwords.",
        "Two-factor authentication adds an extra layer of security beyond your password.",
        "Checking if your password has been leaked is done securely using only part of the password hash.",
        "Passphrases (multiple words together) can be easier to remember and more secure than complex passwords.",
        "Change your passwords regularly, especially for important accounts.",
        "Be careful about where and how you share your password information."
    ]