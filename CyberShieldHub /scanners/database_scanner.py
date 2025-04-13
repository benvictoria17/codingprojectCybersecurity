# Database scanner module for the cybersecurity educational application
import logging
import time
import random
from utils.helpers import format_severity

logger = logging.getLogger(__name__)

def scan_database(db_type, host, port=None):
    """
    Scan a database for security vulnerabilities.
    
    Args:
        db_type (str): The type of database (mysql, postgresql, mongodb, etc.)
        host (str): The hostname or IP address of the database server
        port (int, optional): The port the database is running on
        
    Returns:
        dict: Results of the database scan
    """
    logger.debug(f"Starting database scan for {db_type} at {host}:{port}")
    
    # Initialize results dictionary
    results = {
        "db_type": db_type,
        "host": host,
        "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "findings": [],
        "recommendations": []
    }
    
    # Set port if not provided based on database type
    if not port:
        port = get_default_port(db_type)
        results["port"] = port
    else:
        results["port"] = port
    
    # Validate database type
    if db_type.lower() not in ["mysql", "postgresql", "mongodb", "redis", "elasticsearch"]:
        return {
            "error": f"Unsupported database type: {db_type}. Supported types are MySQL, PostgreSQL, MongoDB, Redis, and Elasticsearch."
        }
    
    # Perform educational simulated database scan
    # This is a simulation for learning purposes only
    
    # Check database accessibility
    accessibility = check_database_accessibility(db_type, host, port)
    results["accessible"] = accessibility["accessible"]
    
    if accessibility["accessible"]:
        results["findings"].append({
            "message": f"Database is accessible from your current location ({accessibility['auth_method']})",
            "severity": "medium" if accessibility["auth_method"] != "Strong Authentication" else "low"
        })
    
    # Check common database security issues
    security_checks = perform_security_checks(db_type)
    results["findings"].extend(security_checks)
    
    # Check database version
    version_info = check_database_version(db_type)
    results["version"] = version_info["version"]
    results["findings"].append({
        "message": f"Database version: {version_info['version']} ({version_info['status']})",
        "severity": version_info["severity"]
    })
    
    # Check encryption
    encryption_info = check_encryption(db_type)
    results["findings"].append({
        "message": f"Data encryption: {encryption_info['status']}",
        "severity": encryption_info["severity"]
    })
    
    # Generate recommendations
    results["recommendations"] = generate_recommendations(db_type, accessibility, version_info, security_checks, encryption_info)
    
    logger.debug(f"Completed database scan for {db_type} at {host}:{port}")
    return results

def get_default_port(db_type):
    """Get the default port for a database type"""
    default_ports = {
        "mysql": 3306,
        "postgresql": 5432,
        "mongodb": 27017,
        "redis": 6379,
        "elasticsearch": 9200
    }
    
    return default_ports.get(db_type.lower(), 0)

def check_database_accessibility(db_type, host, port):
    """
    Check if the database is accessible.
    This is a simulation for educational purposes only.
    """
    # In a real scanner, we would attempt to connect to the database
    # and check if it's accessible from the current location
    
    # Simulate different authentication states for educational purposes
    auth_methods = ["No Authentication", "Password Authentication", "Strong Authentication"]
    auth_method = random.choice(auth_methods)
    
    # Is the database accessible?
    # For educational purposes, we'll randomly determine if it's accessible
    accessible = random.choice([True, False])
    
    return {
        "accessible": accessible,
        "auth_method": auth_method
    }

def perform_security_checks(db_type):
    """
    Perform security checks on the database.
    This is a simulation for educational purposes only.
    """
    findings = []
    
    # Common security checks for all database types
    common_checks = [
        {
            "name": "Public exposure",
            "description": "Database is accessible from the internet",
            "fail_chance": 0.3,
            "severity": "high"
        },
        {
            "name": "Weak credentials",
            "description": "Database uses weak or default credentials",
            "fail_chance": 0.4,
            "severity": "high"
        },
        {
            "name": "Outdated database software",
            "description": "Database software is not updated to the latest version",
            "fail_chance": 0.5,
            "severity": "medium"
        },
        {
            "name": "Unnecessary database users",
            "description": "Database has unnecessary user accounts with privileges",
            "fail_chance": 0.4,
            "severity": "medium"
        },
        {
            "name": "Logging configuration",
            "description": "Database logging is not properly configured",
            "fail_chance": 0.6,
            "severity": "low"
        }
    ]
    
    # Database-specific checks
    specific_checks = {}
    
    specific_checks["mysql"] = [
        {
            "name": "MySQL user privileges",
            "description": "Some users have excessive privileges (e.g., GRANT ALL)",
            "fail_chance": 0.4,
            "severity": "high"
        }
    ]
    
    specific_checks["postgresql"] = [
        {
            "name": "PostgreSQL role permissions",
            "description": "Some roles have unnecessary superuser privileges",
            "fail_chance": 0.3,
            "severity": "high"
        }
    ]
    
    specific_checks["mongodb"] = [
        {
            "name": "MongoDB authentication",
            "description": "MongoDB is running without authentication enabled",
            "fail_chance": 0.5,
            "severity": "high"
        }
    ]
    
    specific_checks["redis"] = [
        {
            "name": "Redis password protection",
            "description": "Redis instance is running without password protection",
            "fail_chance": 0.6,
            "severity": "high"
        }
    ]
    
    specific_checks["elasticsearch"] = [
        {
            "name": "Elasticsearch security",
            "description": "Elasticsearch is running without X-Pack security",
            "fail_chance": 0.5,
            "severity": "high"
        }
    ]
    
    # Perform common checks
    for check in common_checks:
        if random.random() < check["fail_chance"]:
            findings.append({
                "message": check["description"],
                "severity": check["severity"]
            })
    
    # Perform database-specific checks
    for check in specific_checks.get(db_type.lower(), []):
        if random.random() < check["fail_chance"]:
            findings.append({
                "message": check["description"],
                "severity": check["severity"]
            })
    
    return findings

def check_database_version(db_type):
    """
    Check if the database version is up to date.
    This is a simulation for educational purposes only.
    """
    # Simulate different database versions
    versions = {
        "mysql": ["5.7.38", "8.0.28", "8.0.31"],
        "postgresql": ["11.16", "13.7", "14.5"],
        "mongodb": ["4.4.14", "5.0.9", "6.0.3"],
        "redis": ["6.0.16", "6.2.7", "7.0.5"],
        "elasticsearch": ["7.10.2", "7.17.7", "8.5.0"]
    }
    
    # Pick a random version for the database type
    db_versions = versions.get(db_type.lower(), ["Unknown"])
    version = random.choice(db_versions)
    
    # Determine if the version is outdated, current, or latest
    index = db_versions.index(version)
    
    if index == 0:
        status = "Outdated"
        severity = "high"
    elif index == 1:
        status = "Slightly outdated"
        severity = "medium"
    else:
        status = "Up to date"
        severity = "low"
    
    return {
        "version": version,
        "status": status,
        "severity": severity
    }

def check_encryption(db_type):
    """
    Check if the database has encryption enabled.
    This is a simulation for educational purposes only.
    """
    # Simulate different encryption states
    encryption_states = [
        {"status": "Not enabled", "severity": "high"},
        {"status": "Partially enabled (transport only)", "severity": "medium"},
        {"status": "Fully enabled (at-rest and in-transit)", "severity": "low"}
    ]
    
    # Pick a random encryption state
    return random.choice(encryption_states)

def generate_recommendations(db_type, accessibility, version_info, security_checks, encryption_info):
    """Generate recommendations based on scan findings"""
    recommendations = []
    
    # Check if database is accessible
    if accessibility["accessible"]:
        if accessibility["auth_method"] == "No Authentication":
            recommendations.append("Enable authentication for your database immediately")
        elif accessibility["auth_method"] == "Password Authentication":
            recommendations.append("Use strong, unique passwords for database access")
        
        recommendations.append("Restrict database access to only necessary IP addresses using a firewall")
    
    # Version recommendations
    if version_info["status"] != "Up to date":
        recommendations.append(f"Update your {db_type} database to the latest version")
    
    # Encryption recommendations
    if encryption_info["status"] != "Fully enabled (at-rest and in-transit)":
        recommendations.append("Enable encryption for your database (both at-rest and in-transit)")
    
    # Add recommendations based on security check findings
    for check in security_checks:
        if "weak credentials" in check["message"].lower():
            recommendations.append("Use strong, unique passwords and avoid default credentials")
        
        if "public exposure" in check["message"].lower():
            recommendations.append("Move your database behind a firewall and restrict access")
        
        if "unnecessary" in check["message"].lower():
            recommendations.append("Remove unnecessary user accounts and minimize privileges")
        
        if "logging" in check["message"].lower():
            recommendations.append("Configure proper logging to track database access and changes")
    
    # Database-specific recommendations
    if db_type.lower() == "mysql":
        recommendations.append("Avoid using 'GRANT ALL' privileges - provide only necessary permissions")
    
    elif db_type.lower() == "postgresql":
        recommendations.append("Limit superuser privileges to only necessary administrative accounts")
    
    elif db_type.lower() == "mongodb":
        recommendations.append("Always enable authentication for MongoDB and use role-based access control")
    
    elif db_type.lower() == "redis":
        recommendations.append("Set a strong Redis password and consider using Redis ACLs")
    
    elif db_type.lower() == "elasticsearch":
        recommendations.append("Enable X-Pack security and use TLS for all communications")
    
    # General recommendations
    if not recommendations:
        recommendations.append("Regularly backup your database")
        recommendations.append("Keep your database software updated")
        recommendations.append("Monitor database access logs for suspicious activity")
    
    return recommendations
