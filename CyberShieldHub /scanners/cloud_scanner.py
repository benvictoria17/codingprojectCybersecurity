# Cloud services scanner module for the cybersecurity educational application
import logging
import time
import random
from utils.helpers import format_severity

logger = logging.getLogger(__name__)

def scan_cloud_services(cloud_provider, resource_type):
    """
    Scan cloud services for security vulnerabilities.
    
    Args:
        cloud_provider (str): The cloud provider to scan (aws, azure, gcp, etc.)
        resource_type (str): The type of resource to scan (storage, compute, database, etc.)
        
    Returns:
        dict: Results of the cloud services scan
    """
    logger.debug(f"Starting cloud services scan for {cloud_provider} {resource_type}")
    
    # Initialize results dictionary
    results = {
        "cloud_provider": cloud_provider,
        "resource_type": resource_type,
        "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "findings": [],
        "recommendations": []
    }
    
    # Validate cloud provider
    if cloud_provider.lower() not in ["aws", "azure", "gcp", "digital_ocean"]:
        return {
            "error": f"Unsupported cloud provider: {cloud_provider}. Supported providers are AWS, Azure, GCP, and Digital Ocean."
        }
    
    # Validate resource type
    if resource_type.lower() not in ["storage", "compute", "database", "serverless", "iam"]:
        return {
            "error": f"Unsupported resource type: {resource_type}. Supported types are storage, compute, database, serverless, and iam."
        }
    
    # Perform educational simulated cloud scan
    # This is a simulation for learning purposes only
    
    # Get security checks specific to the provider and resource
    security_checks = get_security_checks(cloud_provider, resource_type)
    
    # Simulate finding issues with some of these checks
    for check in security_checks:
        if random.random() < check["fail_chance"]:
            results["findings"].append({
                "message": check["description"],
                "severity": check["severity"]
            })
    
    # If no issues found, add a positive note
    if not results["findings"]:
        results["findings"].append({
            "message": f"No security issues found for {cloud_provider} {resource_type}",
            "severity": "low"
        })
    
    # Add best practice recommendations
    results["recommendations"] = get_recommendations(cloud_provider, resource_type, results["findings"])
    
    logger.debug(f"Completed cloud services scan for {cloud_provider} {resource_type}")
    return results

def get_security_checks(cloud_provider, resource_type):
    """Get security checks for the specified cloud provider and resource type"""
    # Common checks for all providers
    common_checks = [
        {
            "name": "Encryption",
            "description": "Resource is not encrypted at rest",
            "fail_chance": 0.4,
            "severity": "high"
        },
        {
            "name": "Logging",
            "description": "Logging is not enabled for this resource",
            "fail_chance": 0.5,
            "severity": "medium"
        },
        {
            "name": "Tags",
            "description": "Resource is missing important tags (owner, environment, etc.)",
            "fail_chance": 0.6,
            "severity": "low"
        }
    ]
    
    # Provider-specific checks
    provider_checks = {}
    
    # AWS checks
    provider_checks["aws"] = {
        "storage": [
            {
                "name": "S3 Public Access",
                "description": "S3 bucket allows public access",
                "fail_chance": 0.4,
                "severity": "high"
            },
            {
                "name": "S3 Versioning",
                "description": "S3 bucket versioning is not enabled",
                "fail_chance": 0.5,
                "severity": "medium"
            },
            {
                "name": "S3 Encryption",
                "description": "S3 bucket is not using server-side encryption",
                "fail_chance": 0.3,
                "severity": "high"
            }
        ],
        "compute": [
            {
                "name": "EC2 Security Groups",
                "description": "EC2 instance has overly permissive security groups",
                "fail_chance": 0.4,
                "severity": "high"
            },
            {
                "name": "EC2 Public IP",
                "description": "EC2 instance has public IP address",
                "fail_chance": 0.5,
                "severity": "medium"
            }
        ],
        "database": [
            {
                "name": "RDS Public Access",
                "description": "RDS database is publicly accessible",
                "fail_chance": 0.3,
                "severity": "high"
            },
            {
                "name": "RDS Encryption",
                "description": "RDS database is not encrypted",
                "fail_chance": 0.4,
                "severity": "high"
            }
        ],
        "serverless": [
            {
                "name": "Lambda Permissions",
                "description": "Lambda function has overly permissive IAM role",
                "fail_chance": 0.4,
                "severity": "medium"
            },
            {
                "name": "Lambda Environment Variables",
                "description": "Lambda has sensitive data in environment variables",
                "fail_chance": 0.3,
                "severity": "high"
            }
        ],
        "iam": [
            {
                "name": "IAM Root Access Keys",
                "description": "AWS account has active root access keys",
                "fail_chance": 0.2,
                "severity": "high"
            },
            {
                "name": "IAM MFA",
                "description": "IAM users don't have multi-factor authentication enabled",
                "fail_chance": 0.5,
                "severity": "high"
            }
        ]
    }
    
    # Azure checks
    provider_checks["azure"] = {
        "storage": [
            {
                "name": "Blob Public Access",
                "description": "Azure Storage Account allows public blob access",
                "fail_chance": 0.4,
                "severity": "high"
            },
            {
                "name": "Storage Account Encryption",
                "description": "Storage Account is not using encryption",
                "fail_chance": 0.3,
                "severity": "high"
            }
        ],
        "compute": [
            {
                "name": "VM Network Security Groups",
                "description": "VM has overly permissive network security groups",
                "fail_chance": 0.4,
                "severity": "high"
            }
        ],
        "database": [
            {
                "name": "Azure SQL Firewall",
                "description": "Azure SQL Server allows access from all IP addresses",
                "fail_chance": 0.3,
                "severity": "high"
            }
        ],
        "serverless": [
            {
                "name": "Function App Authentication",
                "description": "Function App does not have authentication enabled",
                "fail_chance": 0.4,
                "severity": "medium"
            }
        ],
        "iam": [
            {
                "name": "Azure AD Admin",
                "description": "Too many Global Administrators in Azure AD",
                "fail_chance": 0.3,
                "severity": "high"
            }
        ]
    }
    
    # GCP checks
    provider_checks["gcp"] = {
        "storage": [
            {
                "name": "GCS Bucket Access",
                "description": "Cloud Storage bucket has public access",
                "fail_chance": 0.4,
                "severity": "high"
            }
        ],
        "compute": [
            {
                "name": "GCE Firewall Rules",
                "description": "Compute Engine instance has overly permissive firewall rules",
                "fail_chance": 0.4,
                "severity": "high"
            }
        ],
        "database": [
            {
                "name": "Cloud SQL Public IP",
                "description": "Cloud SQL instance has public IP address",
                "fail_chance": 0.3,
                "severity": "high"
            }
        ],
        "serverless": [
            {
                "name": "Cloud Functions IAM",
                "description": "Cloud Function has overly permissive IAM policy",
                "fail_chance": 0.4,
                "severity": "medium"
            }
        ],
        "iam": [
            {
                "name": "Service Account Keys",
                "description": "Service account keys are too old",
                "fail_chance": 0.5,
                "severity": "medium"
            }
        ]
    }
    
    # Digital Ocean checks
    provider_checks["digital_ocean"] = {
        "storage": [
            {
                "name": "Spaces Access",
                "description": "Digital Ocean Spaces bucket has public access",
                "fail_chance": 0.4,
                "severity": "high"
            }
        ],
        "compute": [
            {
                "name": "Droplet Firewall",
                "description": "Droplet is not protected by a firewall",
                "fail_chance": 0.4,
                "severity": "high"
            }
        ],
        "database": [
            {
                "name": "Managed Database Access",
                "description": "Managed Database allows access from all sources",
                "fail_chance": 0.3,
                "severity": "high"
            }
        ],
        "serverless": [
            {
                "name": "App Platform Security",
                "description": "App Platform application is not using HTTPS",
                "fail_chance": 0.4,
                "severity": "medium"
            }
        ],
        "iam": [
            {
                "name": "Team Permissions",
                "description": "Too many users with full access to all resources",
                "fail_chance": 0.4,
                "severity": "high"
            }
        ]
    }
    
    # Get the checks for the specified provider and resource type
    resource_checks = []
    
    # Add common checks
    resource_checks.extend(common_checks)
    
    # Add provider-specific checks
    if cloud_provider.lower() in provider_checks:
        if resource_type.lower() in provider_checks[cloud_provider.lower()]:
            resource_checks.extend(provider_checks[cloud_provider.lower()][resource_type.lower()])
    
    return resource_checks

def get_recommendations(cloud_provider, resource_type, findings):
    """Generate recommendations based on findings"""
    recommendations = []
    
    # Common recommendations
    common_recommendations = {
        "storage": [
            "Enable encryption for all storage resources",
            "Regularly audit who has access to your storage",
            "Enable versioning to protect against accidental deletion or changes"
        ],
        "compute": [
            "Use security groups/firewall rules to restrict access",
            "Keep instances updated with security patches",
            "Use private networking when possible"
        ],
        "database": [
            "Restrict database access to necessary IP addresses only",
            "Enable encryption for all databases",
            "Regularly backup your databases"
        ],
        "serverless": [
            "Follow the principle of least privilege for function permissions",
            "Don't store sensitive data in environment variables",
            "Enable monitoring and logging for all serverless functions"
        ],
        "iam": [
            "Enable multi-factor authentication for all users",
            "Follow the principle of least privilege",
            "Regularly audit user permissions and access"
        ]
    }
    
    # Provider-specific recommendations
    provider_recommendations = {
        "aws": {
            "storage": [
                "Enable S3 block public access setting at the account level",
                "Use S3 bucket policies to control access",
                "Enable S3 Object Lock for critical data"
            ],
            "iam": [
                "Don't use the root account for daily tasks",
                "Remove any access keys for the root account",
                "Use AWS Organizations to manage multiple accounts"
            ]
        },
        "azure": {
            "storage": [
                "Enable 'Secure transfer required' for all storage accounts",
                "Use Azure Private Link for secure access to storage"
            ],
            "iam": [
                "Minimize the number of Global Administrator accounts",
                "Use Azure AD Privileged Identity Management for just-in-time access"
            ]
        },
        "gcp": {
            "storage": [
                "Use uniform bucket-level access control",
                "Set appropriate IAM policies for Cloud Storage buckets"
            ],
            "iam": [
                "Rotate service account keys regularly",
                "Use custom roles to implement least privilege"
            ]
        },
        "digital_ocean": {
            "compute": [
                "Add a firewall to all Droplets",
                "Use DigitalOcean VPC for private networking"
            ]
        }
    }
    
    # Add findings-based recommendations
    for finding in findings:
        message = finding["message"].lower()
        
        if "public access" in message or "publicly accessible" in message:
            recommendations.append("Remove public access to your resources")
        
        if "encryption" in message and "not" in message:
            recommendations.append("Enable encryption for your resources")
        
        if "logging" in message and "not" in message:
            recommendations.append("Enable logging to track access and changes")
        
        if "mfa" in message or "multi-factor" in message:
            recommendations.append("Enable multi-factor authentication for all user accounts")
        
        if "permissive" in message:
            recommendations.append("Tighten access controls to follow the principle of least privilege")
    
    # Add common recommendations for the resource type
    if resource_type.lower() in common_recommendations:
        recommendations.extend(common_recommendations[resource_type.lower()])
    
    # Add provider-specific recommendations
    if cloud_provider.lower() in provider_recommendations:
        if resource_type.lower() in provider_recommendations[cloud_provider.lower()]:
            recommendations.extend(provider_recommendations[cloud_provider.lower()][resource_type.lower()])
    
    # Remove duplicates while preserving order
    unique_recommendations = []
    for rec in recommendations:
        if rec not in unique_recommendations:
            unique_recommendations.append(rec)
    
    return unique_recommendations
