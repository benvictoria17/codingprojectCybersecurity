# Kali Linux tools module for the cybersecurity educational application
# This is a simplified, educational version of Kali Linux tools for children
import logging
import time
import random
from utils.helpers import format_severity, sanitize_input

logger = logging.getLogger(__name__)

def get_kali_tool_info(tool_category, tool_name=None):
    """
    Get information about Kali Linux tools.
    
    Args:
        tool_category (str): Category of tools (information_gathering, vulnerability_analysis, etc.)
        tool_name (str, optional): Name of a specific tool
        
    Returns:
        dict: Information about the requested tools
    """
    logger.debug(f"Getting info for Kali tools in category: {tool_category}, tool: {tool_name}")
    
    # Sanitize inputs
    tool_category = sanitize_input(tool_category)
    if tool_name:
        tool_name = sanitize_input(tool_name)
    
    # Initialize results
    results = {
        "category": tool_category,
        "tool_name": tool_name,
        "search_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "tools": [],
        "educational_notes": []
    }
    
    # Validate tool category
    valid_categories = [
        "information_gathering", 
        "vulnerability_analysis", 
        "web_application_analysis",
        "database_assessment",
        "password_attacks", 
        "wireless_attacks",
        "reverse_engineering",
        "exploitation_tools",
        "sniffing_spoofing",
        "post_exploitation",
        "forensics",
        "reporting_tools",
        "social_engineering"
    ]
    
    if tool_category.lower() not in valid_categories:
        return {
            "error": f"Invalid tool category: {tool_category}. Supported categories are: {', '.join(valid_categories)}"
        }
    
    # Get all tools in the category or a specific tool
    tools_data = get_tools_data(tool_category)
    
    if tool_name:
        # Filter to a specific tool if requested
        tools_data = [tool for tool in tools_data if tool["name"].lower() == tool_name.lower()]
        if not tools_data:
            return {
                "error": f"Tool '{tool_name}' not found in category '{tool_category}'"
            }
    
    results["tools"] = tools_data
    results["educational_notes"] = get_educational_notes(tool_category)
    
    logger.debug(f"Completed gathering Kali tools info for category: {tool_category}")
    return results

def get_tools_data(category):
    """Get data for all tools in a category"""
    tools_by_category = {
        "information_gathering": [
            {
                "name": "Nmap",
                "description": "Nmap is like a map explorer for computer networks. It helps you see what computers are turned on and what doors (ports) are open on them.",
                "kid_friendly_explanation": "Imagine you're exploring a neighborhood. Nmap is like walking around and checking which houses have their lights on and which doors are unlocked. This helps you know which computers are active and what they might be doing.",
                "example_command": "nmap -sV 192.168.1.1",
                "difficulty": "medium",
                "image_url": "/static/images/tools/nmap.png"
            },
            {
                "name": "Recon-ng",
                "description": "Recon-ng helps find information about websites and companies that is available online.",
                "kid_friendly_explanation": "This is like being a detective who searches the internet for clues about a website or company. It helps find information that anyone can see online.",
                "example_command": "recon-ng",
                "difficulty": "hard",
                "image_url": "/static/images/tools/recon-ng.png"
            },
            {
                "name": "Shodan",
                "description": "Shodan is a search engine that can find devices connected to the internet.",
                "kid_friendly_explanation": "Imagine a special magnifying glass that can find things connected to the internet, like cameras, routers, or servers. Shodan helps security people find devices that might not be protected well.",
                "example_command": "Using the Shodan website",
                "difficulty": "medium",
                "image_url": "/static/images/tools/shodan.png"
            },
            {
                "name": "TheHarvester",
                "description": "TheHarvester collects email addresses, names, and other information from public sources.",
                "kid_friendly_explanation": "This tool is like a collector that finds email addresses and other information about a company or website that's publicly available online. It's like finding business cards that were dropped in public.",
                "example_command": "theHarvester -d example.com -b google",
                "difficulty": "easy",
                "image_url": "/static/images/tools/theharvester.png"
            }
        ],
        "vulnerability_analysis": [
            {
                "name": "OpenVAS",
                "description": "OpenVAS checks computers and networks for security problems.",
                "kid_friendly_explanation": "OpenVAS is like a security inspector that checks your computer or network for places where bad guys might get in. It helps find problems so you can fix them before anyone else finds them.",
                "example_command": "Using the OpenVAS web interface",
                "difficulty": "hard",
                "image_url": "/static/images/tools/openvas.png"
            },
            {
                "name": "Nikto",
                "description": "Nikto checks websites for common security issues.",
                "kid_friendly_explanation": "Nikto is like a security guard that checks a website for common mistakes. It looks for doors that might be unlocked or alarms that aren't working right.",
                "example_command": "nikto -h example.com",
                "difficulty": "medium",
                "image_url": "/static/images/tools/nikto.png"
            }
        ],
        "web_application_analysis": [
            {
                "name": "Burp Suite",
                "description": "Burp Suite helps test website security by examining and changing the messages between your browser and the website.",
                "kid_friendly_explanation": "Imagine you could see and change the messages between your web browser and a website. Burp Suite is like having a magnifying glass and a pencil to look at these messages and change them to test if a website is secure.",
                "example_command": "Using the Burp Suite application",
                "difficulty": "hard",
                "image_url": "/static/images/tools/burpsuite.png"
            },
            {
                "name": "OWASP ZAP",
                "description": "OWASP ZAP finds security problems in websites automatically.",
                "kid_friendly_explanation": "OWASP ZAP is like a robot inspector that checks websites for security problems. It can find places where websites might be weak and need extra protection.",
                "example_command": "Using the ZAP application",
                "difficulty": "medium",
                "image_url": "/static/images/tools/owaspzap.png"
            },
            {
                "name": "SQLmap",
                "description": "SQLmap tests if websites have a problem called SQL injection that could let attackers access the website's data.",
                "kid_friendly_explanation": "SQLmap is like trying keys in a lock to see if any work. It checks if a website accidentally accepts commands that could let someone see information they shouldn't.",
                "example_command": "sqlmap -u \"http://example.com/page.php?id=1\"",
                "difficulty": "hard",
                "image_url": "/static/images/tools/sqlmap.png"
            }
        ],
        "database_assessment": [
            {
                "name": "SQLmap",
                "description": "SQLmap tests databases connected to websites for security problems.",
                "kid_friendly_explanation": "SQLmap checks if the storage rooms (databases) behind websites are locked properly. It tries to find doors that might be left open by mistake.",
                "example_command": "sqlmap -u \"http://example.com/page.php?id=1\" --dbs",
                "difficulty": "hard",
                "image_url": "/static/images/tools/sqlmap.png"
            }
        ],
        "password_attacks": [
            {
                "name": "John the Ripper",
                "description": "John the Ripper tries to figure out passwords by testing many possible combinations.",
                "kid_friendly_explanation": "This tool is like a locksmith that tries many different keys to see which one opens a lock. It helps security experts test if passwords are strong enough to keep bad guys out.",
                "example_command": "john --wordlist=passwords.txt hashes.txt",
                "difficulty": "medium",
                "image_url": "/static/images/tools/john.png"
            },
            {
                "name": "Hashcat",
                "description": "Hashcat is a very fast tool for cracking password hashes using graphics cards.",
                "kid_friendly_explanation": "Hashcat is like a super-fast robot that can try billions of keys per second to open a lock. Security people use it to test if passwords are strong enough.",
                "example_command": "hashcat -m 0 -a 0 hashes.txt wordlist.txt",
                "difficulty": "hard",
                "image_url": "/static/images/tools/hashcat.png"
            }
        ],
        "wireless_attacks": [
            {
                "name": "Aircrack-ng",
                "description": "Aircrack-ng is a set of tools for testing WiFi network security.",
                "kid_friendly_explanation": "Aircrack-ng is like a set of tools that test if your home WiFi is secure. It can check if someone could break into your WiFi network and help you make it stronger.",
                "example_command": "aircrack-ng capture-01.cap -w wordlist.txt",
                "difficulty": "hard",
                "image_url": "/static/images/tools/aircrack.png"
            },
            {
                "name": "Wifite",
                "description": "Wifite automatically tests multiple WiFi networks for common security problems.",
                "kid_friendly_explanation": "Wifite is like a security guard that checks many WiFi networks quickly to see if any have easy-to-break locks. Security experts use it to find and fix weak WiFi networks.",
                "example_command": "wifite",
                "difficulty": "medium",
                "image_url": "/static/images/tools/wifite.png"
            }
        ],
        "reverse_engineering": [
            {
                "name": "Ghidra",
                "description": "Ghidra helps security researchers look inside computer programs to understand how they work.",
                "kid_friendly_explanation": "Imagine taking apart a toy to see how it works inside. Ghidra lets security experts take apart computer programs to see what they're doing and if they're safe.",
                "example_command": "Using the Ghidra application",
                "difficulty": "very hard",
                "image_url": "/static/images/tools/ghidra.png"
            }
        ],
        "exploitation_tools": [
            {
                "name": "Metasploit",
                "description": "Metasploit helps security professionals test systems by simulating attacks in a controlled way.",
                "kid_friendly_explanation": "Metasploit is like a training system for security guards. It helps them practice defending against bad guys by safely simulating attacks in a controlled environment.",
                "example_command": "msfconsole",
                "difficulty": "very hard",
                "image_url": "/static/images/tools/metasploit.png"
            }
        ],
        "sniffing_spoofing": [
            {
                "name": "Wireshark",
                "description": "Wireshark lets you see the messages being sent between computers on a network.",
                "kid_friendly_explanation": "Wireshark is like special glasses that let you see the messages computers are sending to each other. Security experts use it to find problems or unusual activity on networks.",
                "example_command": "Using the Wireshark application",
                "difficulty": "hard",
                "image_url": "/static/images/tools/wireshark.png"
            },
            {
                "name": "Ettercap",
                "description": "Ettercap can analyze network traffic and perform network security tests.",
                "kid_friendly_explanation": "Ettercap is like a traffic camera for computer networks. It watches the messages going back and forth and can help security experts find suspicious activity.",
                "example_command": "ettercap -G",
                "difficulty": "hard",
                "image_url": "/static/images/tools/ettercap.png"
            }
        ],
        "post_exploitation": [
            {
                "name": "Mimikatz",
                "description": "Mimikatz can extract passwords from Windows computers for security testing.",
                "kid_friendly_explanation": "Mimikatz is like a detective that can find passwords hidden inside a Windows computer. Security experts use it to test if passwords are being stored safely.",
                "example_command": "mimikatz # sekurlsa::logonpasswords",
                "difficulty": "very hard",
                "image_url": "/static/images/tools/mimikatz.png"
            }
        ],
        "forensics": [
            {
                "name": "Autopsy",
                "description": "Autopsy helps investigators examine computer disks and recover deleted files.",
                "kid_friendly_explanation": "Autopsy is like a digital detective kit. It helps find clues on computers, even if someone tried to erase them. It can recover deleted pictures, documents, and other files.",
                "example_command": "Using the Autopsy application",
                "difficulty": "hard",
                "image_url": "/static/images/tools/autopsy.png"
            },
            {
                "name": "Volatility",
                "description": "Volatility analyzes computer memory to find evidence of attacks or malware.",
                "kid_friendly_explanation": "Volatility looks at what a computer was thinking about (its memory) before it was turned off. This can help find bad programs or hackers that were active on the computer.",
                "example_command": "volatility -f memory.dmp imageinfo",
                "difficulty": "very hard",
                "image_url": "/static/images/tools/volatility.png"
            }
        ],
        "reporting_tools": [
            {
                "name": "Dradis",
                "description": "Dradis helps security teams organize and report on security tests.",
                "kid_friendly_explanation": "Dradis is like a notebook that helps security teams keep track of all the problems they find and make reports to help fix them.",
                "example_command": "Using the Dradis web interface",
                "difficulty": "medium",
                "image_url": "/static/images/tools/dradis.png"
            }
        ],
        "social_engineering": [
            {
                "name": "Social-Engineer Toolkit (SET)",
                "description": "SET helps test how well people in an organization follow security rules.",
                "kid_friendly_explanation": "SET helps test if people can spot tricks like fake emails or websites. It's like a training tool that teaches people not to be fooled by bad guys online.",
                "example_command": "setoolkit",
                "difficulty": "hard",
                "image_url": "/static/images/tools/set.png"
            }
        ]
    }
    
    return tools_by_category.get(category.lower(), [])

def get_educational_notes(category):
    """Get educational notes for each tool category"""
    notes = {
        "information_gathering": [
            "Information gathering tools help you find what's connected to a network.",
            "These tools are like detectives that look for clues about computers and networks.",
            "Security experts use these tools to find what needs to be protected.",
            "Always get permission before scanning networks you don't own."
        ],
        "vulnerability_analysis": [
            "Vulnerability analysis tools look for security problems in systems.",
            "They help find weaknesses before bad guys do.",
            "Regular scanning helps keep systems safe.",
            "These tools should only be used on systems you have permission to test."
        ],
        "web_application_analysis": [
            "Web application tools check if websites are secure.",
            "They look for common mistakes that could let attackers in.",
            "Websites need regular security checks to stay safe.",
            "Never test websites without permission from the owner."
        ],
        "database_assessment": [
            "Database tools check if the places where websites store information are secure.",
            "They help find problems that could let attackers see or change important data.",
            "Databases need special protection because they hold valuable information.",
            "Always get permission before testing someone else's database."
        ],
        "password_attacks": [
            "Password tools help test if passwords are strong enough.",
            "Weak passwords are like easy-to-pick locks for your accounts.",
            "These tools show why you need to use strong, unique passwords.",
            "Only use these tools to test your own passwords or with permission."
        ],
        "wireless_attacks": [
            "Wireless tools test if WiFi networks are secure.",
            "They help find if someone could break into your WiFi.",
            "Always secure your own WiFi with a strong password.",
            "Only test WiFi networks you own or have permission to check."
        ],
        "reverse_engineering": [
            "Reverse engineering tools help look inside programs to see how they work.",
            "Security researchers use them to check if programs are safe.",
            "These tools require a lot of special knowledge to use.",
            "Always respect copyright laws when examining software."
        ],
        "exploitation_tools": [
            "Exploitation tools test security by safely simulating attacks.",
            "They're used by security professionals to find and fix problems.",
            "These are advanced tools that require special training.",
            "Never use these tools without proper permission and training."
        ],
        "sniffing_spoofing": [
            "Sniffing tools let you see messages being sent between computers.",
            "They help find unusual activity on networks.",
            "Network administrators use them to solve problems.",
            "Only use these tools on networks you have permission to monitor."
        ],
        "post_exploitation": [
            "Post-exploitation tools test what happens after a system is compromised.",
            "They help organizations understand security risks.",
            "These are advanced tools for security professionals only.",
            "Never use these tools without proper authorization and training."
        ],
        "forensics": [
            "Forensic tools help investigate computer security incidents.",
            "They can recover deleted files and find evidence of attacks.",
            "Digital detectives use these tools to solve computer crimes.",
            "These tools require special training to use properly."
        ],
        "reporting_tools": [
            "Reporting tools help organize and share security findings.",
            "They make it easier to understand and fix security problems.",
            "Good reports help organizations improve their security.",
            "Clear communication is an important part of security work."
        ],
        "social_engineering": [
            "Social engineering tools test if people can recognize online tricks.",
            "They help train people to spot fake emails and websites.",
            "The human side of security is just as important as technical security.",
            "Always get proper permission before testing people's security awareness."
        ]
    }
    
    return notes.get(category.lower(), ["No specific educational notes for this category."])

def run_simulated_kali_tool(tool_name, target, options=None):
    """
    Run a simulated Kali Linux tool for educational purposes.
    
    Args:
        tool_name (str): The name of the tool to simulate
        target (str): The target to scan or analyze
        options (dict, optional): Additional options for the tool
        
    Returns:
        dict: Simulated results of running the tool
    """
    logger.debug(f"Running simulated Kali tool: {tool_name} on target: {target}")
    
    # Sanitize inputs
    tool_name = sanitize_input(tool_name)
    target = sanitize_input(target)
    
    # Initialize results
    results = {
        "tool": tool_name,
        "target": target,
        "options": options or {},
        "run_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "output": [],
        "findings": [],
        "educational_notes": []
    }
    
    # Get simulated tool output
    tool_output = get_simulated_tool_output(tool_name, target, options)
    if "error" in tool_output:
        return tool_output
    
    results.update(tool_output)
    
    logger.debug(f"Completed simulated run of {tool_name}")
    return results

def get_simulated_tool_output(tool_name, target, options=None):
    """Get simulated output for a specific tool"""
    tool_name = tool_name.lower()
    options = options or {}
    
    # Define outputs for each supported tool
    if tool_name == "nmap":
        return simulate_nmap(target, options)
    elif tool_name == "nikto":
        return simulate_nikto(target, options)
    elif tool_name == "sqlmap":
        return simulate_sqlmap(target, options)
    elif tool_name == "wireshark":
        return {"error": "Wireshark is a GUI application and cannot be simulated in this text-based interface."}
    elif tool_name == "john the ripper" or tool_name == "john":
        return simulate_john(target, options)
    elif tool_name == "aircrack-ng":
        return simulate_aircrack(target, options)
    else:
        return {
            "error": f"Tool '{tool_name}' simulation is not available. Try one of: nmap, nikto, sqlmap, john, aircrack-ng"
        }

def simulate_nmap(target, options):
    """Simulate an Nmap scan"""
    # Check if target looks like an IP or domain
    if not (is_ip_like(target) or is_domain_like(target)):
        return {"error": "Target should be an IP address (like 192.168.1.1) or a domain name (like example.com)"}
    
    # Generate random open ports
    open_ports = random.sample(range(1, 1001), random.randint(3, 8))
    open_ports.sort()
    
    # Common services for demonstration
    services = {
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        443: "HTTPS",
        21: "FTP",
        110: "POP3",
        143: "IMAP",
        3306: "MySQL",
        5432: "PostgreSQL",
        8080: "HTTP-Proxy"
    }
    
    # Generate output lines
    output_lines = [
        f"Starting Nmap scan on host {target}",
        "Scanning for open ports...",
        f"Found {len(open_ports)} open ports"
    ]
    
    findings = []
    for port in open_ports:
        service = services.get(port, "unknown")
        output_lines.append(f"Port {port}/tcp open - {service}")
        
        # Add to findings with severity based on the service
        severity = "low"
        if port in [22, 23, 3306, 5432]:  # More sensitive services
            severity = "medium"
        if port == 23:  # Telnet is insecure
            severity = "high"
            
        findings.append({
            "severity": format_severity(severity),
            "title": f"Open Port: {port} ({service})",
            "description": f"Port {port} is open and running {service}.",
            "recommendation": f"Verify if {service} on port {port} needs to be publicly accessible. If not, restrict access using a firewall."
        })
    
    return {
        "output": output_lines,
        "findings": findings,
        "educational_notes": [
            "Nmap is a tool that helps find open ports (doorways) on computers.",
            "Open ports can be both good and bad. We need some open for services to work.",
            "Security experts check open ports to make sure only the right ones are open.",
            "Securing ports with firewalls helps protect computers from attackers."
        ]
    }

def simulate_nikto(target, options):
    """Simulate a Nikto web vulnerability scan"""
    # Check if target looks like a URL, domain or IP
    if not (is_url_like(target) or is_domain_like(target) or is_ip_like(target)):
        return {"error": "Target should be a URL (like http://example.com) or a domain/IP"}
    
    # Add http:// if it's just a domain or IP
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target
    
    # Generate output lines
    output_lines = [
        f"Starting Nikto scan on {target}",
        "Checking web server...",
        "Scanning for vulnerabilities..."
    ]
    
    # Random findings based on common web vulnerabilities
    possible_findings = [
        {
            "severity": format_severity("low"),
            "title": "Server Information Disclosure",
            "description": "The web server is revealing its version information in headers.",
            "recommendation": "Configure the web server to hide version information."
        },
        {
            "severity": format_severity("medium"),
            "title": "Missing Security Headers",
            "description": "The website is missing important security headers like Content-Security-Policy.",
            "recommendation": "Add recommended security headers to protect against common web attacks."
        },
        {
            "severity": format_severity("low"),
            "title": "Directory Listing Enabled",
            "description": "Some directories on the server allow users to see all files in them.",
            "recommendation": "Disable directory listing in your web server configuration."
        },
        {
            "severity": format_severity("high"),
            "title": "Outdated Web Server",
            "description": "The web server appears to be running an old version with known security issues.",
            "recommendation": "Update the web server to the latest secure version."
        },
        {
            "severity": format_severity("medium"),
            "title": "Form Without CSRF Protection",
            "description": "Forms on the website don't have protection against Cross-Site Request Forgery.",
            "recommendation": "Add CSRF tokens to all forms to prevent attackers from tricking users."
        }
    ]
    
    # Select random findings
    num_findings = random.randint(2, 4)
    findings = random.sample(possible_findings, num_findings)
    
    # Add findings to output
    for finding in findings:
        output_lines.append(f"ALERT: {finding['title']}")
    
    output_lines.append(f"Scan completed with {len(findings)} potential issues found")
    
    return {
        "output": output_lines,
        "findings": findings,
        "educational_notes": [
            "Nikto checks websites for common security problems.",
            "It looks for outdated software, misconfiguration, and other issues.",
            "Regular scanning helps find problems before attackers do.",
            "Not all findings are serious - they need to be checked by experts."
        ]
    }

def simulate_sqlmap(target, options):
    """Simulate a SQLMap injection test"""
    # Check if target looks like a URL with parameters
    if not is_url_like(target) or "?" not in target:
        return {"error": "Target should be a URL with parameters (like http://example.com/page.php?id=1)"}
    
    # Generate output lines
    output_lines = [
        f"Starting SQLMap scan on {target}",
        "Testing for SQL injection...",
        "Analyzing parameters..."
    ]
    
    # Randomly decide if SQL injection is found
    injection_found = random.choice([True, False])
    
    findings = []
    if injection_found:
        # Identify the vulnerable parameter
        param_name = target.split("?")[1].split("=")[0]
        
        output_lines.append(f"[!] SQL injection vulnerability found in parameter '{param_name}'")
        output_lines.append("Testing injection techniques...")
        output_lines.append("Successfully retrieved database version")
        
        findings.append({
            "severity": format_severity("high"),
            "title": f"SQL Injection in parameter '{param_name}'",
            "description": f"The parameter '{param_name}' is vulnerable to SQL injection, which could allow an attacker to access or modify database data.",
            "recommendation": "Use prepared statements or parameterized queries instead of building SQL queries with user input."
        })
    else:
        output_lines.append("No SQL injection vulnerabilities found")
    
    return {
        "output": output_lines,
        "findings": findings,
        "educational_notes": [
            "SQL injection is when websites accept database commands from users by accident.",
            "This can let attackers see or change information they shouldn't have access to.",
            "Developers can prevent SQL injection by carefully handling user input.",
            "SQLMap helps find these problems so they can be fixed."
        ]
    }

def simulate_john(target, options):
    """Simulate John the Ripper password cracking"""
    # Check if target looks like a filename for passwords
    if "." not in target:
        return {"error": "Target should be a filename containing password hashes (like passwords.txt)"}
    
    # Generate output lines
    output_lines = [
        f"Starting John the Ripper on {target}",
        "Loading password hashes...",
        "Starting dictionary attack..."
    ]
    
    # Simulate some passwords being cracked
    num_passwords = random.randint(1, 5)
    cracked_passwords = []
    
    common_passwords = [
        "password123", "welcome1", "qwerty", "123456", "football",
        "baseball", "sunshine", "princess", "dragon", "admin123"
    ]
    
    usernames = [
        "admin", "user", "john", "jane", "staff",
        "guest", "manager", "support", "system", "test"
    ]
    
    # Generate some random "cracked" passwords
    for i in range(num_passwords):
        username = random.choice(usernames)
        password = random.choice(common_passwords)
        cracked_passwords.append({
            "username": username,
            "password": password
        })
        output_lines.append(f"Cracked: {username}:{password}")
    
    findings = []
    if cracked_passwords:
        findings.append({
            "severity": format_severity("high"),
            "title": f"Weak Passwords Cracked ({len(cracked_passwords)})",
            "description": f"John the Ripper was able to crack {len(cracked_passwords)} passwords using a dictionary attack.",
            "recommendation": "Use stronger passwords with a mix of letters, numbers, and symbols. Implement password complexity requirements."
        })
    
    output_lines.append(f"Finished: {len(cracked_passwords)} passwords cracked")
    
    return {
        "output": output_lines,
        "findings": findings,
        "cracked_passwords": cracked_passwords,
        "educational_notes": [
            "John the Ripper tries to guess passwords using dictionaries and patterns.",
            "Weak passwords can be guessed quickly, even with simple tools.",
            "Strong passwords should be long and include letters, numbers, and symbols.",
            "This tool helps security experts test if passwords are strong enough."
        ]
    }

def simulate_aircrack(target, options):
    """Simulate Aircrack-ng WiFi security testing"""
    # Check if target looks like a capture file
    if not target.endswith(('.cap', '.pcap', '.ivs')):
        return {"error": "Target should be a packet capture file (like capture.cap)"}
    
    # Generate output lines
    output_lines = [
        f"Starting Aircrack-ng on {target}",
        "Reading packets...",
        "Analyzing wireless traffic..."
    ]
    
    # Randomly decide if the network is crackable
    network_cracked = random.choice([True, False])
    
    findings = []
    if network_cracked:
        # Generate fake network details
        network_name = f"WiFi-Network-{random.randint(1, 999)}"
        network_key = "".join(random.choice("0123456789abcdef") for _ in range(10))
        
        output_lines.append(f"KEY FOUND! [ {network_key} ]")
        output_lines.append(f"Network: {network_name}")
        
        findings.append({
            "severity": format_severity("high"),
            "title": "WiFi Password Cracked",
            "description": f"The wireless network '{network_name}' is using a weak password that was cracked.",
            "recommendation": "Use WPA2 or WPA3 encryption with a strong, complex password of at least 12 characters."
        })
    else:
        output_lines.append("No wireless keys found")
    
    return {
        "output": output_lines,
        "findings": findings,
        "educational_notes": [
            "Aircrack-ng tests if WiFi networks can be broken into.",
            "Older WiFi security like WEP can be broken very easily.",
            "WPA2 and WPA3 with strong passwords are much more secure.",
            "This tool helps show why securing your WiFi network is important."
        ]
    }

def is_url_like(text):
    """Check if text looks like a URL"""
    return text.startswith(('http://', 'https://')) or ('.' in text and '/' in text)

def is_domain_like(text):
    """Check if text looks like a domain name"""
    return '.' in text and not is_ip_like(text) and not text.startswith(('http://', 'https://'))

def is_ip_like(text):
    """Check if text looks like an IP address"""
    parts = text.split('.')
    if len(parts) != 4:
        return False
    return all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)