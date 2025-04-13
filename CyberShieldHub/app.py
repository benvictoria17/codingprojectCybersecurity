import os
import logging
import hashlib
from flask import Flask, render_template, request, jsonify, session
import validators

# Import scanner modules
from scanners.osint_scanner import perform_osint_scan
from scanners.website_scanner import scan_website
from scanners.server_scanner import scan_server
from scanners.network_scanner import scan_network
from scanners.database_scanner import scan_database
from scanners.cloud_scanner import scan_cloud_services
from scanners.google_dorking import perform_google_dork
from scanners.kali_tools import get_kali_tool_info, run_simulated_kali_tool
from scanners.password_tools import (generate_password, check_password_strength, 
                                   generate_passphrase, check_leaked_password, 
                                   check_leaked_email)
from scanners.phishing_detector import analyze_email_for_phishing

# Import database models
from models import db, PasswordHistory, LeakCheck, PhishingCheck, ToolUsage

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "cybersecurity-kids-app-secret")

# Routes for main pages
@app.route('/')
def index():
    """Render the home page"""
    return render_template('index.html')

# OSINT Scanner
@app.route('/osint')
def osint():
    """Render the OSINT scanner page"""
    return render_template('osint.html')

@app.route('/api/osint', methods=['POST'])
def api_osint():
    """API endpoint for OSINT scanning"""
    target = request.form.get('target', '')
    if not target:
        return jsonify({'error': 'Please enter a target (name, email, or website)'})
    
    try:
        results = perform_osint_scan(target)
        return jsonify(results)
    except Exception as e:
        logger.error(f"OSINT scan error: {str(e)}")
        return jsonify({'error': f"Sorry, something went wrong: {str(e)}"})

# Website Scanner
@app.route('/website-scanner')
def website_scanner():
    """Render the website scanner page"""
    return render_template('website_scanner.html')

@app.route('/api/scan-website', methods=['POST'])
def api_scan_website():
    """API endpoint for website scanning"""
    url = request.form.get('url', '')
    if not url:
        return jsonify({'error': 'Please enter a website URL'})
    
    if not validators.url(url):
        return jsonify({'error': 'Please enter a valid URL (e.g., https://example.com)'})
    
    try:
        results = scan_website(url)
        return jsonify(results)
    except Exception as e:
        logger.error(f"Website scan error: {str(e)}")
        return jsonify({'error': f"Sorry, something went wrong: {str(e)}"})

# Server Scanner
@app.route('/server-scanner')
def server_scanner():
    """Render the server scanner page"""
    return render_template('server_scanner.html')

@app.route('/api/scan-server', methods=['POST'])
def api_scan_server():
    """API endpoint for server scanning"""
    hostname = request.form.get('hostname', '')
    port = request.form.get('port', '')
    
    if not hostname:
        return jsonify({'error': 'Please enter a server hostname or IP address'})
    
    try:
        if port:
            port = int(port)
        results = scan_server(hostname, port)
        return jsonify(results)
    except ValueError:
        return jsonify({'error': 'Port must be a number'})
    except Exception as e:
        logger.error(f"Server scan error: {str(e)}")
        return jsonify({'error': f"Sorry, something went wrong: {str(e)}"})

# Network Scanner
@app.route('/network-scanner')
def network_scanner():
    """Render the network scanner page"""
    return render_template('network_scanner.html')

@app.route('/api/scan-network', methods=['POST'])
def api_scan_network():
    """API endpoint for network scanning"""
    target = request.form.get('target', '')
    
    if not target:
        return jsonify({'error': 'Please enter a network address (e.g., 192.168.1.0/24)'})
    
    try:
        results = scan_network(target)
        return jsonify(results)
    except Exception as e:
        logger.error(f"Network scan error: {str(e)}")
        return jsonify({'error': f"Sorry, something went wrong: {str(e)}"})

# Database Scanner
@app.route('/database-scanner')
def database_scanner():
    """Render the database scanner page"""
    return render_template('database_scanner.html')

@app.route('/api/scan-database', methods=['POST'])
def api_scan_database():
    """API endpoint for database scanning"""
    db_type = request.form.get('db_type', '')
    host = request.form.get('host', '')
    port = request.form.get('port', '')
    
    if not db_type or not host:
        return jsonify({'error': 'Please enter database type and host'})
    
    try:
        if port:
            port = int(port)
        results = scan_database(db_type, host, port)
        return jsonify(results)
    except ValueError:
        return jsonify({'error': 'Port must be a number'})
    except Exception as e:
        logger.error(f"Database scan error: {str(e)}")
        return jsonify({'error': f"Sorry, something went wrong: {str(e)}"})

# Cloud Services Scanner
@app.route('/cloud-scanner')
def cloud_scanner():
    """Render the cloud services scanner page"""
    return render_template('cloud_scanner.html')

@app.route('/api/scan-cloud', methods=['POST'])
def api_scan_cloud():
    """API endpoint for cloud services scanning"""
    cloud_provider = request.form.get('cloud_provider', '')
    resource_type = request.form.get('resource_type', '')
    
    if not cloud_provider or not resource_type:
        return jsonify({'error': 'Please select a cloud provider and resource type'})
    
    try:
        results = scan_cloud_services(cloud_provider, resource_type)
        return jsonify(results)
    except Exception as e:
        logger.error(f"Cloud scan error: {str(e)}")
        return jsonify({'error': f"Sorry, something went wrong: {str(e)}"})

# Google Dorking Tool
@app.route('/google-dorking')
def google_dorking():
    """Render the Google dorking page"""
    return render_template('google_dorking.html')

@app.route('/api/google-dork', methods=['POST'])
def api_google_dork():
    """API endpoint for Google dorking"""
    dork_type = request.form.get('dork_type', '')
    keyword = request.form.get('keyword', '')
    
    if not dork_type or not keyword:
        return jsonify({'error': 'Please select a dork type and enter a keyword'})
    
    try:
        results = perform_google_dork(dork_type, keyword)
        return jsonify(results)
    except Exception as e:
        logger.error(f"Google dorking error: {str(e)}")
        return jsonify({'error': f"Sorry, something went wrong: {str(e)}"})

# Educational Content
@app.route('/education')
def education():
    """Render the main education page"""
    return render_template('education.html')

@app.route('/education/phishing')
def education_phishing():
    """Render the phishing education page"""
    return render_template('education_phishing.html')

@app.route('/education/passwords')
def education_passwords():
    """Render the password security education page"""
    return render_template('education_passwords.html')

@app.route('/education/exposed-apis')
def education_exposed_apis():
    """Render the exposed APIs education page"""
    return render_template('education_exposed_apis.html')

@app.route('/education/s3-configs')
def education_s3_configs():
    """Render the S3 bucket configuration education page"""
    return render_template('education_s3_configs.html')

# Kali Linux Tools
@app.route('/kali-tools')
def kali_tools():
    """Render the Kali Linux tools page"""
    return render_template('kali_tools.html')

@app.route('/api/kali-tools', methods=['GET'])
def api_kali_tools_info():
    """API endpoint for getting information about Kali Linux tools"""
    tool_category = request.args.get('category', '')
    tool_name = request.args.get('tool_name', '')
    
    if not tool_category:
        return jsonify({'error': 'Please select a tool category'})
    
    try:
        results = get_kali_tool_info(tool_category, tool_name)
        return jsonify(results)
    except Exception as e:
        logger.error(f"Kali tools info error: {str(e)}")
        return jsonify({'error': f"Sorry, something went wrong: {str(e)}"})

@app.route('/api/run-kali-tool', methods=['POST'])
def api_run_kali_tool():
    """API endpoint for running a simulated Kali Linux tool"""
    tool_name = request.form.get('tool_name', '')
    target = request.form.get('target', '')
    options = request.form.get('options', '{}')
    
    if not tool_name or not target:
        return jsonify({'error': 'Please provide tool name and target'})
    
    try:
        # Parse options if provided
        if options:
            import json
            options = json.loads(options)
        else:
            options = {}
            
        results = run_simulated_kali_tool(tool_name, target, options)
        return jsonify(results)
    except Exception as e:
        logger.error(f"Run Kali tool error: {str(e)}")
        return jsonify({'error': f"Sorry, something went wrong: {str(e)}"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
