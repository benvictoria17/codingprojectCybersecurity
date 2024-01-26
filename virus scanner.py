# tkinter is a set of tools for creating a window or box on your screen to interact with.
import tkinter as tk

# messagebox and filedialog are parts of tkinter for showing messages and choosing files.
from tkinter import messagebox, filedialog

# requests lets our program communicate with websites and online services.
import requests

# threading allows our program to do multiple tasks at the same time.
import threading

# hashlib is used for creating a unique code for files, serving as a digital fingerprint.
import hashlib

# Here, we define keys and addresses to use the VirusTotal service for checking safety.Replace with your API key
API_KEY = 'ba82a809340dc576dcc6e122fe1e7768cd54993959168998fd425965cf3f1408' 

# This is the base URL for the VirusTotal API.
URL_SCAN_API = 'https://www.virustotal.com/api/v3/urls' 
FILE_SCAN_API = 'https://www.virustotal.com/api/v3/files'
IP_SCAN_API = 'https://www.virustotal.com/api/v3/ip_addresses/'
DOMAIN_SCAN_API = 'https://www.virustotal.com/api/v3/domains/'

# This function computes the SHA-256 hash of a file, a way to uniquely identify it.
def hash_file(file_path):
    BUF_SIZE = 65536  # This is the size of the chunk of the file it reads at a time.
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:  # Opens file in binary mode.
        while True: # This loop reads the file in chunks and updates the hash object.
            data = f.read(BUF_SIZE) # Reads the file in chunks.
            if not data: # If there is no data, it breaks the loop.
                break # Breaks the loop.
            sha256.update(data) # Updates the hash object.
    return sha256.hexdigest() # Returns the hash object as a hexadecimal string.

# These functions use the VirusTotal service to check if an IP, domain, URL, or file is safe.
def scan_ip(ip_address): # This function takes an IP address as input.
    headers = {"x-apikey": API_KEY} # This sets the API key for the request.
    response = requests.get(IP_SCAN_API + ip_address, headers=headers) # This sends a GET request to the VirusTotal API.
    interpret_scan_results(response.json()) # This calls the interpret_scan_results function to interpret the results.

def scan_domain(domain): # This function takes a domain as input.
    headers = {"x-apikey": API_KEY} # This sets the API key for the request.
    response = requests.get(DOMAIN_SCAN_API + domain, headers=headers) # This sends a GET request to the VirusTotal API.
    interpret_scan_results(response.json()) # This calls the interpret_scan_results function to interpret the results.

def scan_url(url): # This function takes a URL as input.
    headers = {"x-apikey": API_KEY} # This sets the API key for the request.
    response = requests.post(URL_SCAN_API, headers=headers, data={"url": url}) # This sends a POST request to the VirusTotal API.
    interpret_scan_results(response.json()) # This calls the interpret_scan_results function to interpret the results.

def scan_file(file_path): # This function takes a file path as input.
    file_hash = hash_file(file_path) # This calls the hash_file function to compute the hash of the file.
    headers = {"x-apikey": API_KEY} # This sets the API key for the request.
    files = {'file': (file_path, open(file_path, 'rb'))} # This creates a dictionary of files to send with the request.
    response = requests.post(FILE_SCAN_API, headers=headers, files=files) # This sends a POST request to the VirusTotal API.
    interpret_scan_results(response.json()) # This calls the interpret_scan_results function to interpret the results.

# After scanning, this function shows a message if the item is safe or not.
def interpret_scan_results(scan_results): # This function takes a dictionary of scan results as input.
    if scan_results.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0) > 0: # This checks if the item is malicious.
        messagebox.showinfo("Scan Result", "Not safe") # This shows a message box saying that the item is not safe.
    else: # If the item is not malicious,
        messagebox.showinfo("Scan Result", "Safe") # This shows a message box saying that the item is safe.

# Lets the user pick a file to scan for safety.
def select_file(): # This function is called when the user clicks the "Select File" button.
    file_path = filedialog.askopenfilename() # This opens a file dialog box to let the user pick a file.
    if file_path:  # Proceeds only if a file was chosen.
        threading.Thread(target=lambda: scan_file(file_path)).start() # This starts a thread to scan the file.

# Sets up the window where you interact with the program.
root = tk.Tk() # This creates the window.
root.title("Virus Scanner") # This sets the title of the window.

# A place to enter URLs, IP addresses, or domains.
input_entry = tk.Entry(root, width=50) # This creates an entry box for the user to enter a URL, IP address, or domain.
input_entry.pack() # This packs the input entry widget into the window.

# Buttons for the different types of scans you can do.
scan_url_button = tk.Button(root, text="Scan URL", command=lambda: threading.Thread(target=lambda: scan_url(input_entry.get())).start()) # This creates a button for scanning a URL.
scan_url_button.pack() # This packs the button into the window.

scan_ip_button = tk.Button(root, text="Scan IP", command=lambda: threading.Thread(target=lambda: scan_ip(input_entry.get())).start()) # This creates a button for scanning an IP address.
scan_ip_button.pack() # This packs the button into the window.

scan_domain_button = tk.Button(root, text="Scan Domain", command=lambda: threading.Thread(target=lambda: scan_domain(input_entry.get())).start()) # This creates a button for scanning a domain.
scan_domain_button.pack() # This packs the button into the window.

select_file_button = tk.Button(root, text="Select File to Scan", command=select_file)# This creates a button for selecting a file to scan.
select_file_button.pack() # This packs the button into the window.

# Begins the application, opening the window for interaction.
root.mainloop() # This starts the application.
