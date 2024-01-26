# Importing necessary libraries and modules for creating the GUI, making HTTP requests, threading, and hashing files.
import tkinter as tk
from tkinter import messagebox, filedialog
import requests
import threading
import hashlib

# Defining API keys and endpoints for using the VirusTotal service.
API_KEY = 'ba82a809340dc576dcc6e122fe1e7768cd54993959168998fd425965cf3f1408'
URL_SCAN_API = 'https://www.virustotal.com/api/v3/urls'
FILE_SCAN_API = 'https://www.virustotal.com/api/v3/files'
IP_SCAN_API = 'https://www.virustotal.com/api/v3/ip_addresses/'
DOMAIN_SCAN_API = 'https://www.virustotal.com/api/v3/domains/'
FILE_HASH_API = 'https://www.virustotal.com/api/v3/files'  

# Function to compute the SHA-256 hash of a file.
def hash_file(file_path):
    BUF_SIZE = 65536  # Reading file in chunks of this size.
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:  # Opening file in binary mode.
        while True:
            data = f.read(BUF_SIZE)  # Reading a chunk of the file.
            if not data:  # If no more data, stop reading.
                break
            sha256.update(data)  # Updating the hash with the chunk.
    return sha256.hexdigest()  # Returning the hexadecimal digest of the hash.

# Functions to scan an IP, domain, URL, or file using VirusTotal.
def scan_ip(ip_address):
    if not ip_address:  # Check if the input is empty.
        messagebox.showwarning("Warning", "Please enter an IP address.")
        return
    headers = {"x-apikey": API_KEY}
    response = requests.get(IP_SCAN_API + ip_address, headers=headers)
    interpret_scan_results(response.json())

def scan_domain(domain):
    if not domain:  # Check if the input is empty.
        messagebox.showwarning("Warning", "Please enter a domain.")
        return
    headers = {"x-apikey": API_KEY}
    response = requests.get(DOMAIN_SCAN_API + domain, headers=headers)
    interpret_scan_results(response.json())

def scan_url(url):
    if not url:  # Check if the input is empty.
        messagebox.showwarning("Warning", "Please enter a URL.")
        return
    headers = {"x-apikey": API_KEY}
    response = requests.post(URL_SCAN_API, headers=headers, data={"url": url})
    interpret_scan_results(response.json())

def scan_file(file_path):
    if not file_path:  # Check if a file was selected.
        messagebox.showwarning("Warning", "Please select a file.")
        return
    file_hash = hash_file(file_path)  # Getting the file's hash.
    headers = {"x-apikey": API_KEY}
    files = {'file': (file_path, open(file_path, 'rb'))}
    response = requests.post(FILE_SCAN_API, headers=headers, files=files)
    interpret_scan_results(response.json())

# Function to check a file's hash with VirusTotal.
def check_file_hash(file_path):
    if not file_path:  # Check if a file was selected.
        messagebox.showwarning("Warning", "Please select a file.")
        return
    file_hash = hash_file(file_path)  # Getting the file's hash.
    headers = {"x-apikey": API_KEY}
    response = requests.get(FILE_HASH_API + '/' + file_hash, headers=headers)
    interpret_scan_results(response.json())

# Function to interpret the scan results from VirusTotal.
def interpret_scan_results(scan_results):
    # Checking if the item is marked as malicious.
    if scan_results.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0) > 0:
        messagebox.showinfo("Scan Result", "Not safe")
    else:
        messagebox.showinfo("Scan Result", "Safe")

# Function to let the user pick a file to scan.
def select_file():
    file_path = filedialog.askopenfilename()  # Opening file dialog to select a file.
    if file_path:  # Proceed only if a file was selected.
        threading.Thread(target=lambda: scan_file(file_path)).start()  # Starting a thread to scan the file.

# Function for selecting a file to check its hash.
def select_file_for_hash():
    file_path = filedialog.askopenfilename()  # Opening file dialog to select a file.
    if file_path:  # Proceed only if a file was selected.
        threading.Thread(target=lambda: check_file_hash(file_path)).start()  # Starting a thread to check the file's hash.

# Setting up the GUI.
root = tk.Tk()
root.title("Virus Scanner")  # Setting the window title.

# Creating and packing the GUI elements (entry field, buttons).
input_entry = tk.Entry(root, width=50)
input_entry.pack()

# Buttons for scanning URL, IP, domain, selecting a file to scan, and checking file hash.
scan_url_button = tk.Button(root, text="Scan URL", command=lambda: threading.Thread(target=lambda: scan_url(input_entry.get())).start())
scan_url_button.pack()

scan_ip_button = tk.Button(root, text="Scan IP", command=lambda: threading.Thread(target=lambda: scan_ip(input_entry.get())).start())
scan_ip_button.pack()

scan_domain_button = tk.Button(root, text="Scan Domain", command=lambda: threading.Thread(target=lambda: scan_domain(input_entry.get())).start())
scan_domain_button.pack()

select_file_button = tk.Button(root, text="Select File to Scan", command=select_file)
select_file_button.pack()

check_file_hash_button = tk.Button(root, text="Check File Hash", command=select_file_for_hash)
check_file_hash_button.pack()

root.mainloop()  # Starting the GUI application.
