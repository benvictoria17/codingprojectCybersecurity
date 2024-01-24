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

# Here, we define keys and addresses to use the VirusTotal service for checking safety.
API_KEY = 'ba82a809340dc576dcc6e122fe1e7768cd54993959168998fd425965cf3f1408'
URL_SCAN_API = 'https://www.virustotal.com/api/v3/urls'
FILE_SCAN_API = 'https://www.virustotal.com/api/v3/files'
IP_SCAN_API = 'https://www.virustotal.com/api/v3/ip_addresses/'
DOMAIN_SCAN_API = 'https://www.virustotal.com/api/v3/domains/'
FILE_HASH = 'https://www.virustotal.com/api/v3/files/'

# This function computes the SHA-256 hash of a file, a way to uniquely identify it.
def hash_file(file_path):
    BUF_SIZE = 65536  # This is the size of the chunk of the file it reads at a time.
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:  # Opens file in binary mode.
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            sha256.update(data)
    return sha256.hexdigest()

# These functions use the VirusTotal service to check if an IP, domain, URL, or file is safe.
def scan_ip(ip_address):
    headers = {"x-apikey": API_KEY}
    response = requests.get(IP_SCAN_API + ip_address, headers=headers)
    interpret_scan_results(response.json())

def scan_domain(domain):
    headers = {"x-apikey": API_KEY}
    response = requests.get(DOMAIN_SCAN_API + domain, headers=headers)
    interpret_scan_results(response.json())

def scan_url(url):
    headers = {"x-apikey": API_KEY}
    response = requests.post(URL_SCAN_API, headers=headers, data={"url": url})
    interpret_scan_results(response.json())

def scan_file(file_path):
    file_hash = hash_file(file_path)
    headers = {"x-apikey": API_KEY}
    files = {'file': (file_path, open(file_path, 'rb'))}
    response = requests.post(FILE_SCAN_API, headers=headers, files=files)
    interpret_scan_results(response.json())

# After scanning, this function shows a message if the item is safe or not.
def interpret_scan_results(scan_results):
    if scan_results.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0) > 0:
        messagebox.showinfo("Scan Result", "Not safe")
    else:
        messagebox.showinfo("Scan Result", "Safe")

# Lets the user pick a file to scan for safety.
def select_file():
    file_path = filedialog.askopenfilename()
    if file_path:  # Proceeds only if a file was chosen.
        threading.Thread(target=lambda: scan_file(file_path)).start()

# Sets up the window where you interact with the program.
root = tk.Tk()
root.title("Virus Scanner")

# A place to enter URLs, IP addresses, or domains.
input_entry = tk.Entry(root, width=50)
input_entry.pack()

# Buttons for the different types of scans you can do.
scan_url_button = tk.Button(root, text="Scan URL", command=lambda: threading.Thread(target=lambda: scan_url(input_entry.get())).start())
scan_url_button.pack()

scan_ip_button = tk.Button(root, text="Scan IP", command=lambda: threading.Thread(target=lambda: scan_ip(input_entry.get())).start())
scan_ip_button.pack()

scan_domain_button = tk.Button(root, text="Scan Domain", command=lambda: threading.Thread(target=lambda: scan_domain(input_entry.get())).start())
scan_domain_button.pack()

file_button = tk.Button(root, text="Select File to Scan", command=select_file)
file_button.pack()

file_hash_button = tk.Button(root, text="File Hash", command=lambda: threading.Thread(target=hash_file).start())
file_hash_button.pack()

# Begins the application, opening the window for interaction.
root.mainloop()
