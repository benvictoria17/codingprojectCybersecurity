import tkinter as tk
from tkinter import messagebox, filedialog
import threading
import cloudmersive_virus_api_client
from cloudmersive_virus_api_client.rest import ApiException
import cloudmersive_virus_api_client.models.website_scan_result
from pprint import pprint

configuration = cloudmersive_virus_api_client.Configuration()
configuration.api_key['Apikey'] = '98579813-375d-4664-b309-d365dde49f29'
api_instance = cloudmersive_virus_api_client.ScanApi(cloudmersive_virus_api_client.ApiClient(configuration))

# good_website = google.com
# bad_website = linux.domainesia.com


def scan_url(url):
    if not url:  # Check if the input is empty
        messagebox.showwarning("Warning", "Please enter a URL.")
        return

    input = cloudmersive_virus_api_client.WebsiteScanRequest(url)

    try:
        api_response = api_instance.scan_website(input)
        # pprint(api_response)
    except ApiException as e:
        api_response = None
        print("Exception when calling ScanApi->scan_website: %s\n" % e)

    check_website_scan_results(api_response)


def scan_file(file_path):
    try:
        # Scan a file for viruses
        api_response = api_instance.scan_file(file_path)
        # pprint(api_response)
    except ApiException as e:
        api_response = None
        print("Exception when calling ScanApi->scan_file: %s\n" % e)

    check_file_scan_results(api_response)


def select_file():
    file_path = filedialog.askopenfilename()  # Opening file dialog to select a file
    if file_path:
        threading.Thread(target=lambda: scan_file(file_path)).start()  # Starting a thread to scan the file


def check_website_scan_results(scan_results):
    # Checking if the website is marked as malicious

    if scan_results is None:
        messagebox.showinfo("Scan Result", "Unable to scan website.")

    results_dict = scan_results.to_dict()
    pprint(results_dict)

    if 'website_threat_type' in results_dict:
        if results_dict['website_threat_type'] == 'None':
            messagebox.showinfo("Scan Result", "Safe")
        else:
            messagebox.showinfo("Scan Result", f"Not safe.\nReason: {results_dict['website_threat_type']}")
    else:
        messagebox.showinfo("Scan Result", "Unable to scan website.")


def check_file_scan_results(scan_results):
    # Checking if the file is marked as malicious

    if scan_results is None:
        messagebox.showinfo("Scan Result", "Unable to scan file.")

    results_dict = scan_results.to_dict()
    pprint(results_dict)

    if 'clean_result' in results_dict:
        if results_dict['clean_result'] == True:
            messagebox.showinfo("Scan Result", "Safe")
        else:
            messagebox.showinfo("Scan Result", f"Not safe.\nReason: {results_dict['found_viruses']}")
    else:
        messagebox.showinfo("Scan Result", "Unable to scan website.")


# Setting up the GUI
root = tk.Tk()
root.title("Virus Scanner")  # Setting the window title

# Adding the URL input entry to the GUI
input_entry = tk.Entry(root, width=50)
input_entry.pack()

# Button for scanning URL
scan_url_button = tk.Button(root, text="Scan UR/Website Domain/IP address", command=lambda: threading.Thread(target=lambda: scan_url(input_entry.get())).start())
scan_url_button.pack()

# Button for scanning file
select_file_button = tk.Button(root, text="Select File to Scan", command=select_file)
select_file_button.pack()

root.mainloop()  # Starting the GUI application
