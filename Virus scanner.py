import requests

# 1. This line imports the 'requests' module, which lets us send HTTP requests using Python.

def check_website(url):
    # 2. We define a function 'check_website' that takes a URL as its argument.

    api_key = 'l4s6un6v...a7c99f75'
    # 3. Replace 'YOUR_API_KEY' with your actual API key from Hybrid Analysis.

    headers = {'api-key': api_key, 'user-agent': 'Falcon Sandbox'}
    # 4. We set the headers for our API request, including our API key and a user agent.

    params = {'url': url}
    # 5. We set the parameters for our request, which is the URL to check.

    response = requests.post('https://www.hybrid-analysis.com/api/v2/quick-scan/url', headers=headers, data=params)
    # 6. We send a POST request to the Hybrid Analysis quick scan API with our headers and parameters.

    if response.status_code == 200:
        result_url = response.json()['permalink']
        # 7. If the request is successful, we get the permanent link to the scan results from the JSON response.

        print(f"Check the detailed report of the website scan here: {result_url}")
        # 8. We print out the link to the report for the user to view.
    else:
        print("There was an error scanning the website.")
        print("Status Code:", response.status_code)
        print("Response:", response.text)
        # 9. These lines print out the status code and the response text, which can help in diagnosing the issue.

# This part is where we ask the user for the website they want to check.
user_input_url = input("Enter the website URL you want to scan for malware: ")
# 10. We ask the user to input a website URL.

check_website(user_input_url)
# 11. We call the 'check_website' function with the user's input URL.
