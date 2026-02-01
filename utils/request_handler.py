import requests
import urllib3
urllib3.disable_warnings()

def send_request(url):
    try:
        return requests.get(url, timeout=10, verify=False)
    except:
        return None
