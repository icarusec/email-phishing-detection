import requests
import pandas as pd
import os

def domain_db_update():
    filename='processed_domains.pkl'
    if os.path.exists(filename):
        os.remove(filename)
        print("Deleting Previous Domain Blacklist")

    urls = [
        "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/wildcard/tif-onlydomains.txt",
        "https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt",
        "https://malware-filter.gitlab.io/malware-filter/phishing-filter-domains.txt",
        "https://raw.githubusercontent.com/matomo-org/referrer-spam-blacklist/master/spammers.txt",
        "https://phishing.army/download/phishing_army_blocklist_extended.txt",
        "https://big.oisd.nl/domainswild2"
    ]
    
    processed_domains = set()
    
    for url in urls:
        print(f"Fetching Domains from {url}: ")
        response = requests.get(url)
        
        if response.status_code == 200:
            lines = response.text.splitlines()
            for line in lines:
                if '#' in line:
                    continue
                processed_domains.add(line)
        else:
            print(f"Failed to download file from {url}. HTTP Status Code: {response.status_code}")
    
    df = pd.DataFrame(sorted(processed_domains), columns=["domain"])
    output_filename = "processed_domains.pkl"
    df.to_pickle(output_filename)
    
    print(f"Processed domains saved to {output_filename}")

def ip_db_update():

    filename='processed_ip.pkl'
    if os.path.exists(filename):
        os.remove(filename)
        print("Deleting Previous IP Blacklist")

    urls = [
        "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
        "https://sslbl.abuse.ch/blacklist/sslipblacklist_aggressive.txt",
        "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
        "https://lists.blocklist.de/lists/all.txt",
        "http://www.talosintelligence.com/documents/ip-blacklist",
        "https://lists.blocklist.de/lists/mail.txt",
        "https://snort.org/downloads/ip-block-list"
    ]
    
    processed_lines = []
    
    for url in urls:
        print(f"Fetching IP's from {url}:")
        response = requests.get(url)
        if response.status_code == 200:
            lines = response.text.splitlines()
            for line in lines:
                if '#' in line:
                    continue
                if url == "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt":
                    first_field = line.split('\t')[0]
                    processed_lines.append(first_field)
                else:
                    processed_lines.append(line)
        else:
            print(f"Failed to download file from {url}. HTTP Status Code: {response.status_code}")

    df = pd.DataFrame(sorted(processed_lines), columns=["ip"])
    output_filename = "processed_ip.pkl"
    df.to_pickle(output_filename)
    
    print(f"Processed IPs saved to {output_filename}")


