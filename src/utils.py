import sys
import requests
import json
import os
from bs4 import BeautifulSoup
from pathlib import Path
from urllib.parse import urlparse

JSONNAME = "./output.json"
HAS_CAPTCHA = False

def process_url(url):
    clear_json()
    if url.startswith("https://") != True:
        url = "https://" + url

    print(f"Processing URL: " + url)
    try:
        response = requests.get(url)
    except:
        print("Failed to retrieve the page")
        return 1
    if response.status_code != 200:
        print("Failed to retrieve the page")
        return 1

    set_json(url)
    vuln_list = []
    for function_check in one_time_function_list:
        vuln_list = function_check(vuln_list, url)
    HTML_soup = BeautifulSoup(response.text, 'html.parser')
    forms = HTML_soup.find_all('form')
    global HAS_CAPTCHA
    HAS_CAPTCHA = check_for_captcha(response, HTML_soup)
    for form in forms:
        inputs = form.find_all('input')
        for input_field in inputs:
            input_name = input_field.get('name', '')
            input_type = input_field.get('type', 'text')
            for function_check in function_check_list:
                vuln_list = function_check(vuln_list, url, input_name, input_type)
    print(vuln_list)
    return 0


#############################################################################
## Functions scanning for vulnerabilities to check
#############################################################################

def check_parameters(url):
    parsed_url = urlparse(url)
    return bool(parsed_url.query)



def check_url_sql(vuln_list, url):
    if check_parameters(url):
        add_entry_to_json("SQL injection", "URL", "", "URL contains parameters")
        vuln_list.append(["SQL injection", "URL contains parameters"])
    return vuln_list



def check_SQL(vuln_list, url, name, type):
    check_list_type_sql = ["email", "password", "search", "text"]
    if type in check_list_type_sql:
        add_entry_to_json("SQL injection", "form type : " + type, "form name : " + name, "")
        vuln_list.append(["SQL injection", "form type : " + type])
    return vuln_list


def check_for_captcha(response, HTML_soup):
    captcha_keywords = ["captcha", "g-recaptcha", "h-captcha", "grecaptcha", "verify you're human"]

    if any(keyword in response.text.lower() for keyword in captcha_keywords):
        return True

    iframes = HTML_soup.find_all("iframe")
    for iframe in iframes:
        iframe_src = iframe.get("src", "")
        if any(keyword in iframe_src.lower() for keyword in captcha_keywords):
            return True

    scripts = HTML_soup.find_all("script")
    for script in scripts:
        script_src = script.get("src", "")
        if any(keyword in script_src.lower() for keyword in captcha_keywords):
            return True
    return False



def check_brute_force(vuln_list, url, name, type):
    check_list_type_brute = ["password"]
    if type in check_list_type_brute:
        if (HAS_CAPTCHA):
            add_entry_to_json("Brute force", "form type : " + type, "form name : " + name, "Probably harder to do since there is a captcha")
            vuln_list.append(["Brute force", "form type : " + type])
        else:
            add_entry_to_json("Brute force", "form type : " + type, "form name : " + name, "")
            vuln_list.append(["Brute force", "form type : " + type])
    return vuln_list

## add scanning fuctions in the list to execute them
function_check_list = [check_SQL, check_brute_force]
one_time_function_list = [check_url_sql]

#############################################################################
## Writing entries in json
#############################################################################

def set_json(url):
    if Path(JSONNAME).is_file():
        with open(JSONNAME, 'r') as file:
            data = json.load(file)
    else:
        data = []

    start_entry = {
        "URL scanned": url
    }
    data.append(start_entry)
    with open(JSONNAME, 'w') as file:
        json.dump(data, file, indent=4)
    file.close()

# if the entry doesn't have a name, put "" (or an empty string) for the 'form_name' parameter. Same for info
def add_entry_to_json(name, found_in, form_name, info):
    if Path(JSONNAME).is_file():
        with open(JSONNAME, 'r') as file:
            data = json.load(file)

    if (form_name == ""):
        new_entry = {
            "Name": name,
            "Found_in": found_in,
            "Info": info
        }
    else:
        new_entry = {
            "Name": name,
            "Found_in": found_in,
            "Info": info,
            "Form_name": form_name
        }
    data.append(new_entry)

    with open(JSONNAME, 'w') as file:
        json.dump(data, file, indent=4)

def clear_json():
    if Path(JSONNAME).is_file():
        os.remove(JSONNAME)