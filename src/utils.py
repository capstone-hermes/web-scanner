import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from password_security import check_asvs_l1_password_security_V2_1_1
from constants import *
from json_edit import *


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
        add_entry_to_json("SQL injection", "URL", "URL contains parameters")
        vuln_list.append(["SQL injection", "URL contains parameters"])
    return vuln_list


def check_SQL(vuln_list, url, name, type):
    check_list_type_sql = ["email", "password", "search", "text"]
    if type in check_list_type_sql:
        add_entry_to_json("SQL injection", "form type : " + type, "")
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


## add scanning fuctions in the list to execute them
function_check_list = []
one_time_function_list = [check_url_sql, check_asvs_l1_password_security_V2_1_1]
