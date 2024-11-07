import sys
import requests
from bs4 import BeautifulSoup

def process_url(url):
    if url.startswith("https://") != True:
        url = "https://" + url

    print(f"Processing URL: " + url)
    try:
        response = requests.get(url)
    except:
        print("Failed to retrieve the page.")
        return 1
    if response.status_code != 200:
        print("Failed to retrieve the page.")
        return 1

    vuln_list = []
    HTMLsoup = BeautifulSoup(response.text, 'html.parser')
    forms = HTMLsoup.find_all('form')
    for form in forms:
        inputs = form.find_all('input')
        for input_field in inputs:
            input_name = input_field.get('name', '')
            input_type = input_field.get('type', 'text')
            print(f"Input name '{input_name}' and type '{input_type}'")
            for function_check in function_check_list:
                vuln_list = function_check(vuln_list, url, input_name, input_type)
    print(vuln_list)
    return 0

def check_SQL(vuln_list, url, name, type):
    return vuln_list

def check_password(vuln_list, url, name, type):
    return vuln_list

function_check_list = [check_SQL, check_password]