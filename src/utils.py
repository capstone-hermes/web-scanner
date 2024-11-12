import sys
import requests
import json
import os
from bs4 import BeautifulSoup
from pathlib import Path

def process_url(url):
    clear_json("./output.json")
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

    vuln_list = []
    HTMLsoup = BeautifulSoup(response.text, 'html.parser')
    forms = HTMLsoup.find_all('form')
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


def check_SQL(vuln_list, url, name, type):
    check_list_type_sql = ["email", "password", "search", "text"]
    check_list_name_sql = ["username", "password", "id", "query", "search"]
    if type in check_list_type_sql:
        add_entry_to_json("./output.json", "SQL injection", "form type : " + type)
        vuln_list.append(["SQL injection", "form type : " + type])
        return vuln_list
    elif name in check_list_name_sql:
        add_entry_to_json("./output.json", "SQL injection", "form name : " + name)
        vuln_list.append(["SQL injection", "form name : " + name])
        return vuln_list
    return vuln_list

def check_password(vuln_list, url, name, type):
    return vuln_list

## add scanning fuctions in the list to execute them
function_check_list = [check_SQL, check_password]


#############################################################################
## Writing entries in json
#############################################################################


def add_entry_to_json(file_path, name, found_in):
    if Path(file_path).is_file():
        with open(file_path, 'r') as file:
            data = json.load(file)
    else:
        data = []

    new_entry = {
        "name": name,
        "found_in": found_in
    }
    data.append(new_entry)

    with open(file_path, 'w') as file:
        json.dump(data, file, indent=4)

def clear_json(file_path):
    os.remove(file_path)