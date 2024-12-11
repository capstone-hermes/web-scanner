import requests
from bs4 import BeautifulSoup
import re
from constants import *
from json_edit import add_entry_to_json


## Args: url (str): The URL to scan
##       vuln_list (tuple list): Gets all the supposed scanned ASVS security breach
## Returns: list: A list of dictionaries, each containing form action, method, and input fields
def detect_forms(url):
    forms = []
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, "html.parser")
        for form in soup.find_all("form"):
            form_details = {"action": form.get("action"), "method": form.get("method", "get").lower(), "inputs": []}
            for input_tag in form.find_all("input"):
                input_name = input_tag.get("name")
                input_type = input_tag.get("type", "text")
                form_details["inputs"].append({"name": input_name, "type": input_type})
            forms.append(form_details)
    except Exception as e:
        print(f"Error while detecting forms: {e}")
    return forms


## Args: url (str): The URL of the registration/login page
##       vuln_list (tuple list): Gets all the supposed scanned ASVS security breach
## Returns: bool: True if the site enforces 12+ character password policy, False otherwise
def check_asvs_l1_password_security_V2_1_1(vuln_list, url):
    forms = detect_forms(url)

    for form in forms:
        print(f"ACTION = {form["action"]}")
        action = form["action"] if form["action"] else url
        form_method = form["method"]
        inputs = form["inputs"]

        username_field = None
        password_field = None
        confirm_password_field = None
        email_field = None
        other_fields = {}
        checkboxes = {}
        for input_tag in inputs:
            input_name = input_tag.get("name")
            input_type = input_tag.get("type", "text")

            if not input_name:
                continue
            if input_type == "password":
                if password_field is None:
                    password_field = input_name
                else:
                    confirm_password_field = input_name
            elif "user" in input_name.lower():
                username_field = input_name
            elif input_type == "email" or "mail" in input_name.lower():
                email_field = input_name
            elif input_type == "checkbox":
                checkboxes[input_name] = "on"
            else:
                other_fields[input_name] = "ASVSHermesTestvalue"

        if not password_field:
            continue
        form_url = url if action.startswith("/") else action
        data_wrong_password = {password_field: "Elev3nwr@ng"}
        if confirm_password_field:
            data_wrong_password[confirm_password_field] = "Elev3nwr@ng"
        if username_field:
            data_wrong_password[username_field] = "ASVS_HERMES_TEST_user"
        if email_field:
            data_wrong_password[email_field] = "ASVSHermesTest@gmail.com"
        data_wrong_password.update(other_fields)
        data_wrong_password.update(checkboxes)
        try:
            if form_method == "post":
                response_wrong = requests.post(form_url, data=data_wrong_password, timeout=10)
            else:
                response_wrong = requests.get(form_url, params=data_wrong_password, timeout=10)
            if response_wrong.status_code == 200 and "error" not in response_wrong.text.lower():
                add_entry_to_json("V2.1.1", "Password Security", "User password isn't required to be at least 12 characters in length")
                vuln_list.append(["Password Security", "Password accepted with fewer than 12 characters"])
            return vuln_list
        except Exception as e:
            print(f"Error while scanning form: {e}")
    return vuln_list