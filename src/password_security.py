import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin
from constants import *
from json_edit import add_entry_to_json
import logging

#logger config
logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# HTTP Headers to pretend to be a navigator
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
}

PASSWORD_ERROR_PATTERNS = [
    r"password.*too short",
    r"must be at least.*12 characters",
    r"invalid password"
]

def detect_forms(url):
    forms = []
    try:
        response = requests.get(url, headers=HEADERS, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, "html.parser")
        for form in soup.find_all("form"):
            form_details = {"action": form.get("action"), "method": form.get("method", "post").lower(), "inputs": []}
            for input_tag in form.find_all("input"):
                input_name = input_tag.get("name")
                input_type = input_tag.get("type", "text")
                form_details["inputs"].append({"name": input_name, "type": input_type})
            forms.append(form_details)
    except Exception as e:
        logger.error(f"Error while detecting forms: {e}")
    return forms

def submit_form(form_url, form_method, data):
    try:
        if form_method == "post":
            response = requests.post(form_url, data=data, headers=HEADERS, timeout=10)
        else:
            response = requests.get(form_url, params=data, headers=HEADERS, timeout=10)
        return response
    except Exception as e:
        logger.error(f"Error while submitting form: {e}")
        return None

def check_asvs_l1_password_security_V2_1_1(vuln_list, url):
    forms = detect_forms(url)
    print(f"OMAGAD A FORM: {forms}")
    for form in forms:
        action = form["action"] if form["action"] else url
        form_url = urljoin(url, action)
        form_method = form["method"]
        inputs = form["inputs"]

        password_field = None
        confirm_password_field = None
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
            elif input_type == "checkbox":
                checkboxes[input_name] = "on"
            else:
                other_fields[input_name] = "ASVSHermesTestvalue"

        if not password_field:
            continue

        data_wrong_password = {password_field: "short"}
        if confirm_password_field:
            data_wrong_password[confirm_password_field] = "short"
        data_wrong_password.update(other_fields)
        data_wrong_password.update(checkboxes)

        response_wrong = submit_form(form_url, form_method, data_wrong_password)
        if response_wrong and response_wrong.status_code == 200:
            if not any(re.search(pattern, response_wrong.text.lower()) for pattern in PASSWORD_ERROR_PATTERNS):
                add_entry_to_json(
                    "V2.1.1",
                    "Password Security",
                    "User password isn't required to be at least 12 characters in length"
                )
                vuln_list.append(["Password Security", "Password accepted with fewer than 12 characters"])
    return vuln_list
