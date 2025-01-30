import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin
import constants
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

def extract_form_details(form):
    """Extract relevant details from a form."""

    form_details = {
        "username_field": None,
        "email_field": None,
        "password_field": None,
        "confirm_password_field": None,
        "other_fields": {},
        "checkboxes": {}
    }
    for input_tag in form["inputs"]:
        input_name = input_tag.get("name")
        input_type = input_tag.get("type", "text")
        if not input_name:
            continue
        if input_type == "password":
            if form_details["password_field"] is None:
                form_details["password_field"] = input_name
            else:
                form_details["confirm_password_field"] = input_name
        elif "user" in input_name.lower():
            form_details["username_field"] = input_name
        elif input_type == "email" or "mail" in input_name.lower():
            form_details["email_field"] = input_name
        elif input_type == "checkbox":
            form_details["checkboxes"][input_name] = "on"
        else:
            form_details["other_fields"][input_name] = "ASVSHermesTestvalue"
    return form_details

def prepare_form_data(form_details, test_values):
    """Prepare form data for submission."""

    data = {}
    if form_details["password_field"]:
        data[form_details["password_field"]] = test_values.get("password")
    if form_details["confirm_password_field"]:
        data[form_details["confirm_password_field"]] = test_values.get("confirm_password")
    if form_details["username_field"]:
            data[form_details["username_field"]] = test_values.get("username")
    if form_details["email_field"]:
            data[form_details["email_field"]] = test_values.get("email")
    data.update(form_details["other_fields"])
    data.update(form_details["checkboxes"])
    return data


def validate_password_policy(response, error_patterns):
    """Check if the response indicates a failed password validation."""
    if response and response.status_code == 200:
        return any(re.search(pattern, response.text.lower()) for pattern in error_patterns)
    return False


def check_asvs_l1_password_security_V2_1_1(vuln_list, url):
    if constants.HAS_CAPTCHA:
        return vuln_list
    forms = detect_forms(url)
    for form in forms:
        action = form["action"] if form["action"] else url
        form_url = urljoin(url, action)
        form_method = form["method"]

        form_details = extract_form_details(form)
        if not form_details["password_field"]:
            continue

        # Prepare datas for a short pwd
        test_values = {"username": "ASVS_HERMES_TEST_user", "email": "ASVSHermesTest@gmail.com", "password": "Elev3nwr@ng", "confirm_password": "Elev3nwr@ng"}
        data_wrong_password = prepare_form_data(form_details, test_values)

        response_wrong = submit_form(form_url, form_method, data_wrong_password)

        # Verify response
        if response_wrong and not validate_password_policy(response_wrong, PASSWORD_ERROR_PATTERNS):
            add_entry_to_json(
                "V2.1.1",
                "Password Security",
                "User password isn't required to be at least 12 characters in length"
            )
            vuln_list.append(["Password Security", "Password accepted with fewer than 12 characters"])
    return vuln_list


def check_asvs_l1_password_security_V2_1_2(vuln_list, url):
    if constants.HAS_CAPTCHA:
        return vuln_list
    forms = detect_forms(url)
    for form in forms:
        action = form["action"] if form["action"] else url
        form_url = urljoin(url, action)
        form_method = form["method"]

        form_details = extract_form_details(form)
        if not form_details["password_field"]:
            continue
        
        # Prepare a password with more than 128 char
        long_password = "a" * 129
        test_values = {"username": "ASVS_HERMES_TEST_user", "email": "ASVSHermesTest@gmail.com", "password": long_password, "confirm_password": long_password}
        data_long_password = prepare_form_data(form_details, test_values)

        response_long = submit_form(form_url, form_method, data_long_password)

        if response_long and not validate_password_policy(response_long, PASSWORD_ERROR_PATTERNS):
            add_entry_to_json(
                "V2.1.2",
                "Password Security",
                "User password is allowed with more than 128 characters"
            )
            vuln_list.append(["Password Security", "Password accepted with more than 128 characters"])
    return vuln_list
