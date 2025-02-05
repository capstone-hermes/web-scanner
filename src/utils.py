import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from password_security import *
from constants import *
from json_edit import *
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("scanner.log"), # logs are written in this file
        logging.StreamHandler()             
    ]
)
logger = logging.getLogger(__name__)

def fetch_page(url):
    try:
        response = requests.get(url)
        if response.status_code != 200:
            logger.error(f"Failed to retrieve the page. Status code: {response.status_code}")
            return None
        logger.info("Page retrieved successfully")
        return response
    except requests.RequestException as e:
        logger.error(f"Error fetching the page: {e}")
        return None

def process_forms(vuln_list, forms, url):
    for form in forms:
        inputs = form.find_all('input')
        for input_field in inputs:
            input_name = input_field.get('name', '')
            input_type = input_field.get('type', 'text')
            for function_check in function_check_list:
                vuln_list = function_check(vuln_list, url, input_name, input_type)
    return vuln_list

## Args: url (str): Link to be scanned
##       visited (list): List of already visited URLs
## Returns: List: Returns a list of all the links accessible by following href belonging to the same domain as the base URL
def get_internal_links(url, visited=None):
    if visited is None:
        visited = []

    domain = urlparse(url).netloc
    if url in visited:
        return visited
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
    except requests.RequestException:
        return visited

    visited.append(url)
    soup = BeautifulSoup(response.text, "html.parser")
    for link in soup.find_all("a", href=True):
        new_url = urljoin(url, link["href"])
        parsed_url = urlparse(new_url)
        if parsed_url.netloc == domain and new_url not in visited:
            get_internal_links(new_url, visited)
    return visited

def process_url(url):
    clear_json()
    if not url.startswith("https://"):
        url = "https://" + url

    logger.info(f"Processing URL: {url}")
    links = get_internal_links(url)
    if links == False:
        return 1

    vuln_list = []
    set_json(links[0])
    for link in links:
        response = fetch_page(link)
        if not response:
            return 1
        add_link_to_json(link)

        HTML_soup = BeautifulSoup(response.text, 'html.parser')
        forms = HTML_soup.find_all('form')
        constants.HAS_CAPTCHA = check_for_captcha(response, HTML_soup)

        for function_check in one_time_function_list:
            vuln_list = function_check(vuln_list, link)

        # Forms analyze
        vuln_list = process_forms(vuln_list, forms, link)

    logger.info(f"Vulnerabilities detected: {vuln_list}")
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
one_time_function_list = [check_asvs_l1_password_security_V2_1_1, check_asvs_l1_password_security_V2_1_2]
