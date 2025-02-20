import asyncio
import json
import re
from urllib.parse import urljoin, urlencode
from bs4 import BeautifulSoup
import constants
from json_edit import add_entry_to_json
import logging
from pyppeteer import launch

# Configuration du logger
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

PASSWORD_ERROR_PATTERNS = [
    r"password.*too short",
    r"must be at least.*12 characters",
    r"invalid",
    r"error"
]

def detect_token(soup):
    """
    Recherche dans le HTML un input caché susceptible de contenir un token
    """
    for input_tag in soup.find_all("input", {"type": "hidden"}):
        name = input_tag.get("name", "").lower()
        if any(keyword in name for keyword in constants.TOKEN_KEYWORDS):
            return name, input_tag.get("value", "")
    return None, None

async def detect_forms(url, browser):
    """
    Charge la page via pyppeteer et en extrait les formulaires
    """
    forms = []
    try:
        page = await browser.newPage()
        await page.goto(url, {'timeout': 20000})
        html = await page.content()
        soup = BeautifulSoup(html, "html.parser")
        for form in soup.find_all("form"):
            form_details = {
                "action": form.get("action"),
                "method": form.get("method", "post").lower(),
                "inputs": []
            }
            for input_tag in form.find_all("input"):
                input_name = input_tag.get("name")
                input_type = input_tag.get("type", "text")
                form_details["inputs"].append({"name": input_name, "type": input_type})
            forms.append(form_details)
        content_type = "text/html"
        await page.close()
        return forms, soup, content_type
    except Exception as e:
        logger.error(f"Error while detecting forms: {e}")
        return forms, None, None

async def submit_form(form_url, form_method, data, inputs, content_type):
    """
    Remplit le formulaire en utilisant pyppeteer pour chacuns des champs présents dans la liste `inputs` et le soumet
    
    Return : réponse du site par rapport à la requête envoyée
    """
    try:
        browser = await launch(headless=True, executablePath=constants.BROWSER_EXECUTABLE_PATH)
        page = await browser.newPage()
        await page.goto(form_url, {'timeout': 10000})
        
        forms = await page.querySelectorAll("form")
        login_form = None
        for form in forms:
            if await form.querySelector("input[type='password']"):
                login_form = form
                break

        if not login_form:
            logger.error("Aucun formulaire de connexion trouvé")
            await browser.close()
            return None

        # Récupération des champs du formulaire
        inputs = await login_form.querySelectorAll("input")
        form_data = {}
        for input_field in inputs:
            name_property = await input_field.getProperty("name")
            name = await name_property.jsonValue() if name_property else None

            type_property = await input_field.getProperty("type")
            input_type = await type_property.jsonValue() if type_property else "text"

            if name:
                form_data[name] = input_type

        # Remplissage des champs
        first_password_filled = False
        for name, input_type in form_data.items():
            if input_type == "password":
                if not first_password_filled:
                    await page.type(f'input[name="{name}"]', data.get("password", ""))
                    first_password_filled = True
                else:
                    # Remplir le champ de confirmation, ou réutiliser le password s'il n'est pas défini
                    await page.type(f'input[name="{name}"]', data.get("confirm_password", data.get("password", "")))
            elif input_type in ["text", "email"]:
                lower_name = name.lower()
                if "user" in lower_name or "uid" in lower_name:
                    await page.type(f'input[name="{name}"]', data.get("username", ""))
                elif "mail" in lower_name or "email" in lower_name:
                    await page.type(f'input[name="{name}"]', data.get("email", ""))
                else:
                    if name in data:
                        await page.type(f'input[name="{name}"]', data[name])
        
        # Soumission du formulaire
        submit_button = await login_form.querySelector("button[type='submit'], input[type='submit']")
        if submit_button:
            await submit_button.click()
        else:
            await page.evaluate('(form) => form.submit()', login_form)

        try:
            await page.waitForNavigation({'timeout': 10000})
        except Exception:
            pass

        html = await page.content()
        class FakeResponse:
            pass
        fake_response = FakeResponse()
        fake_response.status_code = 200
        fake_response.text = html
        await browser.close()
        return fake_response
    except Exception as e:
        logger.error(f"Error while submitting form: {e}, URL: {form_url}, Data: {data}")
        return None

def extract_form_details(form):
    """
    Extrait les détails pertinents d'un formulaire
    """
    form_details = {
        "username_field": None,
        "email_field": None,
        "password_field": None,
        "confirm_password_field": None,
        "other_fields": {},
        "checkboxes": {}
    }
    
    # Listes de mots-clés pour identifier les champs
    username_keywords = ["user", "username", "login", "uid", "account"]
    email_keywords = ["mail", "email", "e-mail", "address"]

    for input_tag in form["inputs"]:
        input_name = input_tag.get("name")
        input_type = input_tag.get("type", "text").lower()
        if not input_name:
            continue
        lower_input_name = input_name.lower()
        if input_type == "password":
            if form_details["password_field"] is None:
                form_details["password_field"] = input_name
            else:
                form_details["confirm_password_field"] = input_name
        elif any(keyword in lower_input_name for keyword in username_keywords):
            form_details["username_field"] = input_name
        elif input_type == "email" or any(keyword in lower_input_name for keyword in email_keywords):
            form_details["email_field"] = input_name
        elif input_type == "checkbox":
            form_details["checkboxes"][input_name] = "on"
        else:
            form_details["other_fields"][input_name] = "ASVSHermesTestvalue"
    return form_details

def prepare_form_data(form_details, test_values, token_name=None, token_value=None):
    """
    Prépare les données du formulaire à envoyer lors de la soumission.
    """
    data = {}
    if form_details.get("password_field"):
        data[form_details["password_field"]] = test_values.get("password")
    if form_details.get("confirm_password_field"):
        data[form_details["confirm_password_field"]] = test_values.get("confirm_password")
    if form_details.get("username_field"):
        data[form_details["username_field"]] = test_values.get("username")
    if form_details.get("email_field"):
        data[form_details["email_field"]] = test_values.get("email")
    data.update(form_details.get("other_fields", {}))
    data.update(form_details.get("checkboxes", {}))
    if token_name:
        data[token_name] = token_value
    return data

def validate_password_policy(response, error_patterns):
    """
    Vérifie si la réponse indique que la politique de mot de passe a échoué.
    """
    if response and response.status_code == 200:
        return any(re.search(pattern, response.text.lower()) for pattern in error_patterns)
    return False

async def check_asvs_l1_password_security_V2_1_1(vuln_list, url, browser):
    """
    Vérifie si la politique de mot de passe force un minimum de 12 caractères.
    """
    if constants.HAS_CAPTCHA:
        return vuln_list
    forms, soup, content_type = await detect_forms(url, browser)
    token_name, token_value = detect_token(soup)
    for form in forms:
        action = form["action"] if form["action"] else url
        form_url = urljoin(url, action)
        form_method = form["method"]
        form_details = extract_form_details(form)

        if not form_details["password_field"]:
            continue

        # Préparation d'un mot de passe trop court
        test_values = {
            "username": "ASVS_HERMES_TEST_user1",
            "email": "ASVSHermesTest1@gmail.com",
            "password": "Elev3nwr@ng",
            "confirm_password": "Elev3nwr@ng"
        }
        data_wrong_password = prepare_form_data(form_details, test_values, token_name, token_value)
        # Passer aussi la liste des inputs du formulaire pour remplir les champs
        sign_in_keywords = ["sign out", "logout"]
        response_wrong = await submit_form(form_url, form_method, data_wrong_password, form["inputs"], content_type)
        if response_wrong and not validate_password_policy(response_wrong, PASSWORD_ERROR_PATTERNS) and any(keyword in response_wrong.text.lower() for keyword in sign_in_keywords):
            add_entry_to_json(
                "V2.1.1",
                "Password Security",
                "User password isn't required to be at least 12 characters in length"
            )
            vuln_list.append(["Password Security", "Password accepted with fewer than 12 characters"])
    return vuln_list

async def check_asvs_l1_password_security_V2_1_2(vuln_list, url, browser):
    """
    Vérifie si un mot de passe de plus de 128 caractères est accepté.
    """
    if constants.HAS_CAPTCHA:
        return vuln_list
    forms, soup, content_type = await detect_forms(url, browser)
    token_name, token_value = detect_token(soup)
    for form in forms:
        action = form["action"] if form["action"] else url
        form_url = urljoin(url, action)
        form_method = form["method"]
        form_details = extract_form_details(form)

        if not form_details["password_field"]:
            continue

        # Préparation d'un mot de passe de 129 caractères
        long_password = "a" * 129
        test_values = {
            "username": "ASVS_HERMES_TEST_user2",
            "email": "ASVSHermesTest2@gmail.com",
            "password": long_password,
            "confirm_password": long_password
        }
        data_long_password = prepare_form_data(form_details, test_values, token_name, token_value)
        sign_in_keywords = ["sign out", "logout"]
        response_long = await submit_form(form_url, form_method, data_long_password, form["inputs"], content_type)
        if response_long and not validate_password_policy(response_long, PASSWORD_ERROR_PATTERNS) and any(keyword in response_long.text.lower() for keyword in sign_in_keywords):
            add_entry_to_json(
                "V2.1.2",
                "Password Security",
                "User password is allowed with more than 128 characters"
            )
            vuln_list.append(["Password Security", "Password accepted with more than 128 characters"])
    return vuln_list
