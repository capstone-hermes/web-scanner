import asyncio
import json
import re
from urllib.parse import urljoin, urlencode
from bs4 import BeautifulSoup
import constants
from json_edit import add_entry_to_json
import logging
from pyppeteer import launch
import platform

# Configuration du logger
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

PASSWORD_ERROR_PATTERNS = [
    r"too short",
    r"must be at least",
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

def validate_password_policy(response, error_patterns):
    """
    Vérifie si la réponse indique que la politique de mot de passe a échoué.
    """
    if response:
        return any(re.search(pattern, response) for pattern in error_patterns)
    return False

async def attempt_signup(url, test_data):
    """
    Simule la soumission d'un formulaire d'inscription via pyppeteer.
    
    Processus :
      - Ouvre la page à l'URL donnée.
      - Recherche le premier formulaire contenant un champ password (sinon utilise le premier formulaire trouvé).
      - Récupère dynamiquement les champs du formulaire et les remplit en fonction du dictionnaire test_data.
        Les clés attendues dans test_data sont :
          - "username"
          - "password"
          - "confirm_password" (optionnel, sinon on réutilise "password")
          - "email" (optionnel)
      - Soumet le formulaire (en cliquant sur le bouton submit ou en exécutant form.submit()).
      - Attend quelques secondes pour laisser le temps au rechargement et retourne le contenu HTML de la page résultante.
    """
    try:
        username_keywords = ["user", "username", "login", "uid", "account"]
        email_keywords = ["mail", "email", "e-mail", "address"]
        # replace to have visual demo
        # browser = await launch(headless=False, slowMo=10, executablePath=constants.BROWSER_EXECUTABLE_PATH)
        browser = await launch(headless=True, executablePath=constants.BROWSER_EXECUTABLE_PATH, args=[
            '--no-sandbox',  # necessary when running as root in Docker
            '--disable-setuid-sandbox'
        ])
        page = await browser.newPage()
        logger.info(f"Accès à {url}...")
        await page.goto(url, {'timeout': 10000})

        # Recherche des formulaires sur la page
        forms = await page.querySelectorAll("form")
        login_form = None
        for form in forms:
            if await form.querySelector("input[type='password']"):
                login_form = form
                break
        if not login_form:
            logger.error("Aucun formulaire trouvé sur la page.")
            await browser.close()
            return None

        # Récupération et remplissage dynamique des champs du formulaire
        inputs = await login_form.querySelectorAll("input")
        # On utilise une variable dans test_data pour suivre le remplissage du premier champ password
        test_data["password_filled"] = False
        for input_field in inputs:
            name_prop = await input_field.getProperty("name")
            name = await name_prop.jsonValue() if name_prop else None
            type_prop = await input_field.getProperty("type")
            input_type = (await type_prop.jsonValue()) if type_prop else "text"
            if not name:
                continue
            if input_type.lower() == "password":
                if not test_data["password_filled"]:
                    await page.type(f'input[name="{name}"]', test_data.get("password"))
                    test_data["password_filled"] = True
                else:
                    await page.type(f'input[name="{name}"]', test_data.get("confirm_password", test_data.get("password")))
            elif input_type.lower() in ["text", "email"]:
                lower_name = name.lower()
                if any(keyword in lower_name for keyword in username_keywords):
                    await page.type(f'input[name="{name}"]', test_data.get("username"))
                elif any(keyword in lower_name for keyword in email_keywords):
                    await page.type(f'input[name="{name}"]', test_data.get("email"))
                elif name in test_data:
                    await page.type(f'input[name="{name}"]', test_data[name])
        
        # Soumission du formulaire
        submit_button = await login_form.querySelector("button[type='submit'], input[type='submit']")
        if submit_button:
            await submit_button.click()
        else:
            await page.evaluate('(form) => form.submit()', login_form)
        
        # Attendre quelques secondes pour le rechargement
        await asyncio.sleep(2)
        content = await page.content()
        await browser.close()
        return content
    except Exception as e:
        logger.error(f"Erreur lors de l'inscription: {e}")
        return None

async def check_asvs_l1_password_security_V2_1_1(vuln_list, url):
    """
    Vérifie si la politique de mot de passe force un minimum de 12 caractères
    """
    if constants.HAS_CAPTCHA or not constants.HAS_INDENTIFICATION:
        return vuln_list
    
    test_data = {
        "username": "1HERMEStest",
        "email": "1ASVSHermesTest@gmail.com",
        "password": "Elev3nwr@ng",
        "confirm_password": "Elev3nwr@ng"
    }

    content = await attempt_signup(url, test_data)
    if content:
        lower_content = content.lower()
        if lower_content and not validate_password_policy(lower_content, PASSWORD_ERROR_PATTERNS):
            add_entry_to_json(
                "V2.1.1",
                "Password Security",
                "User password isn't required to be at least 12 characters in length"
            )
            vuln_list.append(["Password Security", "Password accepted with fewer than 12 characters"])
    return vuln_list

async def check_asvs_l1_password_security_V2_1_2(vuln_list, url):
    """
    Vérifie si un mot de passe de plus de 128 caractères est accepté
    """
    if constants.HAS_CAPTCHA or not constants.HAS_INDENTIFICATION:
        return vuln_list

    long_password = "a" * 129
    test_data = {
        "username": "2HERMEStest",
        "email": "2ASVSHermesTest@gmail.com",
        "password": long_password,
        "confirm_password": long_password
    }

    content = await attempt_signup(url, test_data)
    if content:
        lower_content = content.lower()
        if lower_content and not validate_password_policy(lower_content, PASSWORD_ERROR_PATTERNS):
            add_entry_to_json(
                "V2.1.2",
                "Password Security",
                "User password is allowed with more than 128 characters"
            )
            vuln_list.append(["Password Security", "Password accepted with more than 128 characters"])
    return vuln_list

async def check_asvs_l1_password_security_V2_1_3(vuln_list, url):
    """
    Vérifie si le mot de passe est tronqué
    """
    if constants.HAS_CAPTCHA or not constants.HAS_INDENTIFICATION:
        return vuln_list

    long_password = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwx"
    test_data = {
        "username": "3HERMEStest",
        "email": "3ASVSHermesTest@gmail.com",
        "password": long_password,
        "confirm_password": long_password
    }
    content = await attempt_signup(url, test_data)

    long_password = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrst"
    test_data = {
        "username": "3HERMEStest",
        "email": "3ASVSHermesTest@gmail.com",
        "password": long_password,
        "confirm_password": long_password
    }
    content = await attempt_signup(url, test_data)
    if content:
        lower_content = content.lower()
        created_account_keywords = ["account created", "successfully", "success"]
        if lower_content and any(keyword in lower_content for keyword in created_account_keywords):
            return vuln_list
        if lower_content and not validate_password_policy(lower_content, PASSWORD_ERROR_PATTERNS):
            add_entry_to_json(
                "V2.1.3",
                "Password Security",
                "User password truncation is performed and accepted"
            )
            vuln_list.append(["Password Security", "Password truncation is performed and accepted"])
    return vuln_list

async def check_asvs_l1_password_security_V2_1_4(vuln_list, url):
    """
    Vérifie si un mot de passe accepte des charactère unicode ainsi que des emojis
    """
    if constants.HAS_CAPTCHA or not constants.HAS_INDENTIFICATION:
        return vuln_list

    weird_password = "☺☺☺🤖☻♥♦♣♠•◘○♦P4ssw@rd😁😎"
    test_data = {
        "username": "4HERMEStest",
        "email": "4ASVSHermesTest@gmail.com",
        "password": weird_password,
        "confirm_password": weird_password
    }

    content = await attempt_signup(url, test_data)
    if content:
        lower_content = content.lower()
        already_existing_user_keywords = ["exists", "already", "taken"]
        if lower_content and any(keyword in lower_content for keyword in already_existing_user_keywords):
            return vuln_list
        if lower_content and validate_password_policy(lower_content, PASSWORD_ERROR_PATTERNS):
            add_entry_to_json(
                "V2.1.4",
                "Password Security",
                "User password doesn't accept unicode and emojis"
            )
            vuln_list.append(["Password Security", "Password doesn't accept unicode and emojis"])
    return vuln_list

## check_asvs_l1_password_security_V2_1_5 doit pouvoir vérifier si un utilisateur peut modifier son mot de passe

## check_asvs_l1_password_security_V2_1_6 doit pouvoir vérifier que le changement de mot de passe demande l'ancien mot de passe

async def check_asvs_l1_password_security_V2_1_7(vuln_list, url):
    """
    Vérifie si le mot de passe accepte les mots de passe les plus utilisés
    """
    if constants.HAS_CAPTCHA or not constants.HAS_INDENTIFICATION:
        return vuln_list

    with open("./data/1000-most-common-passwords.txt") as file:
        for line in file:
            weird_password = line.rstrip()
            test_data = {
                "username": "7HERMEStest",
                "email": "7ASVSHermesTest@gmail.com",
                "password": weird_password,
                "confirm_password": weird_password
            }
            content = await attempt_signup(url, test_data)
            if content:
                lower_content = content.lower()
                if lower_content and not validate_password_policy(lower_content, PASSWORD_ERROR_PATTERNS):
                    add_entry_to_json(
                        "V2.1.7",
                        "Password Security",
                        "User password accept one of the 1000 most common passwords"
                    )
                    vuln_list.append(["Password Security", "Password accept one of the 1000 most common passwords"])
                    return vuln_list
    return vuln_list
