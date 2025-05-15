import asyncio
import json
import re
from urllib.parse import urljoin, urlencode
from bs4 import BeautifulSoup
import constants
from json_edit import add_entry_to_json
import logging
from pyppeteer import launch
from links import get_links_as_user
from urllib.parse import urlparse

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
        await page.goto(url, timeout=5_000, waitUntil="networkidle2")
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

async def attempt_signup(url, test_data, page):
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
        logger.info(f"Accès à {url}...")
    
        def _on_request(request):
            logger.debug("▶ REQ ➜ %s %s", request.method, request.url)
            asyncio.create_task(request.continue_())

        def _on_response(response):
            logger.debug("◀ RES « %d » %s", response.status, response.url)

        await page.setRequestInterception(True)
        page.on("request", _on_request)
        page.on("response", _on_response)

        await page.goto(url, timeout=5_000, waitUntil="networkidle2")

        # Recherche des formulaires sur la page
        forms = await page.querySelectorAll("form")
        login_form = None
        for form in forms:
            if await form.querySelector("input[type='password']"):
                login_form = form
                break
        if not login_form:
            logger.error("Aucun formulaire trouvé sur la page.")
            return None, None, page

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
        
        try:
            response = await page.waitForResponse({'timeout': 5000, 'waitUntil': 'networkidle2'})
            status = response.status
        finally:
            status = 201
            await asyncio.sleep(5)

        content = await page.content()
        logger.info(f"Page returned status : {status}")
        return content, status, page
##    except asyncio.TimeoutError:
##        logger.error(f"Timeout lors de l'inscription")
##        return None, None, page
    except Exception as e:
        logger.error(f"Erreur lors de l'inscription: {e}")
        return None, None, page



async def check_asvs_l1_password_security_V2_1_1(vuln_list, url, browser):
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

    page = await browser.newPage()
    content, status, page = await attempt_signup(url, test_data, page)
    if status and status >= 400:
        return vuln_list
    if content:
        lower_content = content.lower()
        if (lower_content and not validate_password_policy(lower_content, PASSWORD_ERROR_PATTERNS)) or (status and status < 400):
            await add_entry_to_json(
                "V2.1.1",
                "Password Security",
                "User password isn't required to be at least 12 characters in length"
            )
            vuln_list.append(["Password Security", "Password accepted with fewer than 12 characters"])
    await page.close()
    return vuln_list

async def check_asvs_l1_password_security_V2_1_2(vuln_list, url, browser):
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

    page = await browser.newPage()
    content, status, page = await attempt_signup(url, test_data, page)
    if status and status >= 400:
        return vuln_list
    if content:
        lower_content = content.lower()
        if (lower_content and not validate_password_policy(lower_content, PASSWORD_ERROR_PATTERNS)) or (status and status < 400):
            await add_entry_to_json(
                "V2.1.2",
                "Password Security",
                "User password is allowed with more than 128 characters"
            )
            vuln_list.append(["Password Security", "Password accepted with more than 128 characters"])
            await page.close()
            return vuln_list

    long_password = "l8(szc?F*~x5[1u3><IOY6yq}N$Si*cG<ledceq5_è(lhtiER^$3Y9@D6le^!9bP"
    test_data = {
        "username": "2aHERMEStest",
        "email": "2aASVSHermesTest@gmail.com",
        "password": long_password,
        "confirm_password": long_password
    }

    await page.close()
    page = await browser.newPage()
    content, status, page = await attempt_signup(url, test_data, page)
    if status and status >= 400:
        return vuln_list
    if content:
        lower_content = content.lower()
        if (lower_content and not validate_password_policy(lower_content, PASSWORD_ERROR_PATTERNS)) or (status and status < 400):
            await add_entry_to_json(
                "V2.1.2",
                "Password Security",
                "User password isn't allowed with more than 64 characters"
            )
            vuln_list.append(["Password Security", "Password isn't accepted with more than 64 characters"])
    await page.close()
    return vuln_list

async def check_asvs_l1_password_security_V2_1_3(vuln_list, url, browser):
    """
    Vérifie si le mot de passe est tronqué
    """
    if constants.HAS_CAPTCHA or not constants.HAS_INDENTIFICATION:
        return vuln_list

    long_password = "@bcdefghijklmn0pqrstuvwxyzabcdefGhijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwx"
    test_data = {
        "username": "3HERMEStest",
        "email": "3ASVSHermesTest@gmail.com",
        "password": long_password,
        "confirm_password": long_password
    }

    page = await browser.newPage()
    content, status, page = await attempt_signup(url, test_data, page)
    if status and status >= 400:
        return vuln_list

    shorter_password = "@bcdefghijklmn0pqrstuvwxyzabcdefGhijklmnopqrstuvwxyzabcdefghijklmnopqrst"
    test_data = {
        "username": "3HERMEStest",
        "email": "3ASVSHermesTest@gmail.com",
        "password": shorter_password,
        "confirm_password": shorter_password
    }

    page = await browser.newPage()
    content, status, page = await attempt_signup(url, test_data, page)
    if content:
        lower_content = content.lower()
        created_account_keywords = ["account created", "successfully", "success"]
        if (lower_content and any(keyword in lower_content for keyword in created_account_keywords)) or (status and status >= 400):
            return vuln_list
        if (lower_content and not validate_password_policy(lower_content, PASSWORD_ERROR_PATTERNS)) or (status and status < 400):
            await add_entry_to_json(
                "V2.1.3",
                "Password Security",
                "User password truncation is performed and accepted"
            )
            vuln_list.append(["Password Security", "Password truncation is performed and accepted"])
    await page.close()
    return vuln_list

async def check_asvs_l1_password_security_V2_1_4(vuln_list, url, browser):
    """
    Vérifie si un mot de passe accepte des charactère unicode ainsi que des emojis
    """
    if constants.HAS_CAPTCHA or not constants.HAS_INDENTIFICATION:
        return vuln_list

    weird_password = "☺☺☺🤖☻♥♦♣♠•◘○♦😁😎"
    test_data = {
        "username": "4HERMEStest",
        "email": "4ASVSHermesTest@gmail.com",
        "password": weird_password,
        "confirm_password": weird_password
    }

    page = await browser.newPage()
    content, status, page = await attempt_signup(url, test_data, page)
    if content:
        if (status and status < 400):
            return vuln_list
        lower_content = content.lower()
        already_existing_user_keywords = ["exists", "already", "taken"]
        if lower_content and any(keyword in lower_content for keyword in already_existing_user_keywords):
            return vuln_list
        if (lower_content and validate_password_policy(lower_content, PASSWORD_ERROR_PATTERNS)) or (status and status >= 400):
            await add_entry_to_json(
                "V2.1.4",
                "Password Security",
                "User password doesn't accept unicode and emojis"
            )
            vuln_list.append(["Password Security", "Password doesn't accept unicode and emojis"])
    await page.close()
    return vuln_list

## check_asvs_l1_password_security_V2_1_5 doit pouvoir vérifier si un utilisateur peut modifier son mot de passe

async def check_asvs_l1_password_security_V2_1_5(vuln_list, url, browser):
    """
    Vérifie si un mot de passe est changeable une fois connecté
    """
    if constants.HAS_CAPTCHA or not constants.HAS_INDENTIFICATION:
        return vuln_list

    password = "Elev3nwr@ngG0Rr1Ght"
    test_data = {
        "username": "5HERMEStest",
        "email": "5ASVSHermesTest@gmail.com",
        "password": password,
        "confirm_password": password
    }

    page = await browser.newPage()
    content, status, page = await attempt_signup(url, test_data, page)
    links = await get_links_as_user(url, page)
    for link in links:
        print(link)
    await page.close()
    return vuln_list
    if status and status >= 400:
        return vuln_list
    if content:
        lower_content = content.lower()
        if (lower_content and not validate_password_policy(lower_content, PASSWORD_ERROR_PATTERNS)) or (status and status < 400):
            await add_entry_to_json(
                "V2.1.5",
                "Password Security",
                "User password can't be changed after login"
            )
            vuln_list.append(["Password Security", "User password can't be changed after login"])
    await page.close()
    return vuln_list

## check_asvs_l1_password_security_V2_1_6 doit pouvoir vérifier que le changement de mot de passe demande l'ancien mot de passe

async def check_asvs_l1_password_security_V2_1_7(vuln_list, url, browser):
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
            page = await browser.newPage()
            content, status, page = await attempt_signup(url, test_data, page)
            if status and status >= 400:
                return vuln_list
            if content:
                lower_content = content.lower()
                if (lower_content and not validate_password_policy(lower_content, PASSWORD_ERROR_PATTERNS)) or (status and status < 400):
                    await add_entry_to_json(
                        "V2.1.7",
                        "Password Security",
                        "User password accepts one of the 1000 most common passwords"
                    )
                    vuln_list.append(["Password Security", "Password accepts one of the 1000 most common passwords"])
                    await page.close()
                    return vuln_list
    await page.close()
    return vuln_list

def check_login_button(content):
    """
    Check if the content contains a submit button (or similar) with login keywords
    Args: content (str): The HTML content of a page
    Returns: bool: True if a login-like submit button is found, False otherwise
    """
    soup = BeautifulSoup(content, 'html.parser')

    login_keywords = ["login", "log in", "sign in", "signin", "connexion", "sign-in", "log-in"]
    for button in soup.find_all('button'):
        text = button.get_text().strip().lower()
        if any(keyword in text for keyword in login_keywords):
            return True

    for input_elem in soup.find_all('input'):
        input_type = input_elem.get('type', '').lower()
        if input_type in ['submit', 'button']:
            value = input_elem.get('value', '').lower()
            if any(keyword in value for keyword in login_keywords):
                return True
    return False

async def check_asvs_l1_password_security_V2_1_8(vuln_list, url, browser):
    """
    Vérifie si le mot de passe a une aide pour montrer a l'utilisateur a quel point celui-ci est sécurisé
    """
    if constants.HAS_CAPTCHA or not constants.HAS_INDENTIFICATION:
        return vuln_list

    page = await browser.newPage()
    try:
        await page.goto(url, timeout=20_000, waitUntil="networkidle2")
        content = await page.content()
        if content:
            lower_content = content.lower()
            if check_login_button(content):
                return vuln_list
            meter_keywords = ["#strength-meter", ".password-strength", ".meter", "[data-strength]"]
            if lower_content and not any(keyword in lower_content for keyword in meter_keywords):
                await add_entry_to_json(
                    "V2.1.8",
                    "Password Security",
                    "There is no password strenght meter to help the user"
                )
                vuln_list.append(["Password Security", "There is no password strenght meter to help the user"])
        return vuln_list
    except Exception as e:
        logger.error(f"Error in check V2.1.8: {e}")
        return vuln_list
    finally:
        await page.close()

async def check_asvs_l1_password_security_V2_1_9(vuln_list, url, browser):
    """
    Vérifie si la politique de mot de passe force un choix de charactères speciaux, chiffre, ou majuscule pour créer celui-ci
    """
    if constants.HAS_CAPTCHA or not constants.HAS_INDENTIFICATION:
        return vuln_list

    page = await browser.newPage()
    try:
        await page.goto(url, timeout=20_000, waitUntil="networkidle2")
        content = await page.content()
        if content:
            lower_content = content.lower()
            if check_login_button(content):
                return vuln_list
            unsafe_password = "hellothisishermes"
            test_data = {
                "username": "9HERMEStest",
                "email": "9ASVSHermesTest@gmail.com",
                "password": unsafe_password,
                "confirm_password": unsafe_password
            }
            page = await browser.newPage()
            content, status, page = await attempt_signup(url, test_data, page)
            if status and status < 400:
                return vuln_list
            if (lower_content and validate_password_policy(lower_content, PASSWORD_ERROR_PATTERNS)) or (status and status >= 400):
                await add_entry_to_json(
                    "V2.1.9",
                    "Password Security",
                    "There should be no requirement for upper or lower case or numbers or special characters"
                )
                vuln_list.append(["Password Security", "There should be no requirement for upper or lower case or numbers or special characters"])
        return vuln_list
    except Exception as e:
        logger.error(f"Error in check V2.1.9: {e}")
        return vuln_list
    finally:
        await page.close()

async def check_asvs_l1_password_security_V2_1_11(vuln_list, url, browser):
    """
    Vérifie si le mot de passe accepte la fonction "coller" ainsi que les "password helpers" sont acceptés
    """
    if constants.HAS_CAPTCHA or not constants.HAS_INDENTIFICATION:
        return vuln_list

    page = await browser.newPage()
    try:
        await page.goto(url, timeout=20_000, waitUntil="networkidle2")
        await page.focus('input[type="password"]')
        passwd2111 = "Elev3nwr@ngG"
        result = await page.evaluate(
            """
            (passwd2111) => {
                const input = document.querySelector('input[type="password"]');
                if (!input) {
                    console.error("No password field found");
                    return;
                }
                const dataTransfer = new DataTransfer();
                dataTransfer.setData('text/plain', passwd2111);
                let pasteEvent;
                try {
                    pasteEvent = new ClipboardEvent('paste', {
                        clipboardData: dataTransfer,
                        bubbles: true,
                        cancelable: true
                    });
                } catch(e) {
                    pasteEvent = new Event('paste', { bubbles: true, cancelable: true });
                    pasteEvent.clipboardData = dataTransfer;
                }
                const isPasteAllowed = input.dispatchEvent(pasteEvent);
                if (isPasteAllowed) input.value = passwd2111;
                return {isPasteAllowed, value: input.value};
            }
        """, passwd2111)

        if (result['isPasteAllowed'] is False) or result['value'] is not passwd2111:
            await add_entry_to_json(
                "V2.1.11",
                "Password Security",
                "The password cannot be pasted from the clipboard"
            )
            vuln_list.append(["Password Security", "The password cannot be pasted from the clipboard"])
        return vuln_list
    except Exception as e:
        logger.error(f"Error in check V2.1.11: {e}")
        return vuln_list
    finally:
        await page.close()

def can_see_password(content):
    """
    Check if the HTML contains a password input field with an associated toggle control to show/hide the password
    Args: content (str): The HTML content of a page
    Returns: bool: True if a toggle control is likely present, False otherwise
    """
    soup = BeautifulSoup(content, 'html.parser')
    password_input = soup.find('input', {'type': 'password'})
    if not password_input:
        return False

    toggle_indicators = ["toggle-password", "show-password", "password-toggle", "fa-eye", "fa-eye-slash", "toggleVisibility"]
    for element in soup.find_all(True):
        classes = element.get('class', [])
        element_id = element.get('id', '').lower()
        if any(indicator in element_id for indicator in toggle_indicators):
            return True
        if any(any(indicator in cls.lower() for indicator in toggle_indicators) for cls in classes):
            return True
    return False

async def check_asvs_l1_password_security_V2_1_12(vuln_list, url, browser):
    """
    Vérifie si le mot de passe a une aide pour montrer sa force a l'utilisateur
    """
    if constants.HAS_CAPTCHA or not constants.HAS_INDENTIFICATION:
        return vuln_list

    page = await browser.newPage()
    try:
        await page.goto(url, timeout=20_000, waitUntil="networkidle2")
        content = await page.content()
        if content:
            lower_content = content.lower()
            if lower_content and not can_see_password(content):
                await add_entry_to_json(
                    "V2.1.12",
                    "Password Security",
                    "The password cannot be shown nor viewed"
                )
                vuln_list.append(["Password Security", "The password cannot be shown nor viewed"])
        return vuln_list
    except Exception as e:
        logger.error(f"Error in check V2.1.12: {e}")
        return vuln_list
    finally:
        await page.close()