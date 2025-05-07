import asyncio
from pyppeteer import launch
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from collections import deque
from password_security import *
from links import *
import constants as constants
from json_edit import *
import logging

# Configuration du logger
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("scanner.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

async def fetch_async_pyppeteer(browser, url):
    """
    Récupère la page via pyppeteer en ouvrant une nouvelle page dans le navigateur.
    """
    try:
        page = await browser.newPage()
        response = await page.goto(url, timeout=20_000, waitUntil="networkidle2")
        if response is None or response.status != 200:
            logger.error(f"Échec de la récupération asynchrone de la page {url}. Code: {response.status if response else 'Aucune réponse'}")
            await page.close()
            return None
        html = await page.content()
        await page.close()
        logger.info(f"Page récupérée avec succès : {url}")
        return html
    except Exception as e:
        logger.error(f"Erreur lors de la récupération asynchrone de {url} : {e}")
        return None

def check_for_captcha(HTML_soup):
    captcha_keywords = ["captcha", "g-recaptcha", "h-captcha", "grecaptcha", "verify you're human"]

    if any(keyword in HTML_soup.text.lower() for keyword in captcha_keywords):
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

def check_for_identification(HTML_soup):
     """
     Vérifie si la page contient des éléments indiquant une identification ou un formulaire d'authentification.
     Retourne True si trouvé, sinon False.
     """
     if HTML_soup.find("input", {"type": "password"}):
         return True
 
     identification_keywords = [
         "username", "email", "e-mail", "mail", "name", "id"
     ]
     for input_field in HTML_soup.find_all("input"):
         input_name = input_field.get("name", "").lower()
         for keyword in identification_keywords:
             if keyword in input_name:
                 return True
     return False

async def deduplicate_vuln_list(vuln_list):
    """
    Fonction qui supprime les clones dans vuln_list.
    """
    checked_tuple = set()
    cleared_list = []
    for vuln in vuln_list:
        vuln_tuple = tuple(vuln)
        if vuln_tuple not in checked_tuple:
            checked_tuple.add(vuln_tuple)
            cleared_list.append(vuln)
    return cleared_list


async def process_url(url):
    """
    Fonction principale qui :
        nettoie le JSON,
        effectue le crawling des liens internes,
        pour chaque URL récupérée, charge la page via pyppeteer,
        analyse la page (formulaires, captcha, etc.) et exécute les fonctions de scan.
    """
    await clear_json()
    if "http://localhost" in url:
        url = url.replace("localhost", "host.docker.internal")
        index = url.find("host.docker.internal")
        actual_index = index + len("host.docker.internal")
        url = url[:actual_index]
    if not url.startswith("https://") and not url.startswith("http://"):
        url = "https://" + url
    if not url.endswith("/"):
        url = url + "/"

    # replace to have visual demo
    # browser = await launch(headless=False, slowMo=10, executablePath=constants.BROWSER_EXECUTABLE_PATH)
    browser = await launch(headless=True, handleSIGINT=False, handleSIGTERM=False, handleSIGHUP=False, executablePath=constants.BROWSER_EXECUTABLE_PATH, args=[
            '--no-sandbox',  # necessary when running as root in Docker
            '--disable-setuid-sandbox'
        ])
    try:
        links = await get_internal_links_async(url, browser, max_pages=100, max_depth=3, batch_size=10)
    except Exception as e:
        logger.error(f"Erreur lors du crawling asynchrone: {e}")
        return 1

    
    if not links:
        logger.error("Aucun lien interne n'a pu être récupéré.")
        return 1
    
    vuln_list = []
    await set_json(links[0])
    
    try:
        for link in links:
            html = await fetch_async_pyppeteer(browser, link)
            if not html:
                continue
            await add_link_to_json(link)
            soup = BeautifulSoup(html, 'html.parser')
            constants.HAS_CAPTCHA = check_for_captcha(soup)
            constants.HAS_INDENTIFICATION = check_for_identification(soup)
            
            for fct in function_list:
                try:
                    single = await asyncio.wait_for(fct(vuln_list, link, browser), timeout=15)
                    if isinstance(single, Exception):
                        logger.error("check %s error: %s", fct.__name__, single)
                    else:
                        for v in single:
                            if v not in vuln_list:
                                vuln_list.append(v)
                except asyncio.TimeoutError:
                    logger.warning("check %s on %s timed out", fct.__name__, link)
                except Exception as e:
                    logger.exception("check %s on %s failed", fct.__name__, link)
    finally:
        await browser.close()
        await deduplicate_json()
        vuln_list = await deduplicate_vuln_list(vuln_list)
        logger.info(f"Vulnérabilités détectées : {vuln_list}")
        return 0

# Listes des fonctions de scan à exécuter

function_check_list = []

function_list = [
    check_asvs_l1_password_security_V2_1_1,
    check_asvs_l1_password_security_V2_1_2,
    check_asvs_l1_password_security_V2_1_3,
    check_asvs_l1_password_security_V2_1_4,
    check_asvs_l1_password_security_V2_1_5,
##    check_asvs_l1_password_security_V2_1_7
    check_asvs_l1_password_security_V2_1_8,
    check_asvs_l1_password_security_V2_1_9,
##    check_asvs_l1_password_security_V2_1_11,
    check_asvs_l1_password_security_V2_1_12
]
