import asyncio
from pyppeteer import launch
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from collections import deque
from password_security import *
from constants import *
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
        response = await page.goto(url, {'timeout': 20000})
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

async def get_internal_links_async(start_url, max_pages=100, max_depth=3, batch_size=10):
    """
    Effectue un crawling asynchrone en utilisant pyppeteer pour récupérer les pages et en extraire les liens internes.
    """
    domain = urlparse(start_url).netloc
    visited = set()
    queue = deque([(start_url, 0)])

    browser = await launch(headless=True, executablePath=constants.BROWSER_EXECUTABLE_PATH, args=[
            '--no-sandbox',  # necessary when running as root in Docker
            '--disable-setuid-sandbox'
        ])
    while queue and len(visited) < max_pages:
        batch = []
        while queue and len(batch) < batch_size:
            url_item = queue.popleft()
            if url_item[0] in visited or url_item[1] > max_depth:
                continue
            batch.append(url_item)
        if not batch:
            continue

        tasks = [fetch_async_pyppeteer(browser, url) for url, _ in batch]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for idx, (url, depth) in enumerate(batch):
            html = results[idx]
            if html is None:
                continue
            visited.add(url)
            soup = BeautifulSoup(html, "html.parser")
            for link in soup.find_all("a", href=True):
                new_url = urljoin(url, link["href"])
                parsed_url = urlparse(new_url)
                if parsed_url.netloc == domain and new_url not in visited:
                    queue.append((new_url, depth + 1))
    await browser.close()
    return list(visited)

async def process_forms(vuln_list, forms, url, browser):
    """
    Parcours les formulaires d'une page et exécute pour chacun les vérifications fournies dans function_check_list.
    (Les fonctions de scan doivent être adaptées pour être awaitables si elles réalisent des appels réseau.)
    """
    for form in forms:
        inputs = form.find_all('input')
        for input_field in inputs:
            input_name = input_field.get('name', '')
            input_type = input_field.get('type', 'text')
            for function_check in function_check_list:
                vuln_list = await function_check(vuln_list, url, input_name, input_type)
    return vuln_list

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

async def process_url(url):
    """
    Fonction principale qui :
        nettoie le JSON,
        effectue le crawling des liens internes,
        pour chaque URL récupérée, charge la page via pyppeteer,
        analyse la page (formulaires, captcha, etc.) et exécute les fonctions de scan.
    """
    await clear_json()
    if not url.startswith("https://") or not url.startswith("http://"):
        url = "https://" + url
    if not url.endswith("/"):
        url = url + "/"

    try:
        links = await get_internal_links_async(url, max_pages=100, max_depth=3, batch_size=10)
    except Exception as e:
        logger.error(f"Erreur lors du crawling asynchrone: {e}")
        return 1

    if not links:
        logger.error("Aucun lien interne n'a pu être récupéré.")
        return 1

    vuln_list = []
    await set_json(links[0])

    browser = await launch(headless=True, executablePath=constants.BROWSER_EXECUTABLE_PATH, args=[
            '--no-sandbox',  # necessary when running as root in Docker
            '--disable-setuid-sandbox'
        ])
    for link in links:
        html = await fetch_async_pyppeteer(browser, link)
        if not html:
            continue
        await add_link_to_json(link)
        soup = BeautifulSoup(html, 'html.parser')
        constants.HAS_CAPTCHA = check_for_captcha(soup)
        constants.HAS_INDENTIFICATION = check_for_identification(soup)
        
        tasks = [function_check(vuln_list, link) for function_check in function_list]
        functions = await asyncio.gather(*tasks, return_exceptions=True)

        for function_result in functions:
            if isinstance(function_result, Exception):
                logger.error(f"Error in function check: {function_result}")
            else:
                for vuln in function_result:
                    if vuln not in vuln_list:
                        vuln_list.append(vuln)

        # Process forms as before.
        vuln_list = await process_forms(vuln_list, soup.find_all('form'), link, browser)
    await browser.close()
    logger.info(f"Vulnérabilités détectées : {vuln_list}")
    return 0

# Listes des fonctions de scan à exécuter

function_check_list = []

function_list = [
    check_asvs_l1_password_security_V2_1_1, 
    check_asvs_l1_password_security_V2_1_2,
    check_asvs_l1_password_security_V2_1_3,
    check_asvs_l1_password_security_V2_1_4,
##    check_asvs_l1_password_security_V2_1_7
    check_asvs_l1_password_security_V2_1_8
]
