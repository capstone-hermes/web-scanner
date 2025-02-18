import requests
import asyncio
import aiohttp
import async_timeout
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
        logging.FileHandler("scanner.log"),  # les logs seront écrits dans ce fichier
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def fetch_page(session, url):
    try:
        response = session.get(url, headers=HEADERS, timeout=20)
        if response.status_code != 200:
            logger.error(f"Échec de la récupération de la page. Code : {response.status_code}")
            return None
        logger.info(f"Page récupérée avec succès : {url}")
        return response
    except requests.RequestException as e:
        logger.error(f"Erreur lors de la récupération de la page {url} : {e}")
        return None

def process_forms(vuln_list, forms, url, session):
    for form in forms:
        inputs = form.find_all('input')
        for input_field in inputs:
            input_name = input_field.get('name', '')
            input_type = input_field.get('type', 'text')
            for function_check in function_check_list:
                vuln_list = function_check(vuln_list, url, input_name, input_type)
    return vuln_list

async def fetch_async(session, url):
    try:
        # On fixe un délai maximum pour la requête (20 secondes)
        async with async_timeout.timeout(20):
            # On envoie la requête de façon asynchrone
            async with session.get(url, headers=HEADERS) as response:
                # Si la réponse est bonne, on retourne le contenu (texte) de la page
                if response.status == 200:
                    return await response.text()
                else:
                    logger.error(f"Échec de la récupération asynchrone de la page {url}. Code: {response.status}")
                    return None
    except Exception as e:
        logger.error(f"Erreur lors de la récupération asynchrone de {url}: {e}")
        return None


async def get_internal_links_async(start_url, max_pages=100, max_depth=3, batch_size=10):
    domain = urlparse(start_url).netloc
    visited = set()  # Ensemble pour mémoriser les URLs déjà visitées
    queue = deque([(start_url, 0)])  # File avec des tuples (URL, profondeur)

    # Création d'une session HTTP asynchrone
    async with aiohttp.ClientSession() as session:
        while queue and len(visited) < max_pages:
            batch = []
            # Rassembler un lot d'URLs à traiter (jusqu'à batch_size)
            while queue and len(batch) < batch_size:
                url_item = queue.popleft()
                if url_item[0] in visited or url_item[1] > max_depth:
                    continue
                batch.append(url_item)
            if not batch:
                continue

            # Exécuter en parallèle les requêtes asynchrones pour le lot d'URLs
            tasks = [fetch_async(session, url) for url, depth in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Traiter chaque résultat obtenu pour le lot
            for idx, (url, depth) in enumerate(batch):
                html = results[idx]
                if html is None:
                    continue
                visited.add(url)  # Marquer l'URL comme visitée
                soup = BeautifulSoup(html, "html.parser")
                for link in soup.find_all("a", href=True):
                    new_url = urljoin(url, link["href"])
                    parsed_url = urlparse(new_url)
                    # Ajouter seulement les liens internes non visités
                    if parsed_url.netloc == domain and new_url not in visited:
                        queue.append((new_url, depth + 1))
    return list(visited)


def process_url(url):
    clear_json()
    if not url.startswith("https://"):
        url = "https://" + url

    # Utilisation du nouveau crawler asynchrone avec limites
    try:
        links = asyncio.run(get_internal_links_async(url, max_pages=100, max_depth=3, batch_size=10))
    except Exception as e:
        logger.error(f"Erreur lors du crawling asynchrone: {e}")
        return 1

    if not links:
        logger.error("Aucun lien interne n'a pu être récupéré.")
        return 1

    vuln_list = []

    # Enregistrement de la première URL scannée dans le JSON
    set_json(links[0])
    session = requests.Session()
    session.get(url)
    for link in links:
        response = fetch_page(session, link)
        if not response:
            continue  # On passe au lien suivant si la page n'a pas pu être récupérée

        add_link_to_json(link)

        HTML_soup = BeautifulSoup(response.text, 'html.parser')
        forms = HTML_soup.find_all('form')
        constants.HAS_CAPTCHA = check_for_captcha(response, HTML_soup)

        for function_check in function_list:
            vuln_list = function_check(vuln_list, link, session)

        # Analyse des formulaires
        vuln_list = process_forms(vuln_list, forms, link, session)

    logger.info(f"Vulnérabilités détectées : {vuln_list}")
    return 0

#############################################################################
## Fonctions de scan pour les vulnérabilités
#############################################################################

def check_parameters(url):
    parsed_url = urlparse(url)
    return bool(parsed_url.query)

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

# Listes des fonctions de scan à exécuter

function_check_list = []

function_list = [
    check_asvs_l1_password_security_V2_1_1, 
    check_asvs_l1_password_security_V2_1_2,
]
