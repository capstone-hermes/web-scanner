import asyncio
from pyppeteer import launch
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from collections import deque
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

async def get_internal_links_async(start_url, browser, max_pages=100, max_depth=3, batch_size=10):
    """
    Effectue un crawling asynchrone en utilisant pyppeteer pour récupérer les pages et en extraire les liens internes.
    """
    domain = urlparse(start_url).netloc
    visited = set()
    queue = deque([(start_url, 0)])

    # replace to have visual demo
    # browser = await launch(headless=False, slowMo=10, executablePath=constants.BROWSER_EXECUTABLE_PATH)

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
    return list(visited)

async def fetch_async_pyppeteer(browser, url):
    """
    Récupère la page via pyppeteer en ouvrant une nouvelle page dans le navigateur.
    """
    try:
        page = await browser.newPage()
        response = await page.goto(url, timeout=20_000, waitUntil="networkidle2")
        if response is None or response.status != 200:
            logger.error(f"Échec de la récupération asynchrone de la page {url}. Code: {response.status if response else 'Aucune réponse'}")
            return None
        html = await page.content()
        logger.info(f"Page récupérée avec succès : {url}")
        return html
    except Exception as e:
        logger.error(f"Erreur lors de la récupération asynchrone de {url} : {e}")
        return None
    finally:
        await page.close()

async def get_links_as_user(start_url, page, max_pages=100, max_depth=3, timeout=60.0):
    """
    Crawl internal links using the same authenticated page instance.
    """
    parsed = urlparse(start_url)
    domain = parsed.netloc

    visited = set()
    queue = deque([(start_url, 0)])
    deadline = asyncio.get_event_loop().time() + timeout

    while queue and len(visited) < max_pages:
        if asyncio.get_event_loop().time() > deadline:
            logger.warning("get_links_as_user timed out after %.1fs", timeout)
            break

        url, depth = queue.popleft()
        if url in visited or depth > max_depth:
            continue

        try:
            resp = await page.goto(url, timeout=20_000, waitUntil="networkidle2")
        except Exception as e:
            logger.debug("Skipping %s: %s", url, e)
            continue

        status = getattr(resp, "status", None)
        if status != 200:
            logger.debug("Non-200 (%s) at %s", status, url)
            continue

        visited.add(url)
        html = await page.content()
        soup = BeautifulSoup(html, "html.parser")
        for a in soup.find_all("a", href=True):
            href = a["href"].split("#", 1)[0]
            new_url = urljoin(url, href)
            p = urlparse(new_url)
            if p.netloc == domain and new_url not in visited:
                queue.append((new_url, depth + 1))

    return list(visited)
