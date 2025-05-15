# file_security.py
import asyncio
import os
import re
import tempfile
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from json_edit import add_entry_to_json
import constants
import logging

logger = logging.getLogger(__name__)

async def _generate_tmp(size_bytes: int) -> str:
    """Crée un fichier temporaire de size_bytes octets et renvoie son chemin."""
    fd, path = tempfile.mkstemp(suffix=".bin")
    os.write(fd, b"A" * size_bytes)
    os.close(fd)
    return path

async def _upload_once(browser, url: str, file_path: str, timeout_ms: int = 30_000) -> int:
    page = await browser.newPage()

    # ─── Listeners réseau (inchangés) ───────────────────────────────
    def _on_request(request):
        logger.debug("▶ REQ ➜ %s %s", request.method, request.url)
        asyncio.create_task(request.continue_())

    def _on_response(response):
        logger.debug("◀ RES « %d » %s", response.status, response.url)

    await page.setRequestInterception(True)
    page.on("request", _on_request)
    page.on("response", _on_response)

    try:
        # 0) Ouvre la page
        logger.info("▶️  Ouvrir la page d'upload : %s", url)
        await page.goto(url, waitUntil="load", timeout=timeout_ms)

        # 1) Sélecteur du champ file
        logger.info("📁  Recherche de l’input file (#file)…")
        await page.waitForSelector("#file", timeout=timeout_ms)
        handle = await page.querySelector("#file")
        if handle:
            logger.info("✅  Input file trouvé : %r", handle)
        else:
            logger.error("❌  Input file introuvable !")
            return -1

        # 2) upload du fichier dans ce champ
        logger.info("📂  uploadFile('%s')", file_path)
        await handle.uploadFile(file_path)
        logger.info("✓  Fichier chargé dans l’input")

        # 3) Préparation de l’écoute POST /file/upload
        logger.info("🎧  Installation du listener pour POST /file/upload")
        post_future = page.waitForResponse(lambda resp: resp.request.method == "POST" and "/file/upload" in resp.url,timeout=timeout_ms)

        # 4) Recherche du bouton Upload
        logger.info("🔍  Recherche du bouton “Upload” par texte…")
        btns = await page.xpath("//button[normalize-space(text())='Upload']")
        if not btns:
            logger.error("❌  Bouton Upload introuvable !")
            return -1
        upload_btn = btns[0]
        logger.info("✅  Bouton Upload trouvé : %r", upload_btn)

        # 5) Clic + attente de la réponse
        logger.info("👆  Clic sur Upload et attente de la réponse…")
        await asyncio.gather(
            upload_btn.click(),
            #post_future
        )

        # 6) Lecture du code HTTP
        resp = await post_future
        logger.info("✅  Serveur a répondu : HTTP %d", resp.status)
        return resp.status

    except asyncio.TimeoutError:
        logger.error("⏰  Timeout en attente du POST /file/upload")
        return -1

    except Exception as e:
        logger.exception("💥  Erreur pendant l’upload : %s", e)
        return -1

    finally:
        await page.close()


async def check_asvs_l1_file_upload_V12_1_1(vuln_list, upload_url, browser, small_kb=4, big_mb=25):
    """
    Orchestration du test ASVS V12.1.1 :
      - Upload d'un petit fichier (ok si status<400)
      - Upload d'un gros fichier (doit être refusé, status>=400)
    """
    # Génère deux tailles de fichiers
    tmp_small = await _generate_tmp(small_kb * 1024)
    tmp_big   = await _generate_tmp(big_mb   * 1024 * 1024)

    try:
        # Ignore si l'URL n'est pas un endpoint d'upload
        if "upload" not in upload_url:
            return vuln_list

        # Lance les deux essais
        status_small = await _upload_once(browser, upload_url, tmp_small)
        status_big   = await _upload_once(browser, upload_url, tmp_big)

        small_ok   = 0 <= status_small < 400
        big_reject = status_big >= 400

        # Si le petit passe et le gros est accepté => vulnérabilité
        if small_ok and not big_reject:
            await add_entry_to_json(
                "V12.1.1",
                "File Upload",
                f"Large file ({big_mb} MB) accepted – no size limit"
            )
            vuln_list.append([
                "File Upload",
                f"V12.1.1 large file ({big_mb} MB) accepted"
            ])

        return vuln_list

    finally:
        # Nettoyage des fichiers
        for p in (tmp_small, tmp_big):
            if os.path.exists(p):
                os.remove(p)