import json
import os
from pathlib import Path
from datetime import datetime
from constants import *

#############################################################################
## Initialiser ou Modifier le JSON
#############################################################################

async def set_json(url):
    async with JSON_LOCK:
        data = {
            "data": {
                "url": url,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "findings": []
            }
        }

        with open(JSONNAME, 'w') as file:
            json.dump(data, file, indent=4)

#############################################################################
## Ajouter une vulnérabilité dans findings[]
## Args: name (str): ID de l'entrée ASVS (ex: "2.1.1")
##       found_in (str): chapitre (ex: "Authentication")
##       info (str): description de la faille
#############################################################################

async def add_entry_to_json(name, found_in, info):
    async with JSON_LOCK:
        if not Path(JSONNAME).is_file():
            raise FileNotFoundError("JSON file not initialized. Call set_json(url) first.")

        with open(JSONNAME, 'r') as file:
            data = json.load(file)

        new_finding = {
            "id": name,
            "chapter": "", # champ vide par défaut
            "section": found_in or "",
            "description": info or "",
            "url": ""       # champ vide par défaut
        }

        data["data"]["findings"].append(new_finding)

        with open(JSONNAME, 'w') as file:
            json.dump(data, file, indent=4)

#############################################################################
## Ajouter un lien (deprecated si on utilise findings.url)
## Conservé si nécessaire pour compatibilité future
#############################################################################

async def add_link_to_json(link):
    async with JSON_LOCK:
        if not Path(JSONNAME).is_file():
            raise FileNotFoundError("JSON file not initialized. Call set_json(url) first.")

        with open(JSONNAME, 'r') as file:
            data = json.load(file)

        # Ajoute un finding générique avec uniquement l’URL si besoin
        # (déprécié si on utilise findings.url) Donc on le garde pour compatibilité future
        # data["data"]["findings"].append({
        #     "id": "",
        #     "chapter": "",
        #     "section": "",
        #     "description": "",
        #     "url": link
        # })

        with open(JSONNAME, 'w') as file:
            json.dump(data, file, indent=4)

        return True

#############################################################################
## Supprimer le fichier JSON existant
#############################################################################

async def clear_json():
    async with JSON_LOCK:
        if Path(JSONNAME).is_file():
            os.remove(JSONNAME)


#############################################################################
## Enlever les clones dans le JSON
#############################################################################

async def deduplicate_json():
    async with JSON_LOCK:
        if not Path(JSONNAME).is_file():
            raise FileNotFoundError("JSON file not initialized. Call set_json(url) first.")
        with open(JSONNAME, 'r') as file:
            data = json.load(file)

        if "data" in data and "findings" in data["data"]:
            findings = data["data"]["findings"]
            cleared_findings = {}
            for finding in findings:
                fid = finding.get("id")
                if fid and fid not in cleared_findings:
                    cleared_findings[fid] = finding
            data["data"]["findings"] = list(cleared_findings.values())

        with open(JSONNAME, 'w') as file:
            json.dump(data, file, indent=4)