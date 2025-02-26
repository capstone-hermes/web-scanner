import json
import os
from pathlib import Path
from constants import *

#############################################################################
## Modifying and Writing entries in the json file
#############################################################################

def set_json(url):
    if Path(JSONNAME).is_file():
        with open(JSONNAME, 'r') as file:
            data = json.load(file)
    else:
        data = []

    start_entry = {
        "URL_scanned": url
    }
    data.append(start_entry)
    with open(JSONNAME, 'w') as file:
        json.dump(data, file, indent=4)
    file.close()

## Args: name (str): Name / ID of the ASVS entry
##       found_in (str): name of the ASVS section name
##       form_name (str): 
## Returns: No return
## if the entry doesn't have a name, put "" (or an empty string) for the 'form_name' parameter. Same for info
def add_entry_to_json(name, found_in, info):
    if Path(JSONNAME).is_file():
        with open(JSONNAME, 'r') as file:
            data = json.load(file)

    if not any(isinstance(entry, dict) and "Findings" in entry for entry in data):
        data.append({"Findings": []})

    findings_entry = next(entry for entry in data if "Findings" in entry)
    findings_entry["Findings"].append({
        "Name": name,
        "Found_in": found_in,
        "Info": info
    })

    with open(JSONNAME, 'w') as file:
        json.dump(data, file, indent=4)

## Args: link (str): Link to a scanned page that will be added to the json
## Returns: No return
def add_link_to_json(link):
    if Path(JSONNAME).is_file():
        with open(JSONNAME, 'r') as file:
            data = json.load(file)

    if not any(isinstance(entry, dict) and "All_URL_Scanned" in entry for entry in data):
        data.append({"All_URL_Scanned": []})

    All_URL_Scanned_entry = next(entry for entry in data if "All_URL_Scanned" in entry)
    All_URL_Scanned_entry["All_URL_Scanned"].append({
        "URL": link
    })

    with open(JSONNAME, 'w') as file:
        json.dump(data, file, indent=4)
    return True

def clear_json():
    if Path(JSONNAME).is_file():
        os.remove(JSONNAME)