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
        "URL scanned": url
    }
    data.append(start_entry)
    with open(JSONNAME, 'w') as file:
        json.dump(data, file, indent=4)
    file.close()

## Args: name (str): Name / ID of the ASVS entry
##       found_in (str): name of the ASVS section name
##       form_name (str): 
## Returns: bool: True if the site enforces 12+ character password policy, False otherwise
## if the entry doesn't have a name, put "" (or an empty string) for the 'form_name' parameter. Same for info
def add_entry_to_json(name, found_in, info):
    if Path(JSONNAME).is_file():
        with open(JSONNAME, 'r') as file:
            data = json.load(file)

    new_entry = {
        "Name": name,
        "Found_in": found_in,
        "Info": info
    }
    data.append(new_entry)

    with open(JSONNAME, 'w') as file:
        json.dump(data, file, indent=4)

def clear_json():
    if Path(JSONNAME).is_file():
        os.remove(JSONNAME)