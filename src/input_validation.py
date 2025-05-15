import constants
from json_edit import add_entry_to_json
from links import get_links_as_user
from password_security import attempt_signup

async def check_asvs_l1_input_validation_V5_1_1(vuln_list, url, browser):
    """
    Vérifie il y a une protection contre le HTTP Parameter Pollution
    """
    if constants.HAS_CAPTCHA or not constants.HAS_INDENTIFICATION:
        return vuln_list

    password = "Elev3nwr@ngG0Rr1Ght"
    test_data = {
        "username": "13HERMEStest",
        "email": "13ASVSHermesTest@gmail.com",
        "password": password,
        "confirm_password": password
    }

    content, status, page = await attempt_signup(url, test_data, browser)

    if status and status >= 400:
        return vuln_list
    if content:
        lower_content = content.lower()
        if (status and status < 400):
            await add_entry_to_json(
                "V5.1.1",
                "Input Validation",
                "Application doesn't have defenses against HTTP Parameter Pollution"
            )
            vuln_list.append(["Input Validation", "Application doesn't have defenses against HTTP Parameter Pollution"])
    await page.close()
    return vuln_list

async def check_asvs_l1_input_validation_V5_1_2(vuln_list, url, browser):
    """
    Vérifie s'il y a une protection contre les remplissages de paramètres massifs
    """
    if constants.HAS_CAPTCHA or not constants.HAS_INDENTIFICATION:
        return vuln_list

    password = "Elev3nwr@ngG0Rr1Ght"
    test_data = {
        "username": "14HERMEStest",
        "email": "14ASVSHermesTest@gmail.com",
        "password": password,
        "confirm_password": password
    }

    content, status, page = await attempt_signup(url, test_data, browser)

    if status and status >= 400:
        return vuln_list
    if content:
        lower_content = content.lower()
        if (status and status < 400):
            await add_entry_to_json(
                "V5.1.2",
                "Input Validation",
                "Application doesn't have defenses against parameter assignment attacks"
            )
            vuln_list.append(["Input Validation", "Application doesn't have defenses against parameter assignment attacks"])
    await page.close()
    return vuln_list

async def check_asvs_l1_input_validation_V5_1_3(vuln_list, url, browser):
    """
    Vérifie si tous les inputs sont correctement filtrés
    """
    if constants.HAS_CAPTCHA or not constants.HAS_INDENTIFICATION:
        return vuln_list

    password = "Elev3nwr@ngG0Rr1Ght"
    test_data = {
        "username": "15HERMEStest",
        "email": "15ASVSHermesTest@gmail.com",
        "password": password,
        "confirm_password": password
    }

    content, status, page = await attempt_signup(url, test_data, browser)

    if status and status >= 400:
        return vuln_list
    if content:
        lower_content = content.lower()
        if (status and status < 400):
            await add_entry_to_json(
                "V5.1.3",
                "Input Validation",
                "Inputs are not properly filtered (such as using allow lists)"
            )
            vuln_list.append(["Input Validation", "Inputs are not properly filtered (such as using allow lists)"])
    await page.close()
    return vuln_list

async def check_asvs_l1_input_validation_V5_1_5(vuln_list, url, browser):
    """
    Vérifie si les liens et URL envoie seulement vers des ressources de confiance, sinon avertie l'utilisateur
    """
    if constants.HAS_CAPTCHA or not constants.HAS_INDENTIFICATION:
        return vuln_list

    password = "Elev3nwr@ngG0Rr1Ght"
    test_data = {
        "username": "17HERMEStest",
        "email": "17ASVSHermesTest@gmail.com",
        "password": password,
        "confirm_password": password
    }

    content, status, page = await attempt_signup(url, test_data, browser)

    if status and status >= 400:
        return vuln_list
    if content:
        lower_content = content.lower()
        if (status and status < 400):
            await add_entry_to_json(
                "V5.1.5",
                "Input Validation",
                "Links and URLs do not only point to trusted resources, neither warn the user"
            )
            vuln_list.append(["Input Validation", "Links and URLs do not only point to trusted resources, neither warn the user"])
    await page.close()
    return vuln_list