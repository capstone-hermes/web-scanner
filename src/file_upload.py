import constants
from json_edit import add_entry_to_json
from links import get_links_as_user
from password_security import attempt_signup

async def check_asvs_l1_file_upload_V12_3_1(vuln_list, url, browser):
    """
    Verify if application accept large files that could fill up storage or cause a denial of service
    """
    if constants.HAS_CAPTCHA or not constants.HAS_INDENTIFICATION:
        return vuln_list


    await add_entry_to_json(
        "V12.3.1",
        "File Upload",
        "Application accept large files that could fill up storage or cause a denial of service"
    )
    vuln_list.append(["File Upload", "Application accept large files that could fill up storage or cause a denial of service"])
    return vuln_list

async def check_asvs_l1_file_upload_V12_3_2(vuln_list, url, browser):
    """
    Verify if filename metadata is used directly by system or framework filesystems
    """
    if constants.HAS_CAPTCHA or not constants.HAS_INDENTIFICATION:
        return vuln_list


    await add_entry_to_json(
        "V12.3.2",
        "File Execution",
        "Filename metadata is used directly by system or framework filesystems"
    )
    vuln_list.append(["File Execution", "Filename metadata is used directly by system or framework filesystems"])
    return vuln_list

async def check_asvs_l1_file_upload_V12_3_3(vuln_list, url, browser):
    """
    Verify if user-submitted filename metadata isn't validated or ignored, it doesn't prevent the disclosure or execution of remote files
    """
    if constants.HAS_CAPTCHA or not constants.HAS_INDENTIFICATION:
        return vuln_list


    await add_entry_to_json(
        "V12.3.3",
        "File Execution",
        "User-submitted filename metadata isn't validated or ignored, it doesn't prevent the disclosure or execution of remote files via Remote File Inclusion (RFI) or Server-side Request Forgery (SSRF) attacks"
    )
    vuln_list.append(["File Execution", "User-submitted filename metadata isn't validated or ignored, it doesn't prevent the disclosure or execution of remote files via Remote File Inclusion (RFI) or Server-side Request Forgery (SSRF) attacks"])
    return vuln_list

async def check_asvs_l1_file_upload_V12_3_4(vuln_list, url, browser):
    """
    Verify if Application doesn't protects against Reflective File Download (RFD) by validating or ignoring user-submitted filenames in a JSON, JSONP, or URL parameter
    """
    if constants.HAS_CAPTCHA or not constants.HAS_INDENTIFICATION:
        return vuln_list


    await add_entry_to_json(
        "V12.3.4",
        "File Execution",
        "Application doesn't protects against Reflective File Download (RFD) by validating or ignoring user-submitted filenames in a JSON, JSONP, or URL parameter"
    )
    vuln_list.append(["File Execution", "Application doesn't protects against Reflective File Download (RFD) by validating or ignoring user-submitted filenames in a JSON, JSONP, or URL parameter"])
    return vuln_list

async def check_asvs_l1_file_upload_V12_3_5(vuln_list, url, browser):
    """
    Verify if Application doesn't protects against Reflective File Download (RFD) by validating or ignoring user-submitted filenames in a JSON, JSONP, or URL parameter
    """
    if constants.HAS_CAPTCHA or not constants.HAS_INDENTIFICATION:
        return vuln_list


    await add_entry_to_json(
        "V12.3.5",
        "File Execution",
        "Untrusted file metadata is used directly with system API or libraries"
    )
    vuln_list.append(["File Execution", "Untrusted file metadata is used directly with system API or libraries"])
    return vuln_list

