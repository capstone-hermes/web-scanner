import constants
from json_edit import add_entry_to_json
from links import get_links_as_user
from password_security import attempt_signup

# --- FILE UPLOAD ---

async def check_asvs_l1_file_upload_V12_1_1(vuln_list, url, browser):
    """
    Verify that the application will not accept large files that could fill up storage or cause a denial of service
    """
    if constants.HAS_CAPTCHA or not constants.HAS_INDENTIFICATION:
        return vuln_list

    await add_entry_to_json(
        "V12.1.1",
        "File Upload",
        "Application accepts large files that could fill up storage or cause a denial of service"
    )
    vuln_list.append(["File Upload", "Application accepts large files that could fill up storage or cause a denial of service"])
    return vuln_list


async def check_asvs_l1_file_upload_V12_3_1(vuln_list, url, browser):
    """
    Verify that user-submitted filename metadata is not used directly by system or framework filesystems and that a URL API is used to protect against path traversal
    """
    if constants.HAS_CAPTCHA or not constants.HAS_INDENTIFICATION:
        return vuln_list

    await add_entry_to_json(
        "V12.3.1",
        "File Execution",
        "Filename metadata used without validation - possible path traversal"
    )
    vuln_list.append(["File Execution", "Filename metadata used without validation - possible path traversal"])
    return vuln_list


async def check_asvs_l1_file_upload_V12_3_2(vuln_list, url, browser):
    """
    Verify that user-submitted filename metadata is validated or ignored to prevent the disclosure, creation, updating or removal of local files (LFI)
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
    Verify that filename metadata is validated or ignored to prevent RFI/SSRF via remote file inclusion or external URLs
    """
    if constants.HAS_CAPTCHA or not constants.HAS_INDENTIFICATION:
        return vuln_list

    await add_entry_to_json(
        "V12.3.3",
        "File Execution",
        "Unvalidated filename metadata allows remote file execution via RFI or SSRF"
    )
    vuln_list.append(["File Execution", "Unvalidated filename metadata allows remote file execution via RFI or SSRF"])
    return vuln_list


async def check_asvs_l1_file_upload_V12_3_4(vuln_list, url, browser):
    """
    Verify that the application protects against Reflective File Download (RFD) by validating user-submitted filenames and setting safe headers
    """
    if constants.HAS_CAPTCHA or not constants.HAS_INDENTIFICATION:
        return vuln_list

    await add_entry_to_json(
        "V12.3.4",
        "File Execution",
        "Application does not protect against Reflective File Download (RFD)"
    )
    vuln_list.append(["File Execution", "Application does not protect against Reflective File Download (RFD)"])
    return vuln_list


async def check_asvs_l1_file_upload_V12_3_5(vuln_list, url, browser):
    """
    Verify that untrusted file metadata is not used directly with system API or libraries to prevent OS command injection
    """
    if constants.HAS_CAPTCHA or not constants.HAS_INDENTIFICATION:
        return vuln_list

    await add_entry_to_json(
        "V12.3.5",
        "File Execution",
        "Untrusted file metadata is used directly with system APIs - possible command injection"
    )
    vuln_list.append(["File Execution", "Untrusted file metadata is used directly with system APIs - possible command injection"])
    return vuln_list

# --- FILE STORAGE ---

async def check_asvs_l1_file_storage_V12_4_1(vuln_list, url, browser):
    """
    Verify that files from untrusted sources are stored outside the web root with restricted permissions
    """
    if constants.HAS_CAPTCHA or not constants.HAS_INDENTIFICATION:
        return vuln_list

    await add_entry_to_json(
        "V12.4.1",
        "File Storage",
        "Untrusted files stored in web root or with excessive permissions"
    )
    vuln_list.append(["File Storage", "Untrusted files stored in web root or with excessive permissions"])
    return vuln_list


async def check_asvs_l1_file_storage_V12_4_2(vuln_list, url, browser):
    """
    Verify that files from untrusted sources are scanned by antivirus scanners before being stored or served
    """
    if constants.HAS_CAPTCHA or not constants.HAS_INDENTIFICATION:
        return vuln_list

    await add_entry_to_json(
        "V12.4.2",
        "File Storage",
        "No antivirus scanning for uploaded files from untrusted sources"
    )
    vuln_list.append(["File Storage", "No antivirus scanning for uploaded files from untrusted sources"])
    return vuln_list

# --- FILE DOWNLOAD ---

async def check_asvs_l1_file_download_V12_5_1(vuln_list, url, browser):
    """
    Verify that the web tier only serves files with allowed extensions to prevent source leakage or sensitive file access
    """
    if constants.HAS_CAPTCHA or not constants.HAS_INDENTIFICATION:
        return vuln_list

    await add_entry_to_json(
        "V12.5.1",
        "File Download",
        "Web tier allows access to backup or sensitive file extensions"
    )
    vuln_list.append(["File Download", "Web tier allows access to backup or sensitive file extensions"])
    return vuln_list


async def check_asvs_l1_file_download_V12_5_2(vuln_list, url, browser):
    """
    Verify that uploaded files cannot be executed as HTML/JS when accessed directly
    """
    if constants.HAS_CAPTCHA or not constants.HAS_INDENTIFICATION:
        return vuln_list

    await add_entry_to_json(
        "V12.5.2",
        "File Download",
        "Uploaded files can be directly executed as HTML or JavaScript"
    )
    vuln_list.append(["File Download", "Uploaded files can be directly executed as HTML or JavaScript"])
    return vuln_list
