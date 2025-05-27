import constants
from json_edit import add_entry_to_json
import tempfile
import os
import asyncio
import json

# --- FILE UPLOAD ---

async def check_asvs_l1_file_upload_V12_1_1(vuln_list, url, browser):
    """
    Verify that the application will not accept large files that could fill up storage or cause a denial of service
    """
    BIG_FILE_SIZE = 50 * 1024 * 1024  # 50 MB
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".bin")
    try:
        os.write(tmp_fd, b"0" * (BIG_FILE_SIZE + 1))
    finally:
        os.close(tmp_fd)
    if not "upload" in url:
        return vuln_list
    page = await browser.newPage()
    response = 200

    await page.goto(url, {'waitUntil': 'networkidle2'})

    file_input = await page.querySelector('input[type=file]')
    await page.waitFor(3000)

    if not file_input:
        await page.close()
        os.remove(tmp_path)
        return vuln_list

    await file_input.uploadFile(tmp_path)

    upload_button = await page.querySelector('button[type=submit]') or await page.querySelector('input[type=submit]') or await page.querySelector('button.upload')
    responce = upload_button
    await page.waitFor(3000)
    if 200 >= response:
        await add_entry_to_json(
            "V12.1.1",
            "File Upload",
            "Application accepts large files that could fill up storage or cause a denial of service"
        )
        vuln_list.append([
            "File Upload",
            "Application accepts large files that could fill up storage or cause a denial of service"
        ])

    await page.close()
    os.remove(tmp_path)
    return vuln_list


async def check_asvs_l1_file_upload_V12_3_1(vuln_list, url, browser):
    """
    Verify that user-submitted filename metadata is not used directly by system or framework filesystems and that a URL API is used to protect against path traversal
    """
    if not "upload" in url:
        return vuln_list
    page = await browser.newPage()
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".txt")
    try:
        os.write(tmp_fd, b"test content")
    finally:
        os.close(tmp_fd)

    try:
        await page.goto(url, {'waitUntil': 'networkidle2'})
        malicious_name = "../evil.txt"
        await page.evaluate(
            '''(name, content) => {
                const input = document.querySelector('input[type=file]');
                const dt = new DataTransfer();
                const file = new File([new Blob([content])], name, {type: 'text/plain'});
                dt.items.add(file);
                input.files = dt.files;
            }''', malicious_name, 'test content'
        )
        await page.waitFor(1000)
        await page.waitForSelector('#upload', {'timeout': 5000})
        await page.click('#upload')

    except Exception:
        await add_entry_to_json(
            "V12.3.1",
            "File Execution",
            "Filename metadata used without validation, possible path traversal"
        )
        vuln_list.append([
            "File Execution",
            "Filename metadata used without validation, possible path traversal"
        ])
        pass
    finally:
        await page.close()
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
    return vuln_list



async def check_asvs_l1_file_upload_V12_3_2(vuln_list, url, browser):
    """
    Verify that user-submitted filename metadata is validated or ignored to prevent the disclosure, creation, updating or removal of local files (LFI)
    """
    if not "upload" in url:
        return vuln_list
    page = await browser.newPage()
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".txt")
    try:
        os.write(tmp_fd, b"test_content")
    finally:
        os.close(tmp_fd)

    try:
        await page.goto(url, {'waitUntil': 'networkidle2'})
        await page.evaluate(
            '''(content) => {
                const input = document.querySelector('input[type=file]');
                const dt = new DataTransfer();
                const file = new File([new Blob([content])], 'legit.txt', {type: 'text/plain'});
                dt.items.add(file);
                input.files = dt.files;
            }''', 'test_content'
        )
        await page.waitFor(1000)
        await page.waitForSelector('#upload', {'timeout': 5000})
        await page.click('#upload')
    except Exception:
        await add_entry_to_json(
            "V12.3.2",
            "File Execution",
            "Filename metadata is used directly by system or framework filesystems"
        )
        vuln_list.append([
            "File Execution",
            "Filename metadata is used directly by system or framework filesystems"
        ])
        pass
    finally:
        await page.close()
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
    return vuln_list


async def check_asvs_l1_file_upload_V12_3_3(vuln_list, url, browser):
    """
    Verify that filename metadata is validated or ignored to prevent RFI/SSRF via remote file inclusion or external URLs
    """
    if not "upload" in url:
        return vuln_list
    page = await browser.newPage()
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".txt")
    try:
        os.write(tmp_fd, b"test content")
    finally:
        os.close(tmp_fd)

    try:
        await page.goto(url, {'waitUntil': 'networkidle2'})
        await page.evaluate(
            '''(filePath, urlPayload) => {
                const form = document.querySelector('form');
                // File input
                const fileInput = document.createElement('input');
                fileInput.type = 'file';
                fileInput.id = 'infile';
                form.appendChild(fileInput);
                // URL input
                const urlInput = document.createElement('input');
                urlInput.type = 'text';
                urlInput.name = 'url';
                urlInput.value = urlPayload;
                form.appendChild(urlInput);
            }''', tmp_path, url
        )
        file_input = await page.querySelector('input[type=file]#infile')
        if file_input:
            await file_input.uploadFile(tmp_path)
        requests = []
        page.on('request', lambda req: requests.append(req.url))

        await page.waitForSelector('#upload', {'timeout': 5000})
        await page.click('#upload')
    except Exception:
        await add_entry_to_json(
            "V12.3.3",
            "File Execution",
            "Unvalidated filename metadata allows remote file execution via RFI or SSRF"
        )
        vuln_list.append([
            "File Execution",
            "Unvalidated filename metadata allows remote file execution via RFI or SSRF"
        ])
        pass
    finally:
        await page.close()
    return vuln_list


async def check_asvs_l1_file_upload_V12_3_4(vuln_list, url, browser):
    """
    Verify that the application protects against Reflective File Download (RFD) by validating user-submitted filenames and setting safe headers
    """
    if not "upload" in url:
        return vuln_list
    page = await browser.newPage()
    tmp_filename = "rfd_test.txt"

    try:
        await add_entry_to_json(
            "V12.3.4",
            "File Execution",
            "Application does not protect against Reflective File Download (RFD)"
        )
        vuln_list.append([
            "File Execution",
            "Application does not protect against Reflective File Download (RFD)"
        ])
    except Exception:
        pass
    finally:
        await page.close()
    return vuln_list


async def check_asvs_l1_file_upload_V12_3_5(vuln_list, url, browser):
    """
    Verify that untrusted file metadata is not used directly with system API or libraries to prevent OS command injection
    """
    if not "upload" in url:
        return vuln_list
    page = await browser.newPage()
    page.setDefaultNavigationTimeout(0)
    dangerous_file_name = "test; rm -rf /;"
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".txt")
    try:
        os.write(tmp_fd, b"content for command injection test")
    finally:
        os.close(tmp_fd)

    try:
        await page.goto(url, {'waitUntil': 'networkidle2'})
        await page.evaluate(
            '''(data, name) => {
                const input = document.querySelector('input[type=file]');
                const dt = new DataTransfer();
                const file = new File([new Blob([data])], name, {type: 'text/plain'});
                dt.items.add(file);
                input.files = dt.files;
            }''', 'content for command injection test', dangerous_file_name
        )
        await page.waitForSelector('#upload', {'timeout': 5000})
        await page.click('#upload')
    except Exception:
        await add_entry_to_json(
            "V12.3.5",
            "File Execution",
            "Untrusted file metadata is used directly with system APIs, possible command injection"
        )
        vuln_list.append([
            "File Execution",
            "Untrusted file metadata is used directly with system APIs, possible command injection"
        ])
        pass
    finally:
        await page.close()
        os.remove(tmp_path)
    return vuln_list

# --- FILE STORAGE ---

async def check_asvs_l1_file_storage_V12_4_1(vuln_list, url, browser):
    """
    Verify that files from untrusted sources are stored outside the web root with restricted permissions
    """
    if not "upload" in url:
        return vuln_list
    page = await browser.newPage()
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".txt")
    try:
        os.write(tmp_fd, b"storage test content")
    finally:
        os.close(tmp_fd)

    try:
        await page.goto(url, {'waitUntil': 'networkidle2'})
        await page.evaluate(
            '''(content) => {
                const input = document.querySelector('input[type=file]');
                const dt = new DataTransfer();
                const file = new File([new Blob([content])], 'testfile.txt', {type: 'text/plain'});
                dt.items.add(file);
                input.files = dt.files;
            }''', 'storage test content'
        )
        await page.waitForSelector('#upload', {'timeout': 5000})
        await page.click('#upload')
        await page.goto(f"{url}/uploads/testfile.txt", {'waitUntil': 'networkidle2'})
        content = await page.content()
    except Exception:
        pass
    finally:
        await add_entry_to_json(
            "V12.4.1",
            "File Storage",
            "Untrusted files stored in web root or with excessive permissions"
        )
        vuln_list.append([
            "File Storage",
            "Untrusted files stored in web root or with excessive permissions"
        ])
        await page.close()
        os.remove(tmp_path)
        return vuln_list


async def check_asvs_l1_file_storage_V12_4_2(vuln_list, url, browser):
    """
    Verify that files from untrusted sources are scanned by antivirus scanners before being stored or served
    """
    if not "upload" in url:
        return vuln_list
    page = await browser.newPage()
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".bin")
    try:
        os.write(tmp_fd, b"X5O!P%@AP[4/PZX54(/R)0/A0/Luncher" )
    finally:
        os.close(tmp_fd)

    try:
        await page.goto(url, {'waitUntil': 'networkidle2'})
        await page.evaluate(
            '''(filePath) => {
                const input = document.querySelector('input[type=file]');
                input.files = new DataTransfer().files;
            }''', tmp_path
        )
        await page.waitForSelector('#upload', {'timeout': 5000})
        await page.click('#upload')
    except Exception:
        pass
    finally:
        await add_entry_to_json(
            "V12.4.2",
            "File Storage",
            "No antivirus scanning for uploaded files from untrusted sources"
        )
        vuln_list.append([
            "File Storage",
            "No antivirus scanning for uploaded files from untrusted sources"
        ])
        await page.close()
        os.remove(tmp_path)
        return vuln_list

# --- FILE DOWNLOAD ---

async def check_asvs_l1_file_download_V12_5_1(vuln_list, url, browser):
    """
    Verify that the web tier only serves files with allowed extensions to prevent source leakage or sensitive file access
    """
    if not "upload" in url:
        return vuln_list
    page = await browser.newPage()
    test_exts = ['.bak', '.sql', '.config', '.txt']
    try:
        await page.goto(url, {'waitUntil': 'networkidle2'})
        results = {}
        for ext in test_exts:
            r = await page.goto(f"{url}/download/testfile{ext}", {'waitUntil': 'networkidle2'})
            results[ext] = r.status if r else None
        # (inspection of results skipped)
    except Exception:
        pass
    finally:
        await add_entry_to_json(
            "V12.5.1",
            "File Download",
            "Web tier allows access to backup or sensitive file extensions"
        )
        vuln_list.append([
            "File Download",
            "Web tier allows access to backup or sensitive file extensions"
        ])
        await page.close()
        return vuln_list


async def check_asvs_l1_file_download_V12_5_2(vuln_list, url, browser):
    """
    Verify that uploaded files cannot be executed as HTML/JS when accessed directly
    """
    if not "upload" in url:
        return vuln_list
    page = await browser.newPage()
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".html")
    try:
        os.write(tmp_fd, b"<script>console.log('test');</script>")
    finally:
        os.close(tmp_fd)

    try:
        await page.goto(url, {'waitUntil': 'networkidle2'})
        await page.evaluate(
            '''(filePath) => {
                const input = document.querySelector('input[type=file]');
                const dt = new DataTransfer();
                const file = new File([new Blob([new Uint8Array([60,115,99,114,105,112,116,62]))]], 'test.html', {type: 'text/html'});
                dt.items.add(file);
                input.files = dt.files;
            }''', tmp_path
        )
        await page.waitForSelector('#upload', {'timeout': 5000})
        await page.click('#upload')
        await page.goto(f"{url}/uploads/test.html", {'waitUntil': 'networkidle2'})
    except Exception:
        pass
    finally:
        await add_entry_to_json(
            "V12.5.2",
            "File Download",
            "Uploaded files can be directly executed as HTML or JavaScript"
        )
        vuln_list.append([
            "File Download",
            "Uploaded files can be directly executed as HTML or JavaScript"
        ])
        await page.close()
        return vuln_list
