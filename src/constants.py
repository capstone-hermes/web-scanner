import asyncio
JSONNAME = "./output.json"
HAS_CAPTCHA = False
TOKEN_KEYWORDS = ['csrf', 'token', 'authenticity_token', 'ctoken', 'security']
HAS_INDENTIFICATION = False
BROWSER_EXECUTABLE_PATH = "/usr/bin/chromium"
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
}
JSON_LOCK = asyncio.Lock()
BASE_URL = "http://localhost:8080"
