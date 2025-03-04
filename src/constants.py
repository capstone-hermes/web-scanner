JSONNAME = "./output.json"
HAS_CAPTCHA = False
HAS_INDENTIFICATION = False
TOKEN_KEYWORDS = ['csrf', 'token', 'authenticity_token', 'ctoken', 'security']
BROWSER_EXECUTABLE_PATH = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
}
PASSWORD_ERROR_PATTERNS = [
    r"too short",
    r"must be at least",
    r"invalid",
    r"error"
]