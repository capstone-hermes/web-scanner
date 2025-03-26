# Web Scanner

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

A Python-based security scanner that automatically checks websites for common vulnerabilities and security issues based on OWASP Application Security Verification Standard (ASVS) Level 1 requirements.

## 🚨 Security Note

This tool is designed for educational and security assessment purposes only. Always obtain proper authorization before scanning any website that you do not own.

## 🌟 Features

- Automated security scanning based on OWASP ASVS Level 1
- API server for integration with other applications
- Multi-threaded scanning for faster results
- Detailed vulnerability reports with remediation advice
- Docker support for isolated execution

## 🚀 Getting Started

### Prerequisites

- [Python](https://www.python.org/) 3.9+
- pip (Python package manager)

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/hermes-fullstack.git
   cd hermes-fullstack/web-scanner
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Usage

#### Command Line

Run a scan directly from the command line:
```bash
python src/main.py <url>
```

#### API Server

Start the FastAPI server:
```bash
uvicorn src.api:app --reload
```

Access the API:
- Scan a website: `GET /scan?url=https://example.com`
- Health check: `GET /health`

## 🐳 Docker

Build and run using Docker:
```bash
docker build -t web-scanner .
docker run web-scanner python src/main.py <url>
```

## 🏗️ Architecture

The scanner consists of multiple modules that work together:
- Core scanning engine
- ASVS requirement verification modules
- Reporting and output formatting
- API interface

## 🛠️ Technology Stack

- [Python](https://www.python.org/) - Programming language
- [aiohttp](https://docs.aiohttp.org/) - Asynchronous HTTP client/server
- [BeautifulSoup4](https://www.crummy.com/software/BeautifulSoup/) - HTML parsing
- [pyppeteer](https://github.com/pyppeteer/pyppeteer) - Headless browser automation
- [FastAPI](https://fastapi.tiangolo.com/) - API framework

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.