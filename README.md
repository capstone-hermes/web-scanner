# Web Scanner

A security scanning tool for websites.

## Usage

### Command Line
```
python src/main.py <url>
```

### API Server
Start the FastAPI server:
```
pip install -r requirements.txt
uvicorn src.api:app --reload
```

Access the API:
- Scan a website: `GET /scan?url=https://example.com`
- Health check: `GET /health`

## Docker
```
docker build -t web-scanner .
docker run web-scanner <url>
```
