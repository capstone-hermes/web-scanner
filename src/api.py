from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import subprocess
import json
import os

app = FastAPI(title="Web Scanner API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],  # Autorise les requêtes de l'URL de ton front-end
    allow_credentials=True,
    allow_methods=["*"],  # Autorise toutes les méthodes HTTP
    allow_headers=["*"],  # Autorise tous les headers
)

@app.get("/scan")
async def perform_scan(url: str):
    """
    Endpoint to scan a website for security vulnerabilities.
    Returns the scan results as JSON.
    """
    try:
        result = subprocess.run(
            ["python3", "src/main.py", url], 
            capture_output=True, 
            text=True,
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        )
        
        if result.returncode != 0:
            raise HTTPException(status_code=500, detail=f"Scan failed: {result.stderr}")
        
        # Read the output.json file which contains the scan results
        with open("output.json", "r") as f:
            scan_results = json.load(f)
            
        return scan_results
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy"}