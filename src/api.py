from fastapi import FastAPI, HTTPException
import subprocess
import json
import os

app = FastAPI(title="Web Scanner API")

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