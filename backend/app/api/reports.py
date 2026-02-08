import shutil
import os
import tempfile
from fastapi import APIRouter, UploadFile, File, HTTPException
from app.parsers.zap_parser import ZapParser
from app.db import db

router = APIRouter()
parser = ZapParser()

MAX_FILE_SIZE = 10 * 1024 * 1024 # 10MB

@router.post("/reports/zap")
async def upload_zap_report(file: UploadFile = File(...)):
    if not file.filename.lower().endswith(".json"):
        raise HTTPException(status_code=400, detail="Invalid file type. Only .json OWASP ZAP reports are allowed.")

    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
            size = 0
            chunk_size = 1024 * 1024
            while True:
                chunk = await file.read(chunk_size)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_FILE_SIZE:
                    os.unlink(tmp.name)
                    raise HTTPException(status_code=413, detail="File too large.")
                tmp.write(chunk)
            tmp_path = tmp.name
        
        # Parse
        vulnerabilities = parser.parse(tmp_path)
        db.vulnerabilities.extend(vulnerabilities)
        
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        
        return {"message": "Report processed successfully", "count": len(vulnerabilities), "vulnerabilities": vulnerabilities}
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error processing ZAP report: {e}")
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise HTTPException(status_code=500, detail="Error processing report.")
