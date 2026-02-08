import shutil
import os
import tempfile
from fastapi import APIRouter, UploadFile, File, Form, HTTPException
from app.parsers.log_parser import LogParser
from app.db import db

router = APIRouter()
parser = LogParser()

# Maximum file size (10 MB in bytes)
MAX_FILE_SIZE = 10 * 1024 * 1024 
ALLOWED_LOG_TYPES = ["access", "auth"]

@router.post("/logs/upload")
async def upload_log(file: UploadFile = File(...), log_type: str = Form(...)):
    # 1. Validate Log Type
    if log_type not in ALLOWED_LOG_TYPES:
        raise HTTPException(status_code=400, detail=f"Invalid log_type. Must be one of {ALLOWED_LOG_TYPES}")
    
    # 2. Validate File Extension
    filename = file.filename.lower()
    if not (filename.endswith(".log") or filename.endswith(".txt")):
        raise HTTPException(status_code=400, detail="Invalid file type. Only .log and .txt files are allowed.")

    try:
        # 3. Create temp file and validate size
        with tempfile.NamedTemporaryFile(delete=False, suffix=".log") as tmp:
            size = 0
            chunk_size = 1024 * 1024 # 1MB chunks
            
            while True:
                chunk = await file.read(chunk_size)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_FILE_SIZE:
                    os.unlink(tmp.name)
                    raise HTTPException(status_code=413, detail=f"File too large. Maximum size is {MAX_FILE_SIZE / (1024*1024)}MB")
                tmp.write(chunk)
                
            tmp_path = tmp.name
            
        # 4. Parse content
        events = parser.parse(tmp_path, log_type=log_type)
        db.logs.extend(events)
        
        # Cleanup
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        
        return {"message": "Log file processed successfully", "count": len(events)}
        
    except HTTPException:
        raise
    except Exception as e:
        # Generic error catching but don't expose full stack trace in production
        print(f"Error processing log file: {e}") 
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise HTTPException(status_code=500, detail="Internal server error processing log file.")
