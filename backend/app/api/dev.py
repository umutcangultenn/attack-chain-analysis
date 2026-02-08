import os
from fastapi import APIRouter, HTTPException
from app.api.reports import parser as zap_parser
from app.api.logs import parser as log_parser
from app.db import db
from app.config import settings

router = APIRouter()

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SAMPLE_DATA_DIR = os.path.join(BASE_DIR, "sample_data")

@router.post("/dev/populate")
async def populate_demo_data():
    """
    Loads Multiple Scenarios (Scenario 2: Path Traversal, Scenario 3: SQL Injection) directly into the system.
    """
    try:
        # Clear existing data
        db.clear()
        
        scenarios_to_load = ["scenario_2", "scenario_3"]
        total_vulns = 0
        total_logs = 0
        
        for scenario_name in scenarios_to_load:
            scenario_dir = os.path.join(SAMPLE_DATA_DIR, scenario_name)
            zap_file = os.path.join(scenario_dir, "zap_report.json")
            access_log = os.path.join(scenario_dir, "access.log")
            
            if os.path.exists(zap_file):
                vulnerabilities = zap_parser.parse(zap_file)
                db.vulnerabilities.extend(vulnerabilities)
                total_vulns += len(vulnerabilities)
            
            if os.path.exists(access_log):
                access_events = log_parser.parse(access_log, log_type="access")
                db.logs.extend(access_events)
                total_logs += len(access_events)
        
        return {
            "message": f"Loaded {len(scenarios_to_load)} Scenarios (Path Traversal & SQL Injection).\n- {total_vulns} Vulnerabilities\n- {total_logs} Log Events\n\nNow click 'Start Analysis'.",
            "vulnerabilities": total_vulns,
            "logs": total_logs
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
