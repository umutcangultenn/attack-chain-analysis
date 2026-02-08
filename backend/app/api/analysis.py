from fastapi import APIRouter
from app.db import db
from app.analyzers.correlator import Correlator
from app.analyzers.chain_builder import ChainBuilder

router = APIRouter()
correlator = Correlator()
chain_builder = ChainBuilder()

@router.post("/analyze")
async def run_analysis():
    if not db.vulnerabilities:
        return {"message": "No vulnerabilities found. Upload a ZAP report first.", "chains": []}
    
    if not db.logs:
        return {"message": "No logs found. Upload log files first.", "chains": []}
        
    # Run correlation
    correlated_data = correlator.correlate(db.vulnerabilities, db.logs)
    
    # Build chains
    chains = chain_builder.build_chains(correlated_data)
    
    # Save to DB
    db.chains = chains
    
    return {
        "message": "Analysis complete", 
        "correlated_events": len(correlated_data),
        "chains_created": len(chains),
        "chains": chains
    }
