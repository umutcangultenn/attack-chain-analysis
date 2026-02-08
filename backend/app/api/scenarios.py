from fastapi import APIRouter
from app.db import db

router = APIRouter()

@router.get("/scenarios")
async def get_scenarios():
    return db.chains

@router.get("/scenarios/{chain_id}")
async def get_scenario(chain_id: str):
    chain = next((c for c in db.chains if c.id == chain_id), None)
    if not chain:
        return {"error": "Scenario not found"}
    return chain

@router.delete("/scenarios/clear")
async def clear_data():
    db.clear()
    return {"message": "All data cleared"}
