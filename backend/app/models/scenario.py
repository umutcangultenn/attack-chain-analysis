from pydantic import BaseModel
from typing import List
from .attack_chain import AttackChain

class Scenario(BaseModel):
    id: str
    name: str
    description: str
    chains: List[AttackChain]
    created_at: str
