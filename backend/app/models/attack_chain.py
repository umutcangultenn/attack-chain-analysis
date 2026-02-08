from pydantic import BaseModel
from typing import List, Optional, Union
from enum import Enum
from datetime import datetime
from .vulnerability import Vulnerability
from .log_event import LogEvent

class ChainStepType(str, Enum):
    VULNERABILITY_EXPLOIT = "VULNERABILITY_EXPLOIT"
    RECONNAISSANCE = "RECONNAISSANCE"
    INITIAL_ACCESS = "INITIAL_ACCESS"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"

class ChainStep(BaseModel):
    id: str
    description: str
    timestamp: datetime
    step_type: ChainStepType
    related_vulnerability: Optional[Vulnerability] = None
    related_logs: List[LogEvent] = []

class AttackChain(BaseModel):
    id: str
    name: str
    steps: List[ChainStep]
    start_time: datetime
    end_time: datetime
    risk_score: int
    source_ips: List[str]
    root_cause_analysis: Optional[str] = None
