from pydantic import BaseModel
from typing import Optional
from enum import Enum
from datetime import datetime

class LogEventType(str, Enum):
    ACCESS = "ACCESS"
    AUTH_FAILURE = "AUTH_FAILURE"
    AUTH_SUCCESS = "AUTH_SUCCESS"
    ERROR = "ERROR"
    UNKNOWN = "UNKNOWN"

class LogEvent(BaseModel):
    timestamp: datetime
    source_ip: str
    method: Optional[str] = None
    endpoint: Optional[str] = None
    status_code: Optional[int] = None
    user_agent: Optional[str] = None
    raw_log: str
    type: LogEventType
