from typing import List
from app.models.vulnerability import Vulnerability
from app.models.log_event import LogEvent
from app.models.attack_chain import AttackChain

class Database:
    def __init__(self):
        self.vulnerabilities: List[Vulnerability] = []
        self.logs: List[LogEvent] = []
        self.chains: List[AttackChain] = []

    def clear(self):
        self.vulnerabilities = []
        self.logs = []
        self.chains = []

db = Database()
