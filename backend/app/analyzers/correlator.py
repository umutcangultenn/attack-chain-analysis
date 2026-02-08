from typing import List, Dict, Any
from app.models.vulnerability import Vulnerability
from app.models.log_event import LogEvent, LogEventType

class Correlator:
    def __init__(self):
        pass

    def correlate(self, vulnerabilities: List[Vulnerability], logs: List[LogEvent]) -> List[Dict[str, Any]]:
        """
        Zafiyetleri ve Logları analiz ederek ilişkili olanları gruplar.
        Döndürülen yapı: [{ "vulnerability": vuln, "related_logs": [log1, log2] }]
        """
        correlated_events = []
        
        # Basit bir korelasyon mantığı:
        # Zafiyet URL'i ile Log Endpoint'i eşleşiyorsa ilişkilendir.
        
        for vuln in vulnerabilities:
            related_logs = []
            vuln_path = self._extract_path(vuln.url)
            
            for log in logs:
                if self._is_related(vuln, vuln_path, log):
                    related_logs.append(log)
            
            if related_logs:
                correlated_events.append({
                    "vulnerability": vuln,
                    "related_logs": related_logs
                })
                
        return correlated_events

    def _extract_path(self, url: str) -> str:
        # http://target.com/path/to/resource?query=1 -> /path/to/resource
        path = url
        if "://" in url:
            try:
                path = "/" + url.split("://")[1].split("/", 1)[1]
            except IndexError:
                path = "/"
        
        # Remove query parameters
        if "?" in path:
            path = path.split("?")[0]
            
        return path

    def _is_related(self, vuln: Vulnerability, vuln_path: str, log: LogEvent) -> bool:
        # 1. Base Endpoint match
        if log.endpoint:
            log_base_path = log.endpoint.split("?")[0] if "?" in log.endpoint else log.endpoint
            if vuln_path == log_base_path:
                return True
                
        # 2. Evidence match (if evidence exists and is in raw log)
        if vuln.evidence and log.raw_log and vuln.evidence in log.raw_log:
            return True
            
        return False
            
        # 2. Evidence match (if evidence exists and is in raw log)
        if vuln.evidence and log.raw_log and vuln.evidence in log.raw_log:
            return True
            
        return False
