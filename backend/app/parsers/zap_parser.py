import json
import logging
from typing import List, Dict, Any
from app.models.vulnerability import Vulnerability, VulnerabilityType

logger = logging.getLogger(__name__)

class ZapParser:
    def __init__(self):
        pass

    def parse(self, report_path: str) -> List[Vulnerability]:
        """
        OWASP ZAP JSON raporunu parse eder ve Vulnerability listesi döndürür.
        """
        try:
            with open(report_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            vulnerabilities = []
            
            # ZAP rapor formatı: data["site"] -> list of sites
            sites = data.get("site", [])
            for site in sites:
                alerts = site.get("alerts", [])
                for alert in alerts:
                    vulnerabilities.extend(self._process_alert(alert))
            
            return vulnerabilities
        
        except Exception as e:
            logger.error(f"Error parsing ZAP report: {e}")
            return []

    def _process_alert(self, alert: Dict[str, Any]) -> List[Vulnerability]:
        """
        Tek bir ZAP alertini işler ve instance'ları Vulnerability objelerine çevirir.
        """
        vulnerabilities = []
        name = alert.get("name", "Unknown Vulnerability")
        desc = alert.get("desc", "")
        solution = alert.get("solution", "")
        risk_desc = alert.get("riskdesc", "Info")
        
        # Risk seviyesini belirle
        severity = "Info"
        if "High" in risk_desc:
            severity = "High"
        elif "Medium" in risk_desc:
            severity = "Medium"
        elif "Low" in risk_desc:
            severity = "Low"
            
        vuln_type = self._map_vuln_type(name)
        
        instances = alert.get("instances", [])
        for i, instance in enumerate(instances):
            vuln = Vulnerability(
                id=f"{alert.get('pluginid', '0')}-{i}",
                type=vuln_type,
                name=name,
                description=desc,
                severity=severity,
                url=instance.get("uri", ""),
                method=instance.get("method", "GET"),
                evidence=instance.get("evidence", ""),
                solution=solution
            )
            vulnerabilities.append(vuln)
            
        return vulnerabilities

    def _map_vuln_type(self, name: str) -> VulnerabilityType:
        """
        ZAP alert ismini VulnerabilityType enum'ına eşler.
        """
        name_lower = name.lower()
        if "sql" in name_lower:
            return VulnerabilityType.SQL_INJECTION
        elif "cross site scripting" in name_lower or "xss" in name_lower:
            return VulnerabilityType.XSS
        elif "remote code execution" in name_lower or "rce" in name_lower:
            return VulnerabilityType.RCE
        elif "disclosure" in name_lower or "exposure" in name_lower:
            return VulnerabilityType.SENSITIVE_DATA_EXPOSURE
        elif "auth" in name_lower or "session" in name_lower:
            return VulnerabilityType.AUTH_BYPASS
        
        return VulnerabilityType.OTHER
