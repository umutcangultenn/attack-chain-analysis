from app.models.attack_chain import AttackChain, ChainStep
from app.models.vulnerability import VulnerabilityType

class RiskScorer:
    def calculate(self, chain_steps: list) -> int:
        score = 0
        
        for step in chain_steps:
            # Zafiyet kaynaklı risk
            if step.related_vulnerability:
                severity = step.related_vulnerability.severity.lower()
                if severity == "high":
                    score += 40
                elif severity == "medium":
                    score += 20
                elif severity == "low":
                    score += 10
            
            # Log olaylarından kaynaklı risk ekle
            for log in step.related_logs:
                if log.status_code and log.status_code >= 500:
                    score += 10
                if "UNION SELECT" in log.raw_log or "OR '1'='1" in log.raw_log:
                    score += 20
                
        return min(score, 100)
