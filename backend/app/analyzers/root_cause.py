from typing import Optional
from app.models.attack_chain import AttackChain

class RootCauseAnalyzer:
    def analyze(self, chain: AttackChain) -> str:
        if not chain.steps:
            return "No steps in attack chain."
            
        # Basit mantık: İlk adım zafiyet sömürüsü ise kök neden odur.
        first_step = chain.steps[0]
        
        if first_step.related_vulnerability:
            vuln = first_step.related_vulnerability
            return (
                f"Saldırı, '{vuln.name}' zafiyetinin sömürülmesiyle başladı. "
                f"Zafiyet '{vuln.url}' adresinde tespit edildi. "
                f"Öneri: {vuln.solution if vuln.solution else 'İlgili endpointi kontrol edin.'}"
            )
            
        return "Saldırının kesin kök nedeni belirlenemedi, ancak şüpheli log aktiviteleriyle başladı."
