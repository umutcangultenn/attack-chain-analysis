import uuid
from typing import List, Dict, Any
from datetime import datetime
from app.models.attack_chain import AttackChain, ChainStep, ChainStepType
from app.models.log_event import LogEventType
from .risk_scorer import RiskScorer
from .root_cause import RootCauseAnalyzer

class ChainBuilder:
    """
    Constructs AttackChain objects from correlated vulnerabilities and logs.
    """
    def __init__(self):
        self.risk_scorer = RiskScorer()
        self.root_cause_analyzer = RootCauseAnalyzer()

    def build_chains(self, correlated_data: List[Dict[str, Any]]) -> List[AttackChain]:
        """
        Builds a list of AttackChain objects based on correlated data.
        
        Args:
            correlated_data: List of dicts containing 'vulnerability' and 'related_logs'.
            
        Returns:
            List[AttackChain]: A list of full attack scenarios with risk scores and root cause analysis.
        """
        chains = []
        
        if not correlated_data:
            return []

        for item in correlated_data:
            vuln = item["vulnerability"]
            logs = item["related_logs"]
            
            # Sort logs chronologically to tell a story
            logs.sort(key=lambda x: x.timestamp)
            
            steps = []
            
            # Create the initial step (Vulnerability Exploit Attempt)
            # In a real system, we might have multiple steps based on log types.
            step_id = str(uuid.uuid4())
            step = ChainStep(
                id=step_id,
                description=f"Potential exploit attempt for {vuln.name} detected on endpoint {vuln.url}",
                timestamp=logs[0].timestamp if logs else datetime.now(),
                step_type=ChainStepType.VULNERABILITY_EXPLOIT,
                related_vulnerability=vuln,
                related_logs=logs
            )
            steps.append(step)
            
            # Determine time range of the attack
            start_time = logs[0].timestamp if logs else datetime.now()
            end_time = logs[-1].timestamp if logs else datetime.now()
            
            # Aggregation of source IPs involved
            source_ips = list(set([log.source_ip for log in logs]))
            
            # Create a temporary chain object to perform analysis
            temp_chain = AttackChain(
                id=str(uuid.uuid4()),
                name=f"Attack Scenario: {vuln.name}",
                steps=steps,
                start_time=start_time,
                end_time=end_time,
                risk_score=0,
                source_ips=source_ips
            )
            
            # Calculate Risk Score (0-100)
            risk_score = self.risk_scorer.calculate(steps)
            
            # Perform Root Cause Analysis
            root_cause = self.root_cause_analyzer.analyze(temp_chain)
            
            # Create the final chain with all analysis results
            final_chain = temp_chain.model_copy(update={
                "risk_score": risk_score, 
                "root_cause_analysis": root_cause
            })
            
            chains.append(final_chain)
            
        return chains
