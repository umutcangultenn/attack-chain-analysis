import pytest
from datetime import datetime
from app.models.vulnerability import Vulnerability, VulnerabilityType
from app.models.log_event import LogEvent, LogEventType
from app.analyzers.correlator import Correlator
from app.analyzers.chain_builder import ChainBuilder
from app.analyzers.risk_scorer import RiskScorer

def test_correlator():
    correlator = Correlator()
    
    vuln = Vulnerability(
        id="1", type=VulnerabilityType.SQL_INJECTION, name="SQLi", 
        description="desc", severity="High", url="http://site.com/vuln", method="GET"
    )
    
    log1 = LogEvent(
        timestamp=datetime.now(), source_ip="1.1.1.1", 
        endpoint="/vuln", status_code=200, raw_log="GET /vuln", type=LogEventType.ACCESS
    )
    
    log2 = LogEvent(
        timestamp=datetime.now(), source_ip="1.1.1.1", 
        endpoint="/safe", status_code=200, raw_log="GET /safe", type=LogEventType.ACCESS
    )
    
    results = correlator.correlate([vuln], [log1, log2])
    
    assert len(results) == 1
    assert results[0]["vulnerability"] == vuln
    assert len(results[0]["related_logs"]) == 1
    assert results[0]["related_logs"][0] == log1

def test_risk_scorer_and_chain_builder():
    builder = ChainBuilder()
    
    vuln = Vulnerability(
        id="1", type=VulnerabilityType.SQL_INJECTION, name="SQLi", 
        description="desc", severity="High", url="http://site.com/vuln", method="GET"
    )
    
    log = LogEvent(
        timestamp=datetime.now(), source_ip="1.1.1.1", 
        endpoint="/vuln", status_code=500, raw_log="GET /vuln UNION SELECT", type=LogEventType.ERROR
    )
    
    correlated_data = [{"vulnerability": vuln, "related_logs": [log]}]
    
    chains = builder.build_chains(correlated_data)
    
    assert len(chains) == 1
    chain = chains[0]
    
    # Check Score: High Vuln (40) + Error 500 (10) + Keyword UNION (20) = 70
    assert chain.risk_score == 70
    assert "SQLi" in chain.root_cause_analysis
