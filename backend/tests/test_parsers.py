import pytest
import os
from app.parsers.zap_parser import ZapParser
from app.parsers.log_parser import LogParser
from app.models.vulnerability import VulnerabilityType
from app.models.log_event import LogEventType

SAMPLE_DATA_DIR = os.path.join(os.path.dirname(__file__), "../sample_data")
ZAP_REPORT_PATH = os.path.join(SAMPLE_DATA_DIR, "zap_report_sample.json")
ACCESS_LOG_PATH = os.path.join(SAMPLE_DATA_DIR, "sample_logs/access.log")
AUTH_LOG_PATH = os.path.join(SAMPLE_DATA_DIR, "sample_logs/auth.log")

def test_zap_parser():
    parser = ZapParser()
    vulnerabilities = parser.parse(ZAP_REPORT_PATH)
    
    assert len(vulnerabilities) > 0
    
    # Check SQL Injection
    sqli = next((v for v in vulnerabilities if v.type == VulnerabilityType.SQL_INJECTION), None)
    assert sqli is not None
    assert "products.php" in sqli.url
    assert sqli.severity == "High"

def test_access_log_parser():
    parser = LogParser()
    events = parser.parse(ACCESS_LOG_PATH, log_type="access")
    
    assert len(events) > 0
    
    # Check for specific event
    error_event = next((e for e in events if e.status_code == 500), None)
    assert error_event is not None
    assert error_event.type == LogEventType.ERROR
    assert "192.168.1.10" in error_event.source_ip

def test_auth_log_parser():
    parser = LogParser()
    events = parser.parse(AUTH_LOG_PATH, log_type="auth")
    
    assert len(events) > 0
    
    # Check for failure
    fail_event = next((e for e in events if e.type == LogEventType.AUTH_FAILURE), None)
    assert fail_event is not None
    assert "192.168.1.50" in fail_event.source_ip
