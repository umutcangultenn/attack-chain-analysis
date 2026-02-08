import re
import logging
from typing import List, Optional
from datetime import datetime
from app.models.log_event import LogEvent, LogEventType

logger = logging.getLogger(__name__)

class LogParser:
    def __init__(self):
        # Apache/Nginx combined format regex
        # 127.0.0.1 - - [18/Jan/2024:10:30:05 +0000] "GET /path HTTP/1.1" 200 1234
        self.access_log_pattern = re.compile(
            r'(?P<ip>[\d\.]+)\s-\s-\s\[(?P<timestamp>.*?)\]\s"(?P<method>\w+)\s(?P<uri>.*?)\sHTTP/.*?"\s(?P<status>\d+)\s(?P<size>\d+)(?:\s"(?P<referrer>.*?)"\s"(?P<user_agent>.*?)")?'
        )
        
        # Auth log pattern example
        # Jan 18 10:35:00 server sshd[1234]: Failed password for invalid user admin from 192.168.1.50
        self.auth_log_pattern = re.compile(
            r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+.*?(?P<message>.*)'
        )

    def parse(self, log_path: str, log_type: str = "access") -> List[LogEvent]:
        """
        Log dosyasını parse eder ve LogEvent listesi döndürür.
        log_type: "access" veya "auth"
        """
        events = []
        try:
            with open(log_path, 'r', encoding='utf-8') as f:
                for line in f:
                    event = None
                    if log_type == "access":
                        event = self._parse_access_log_line(line)
                    elif log_type == "auth":
                        event = self._parse_auth_log_line(line)
                    
                    if event:
                        events.append(event)
            return events
        except Exception as e:
            logger.error(f"Error parsing log file {log_path}: {e}")
            return []

    def _parse_access_log_line(self, line: str) -> Optional[LogEvent]:
        match = self.access_log_pattern.match(line)
        if not match:
            return None
        
        data = match.groupdict()
        status = int(data["status"])
        
        # Determine LogEventType
        event_type = LogEventType.ACCESS
        if status >= 500:
            event_type = LogEventType.ERROR
        elif status == 401 or status == 403:
            event_type = LogEventType.AUTH_FAILURE
        
        # Parse timestamp (Simplified for example, might need clearer format handling)
        # 18/Jan/2024:10:30:05 +0000
        try:
             # Basic stripping of timezone for simplicity in this prototype, or use specific format
             ts_str = data["timestamp"].split(" ")[0]
             timestamp = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S")
        except ValueError:
            timestamp = datetime.now() # Fallback

        return LogEvent(
            timestamp=timestamp,
            source_ip=data["ip"],
            method=data["method"],
            endpoint=data["uri"],
            status_code=status,
            user_agent=data.get("user_agent"),
            raw_log=line.strip(),
            type=event_type
        )

    def _parse_auth_log_line(self, line: str) -> Optional[LogEvent]:
        # Very basic auth log parsing
        match = self.auth_log_pattern.match(line)
        if not match:
            return None
            
        data = match.groupdict()
        message = data["message"]
        
        # Extract IP if possible
        ip_match = re.search(r'from\s+(?P<ip>[\d\.]+)', message)
        ip = ip_match.group("ip") if ip_match else "0.0.0.0"
        
        event_type = LogEventType.UNKNOWN
        if "Failed password" in message or "authentication failure" in message.lower():
            event_type = LogEventType.AUTH_FAILURE
        elif "Accepted password" in message or "session opened" in message.lower():
            event_type = LogEventType.AUTH_SUCCESS
            
        # Timestamp parsing for syslog format (Jan 18 10:35:00) - year is missing usually
        # We'll assume current year for this prototype or handle it carefully
        try:
            ts_str = f"{data['timestamp']} {datetime.now().year}"
            timestamp = datetime.strptime(ts_str, "%b %d %H:%M:%S %Y")
        except ValueError:
            timestamp = datetime.now()

        return LogEvent(
            timestamp=timestamp,
            source_ip=ip,
            raw_log=line.strip(),
            type=event_type
        )
