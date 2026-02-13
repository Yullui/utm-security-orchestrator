"""
UTM Telemetry: Structured Audit Logging with Hash-Chain Integrity

Features:
- JSON-structured audit events
- HMAC-SHA256 tamper-evidence
- Hash-chain linking (blockchain-style)
- Sequence numbering for replay detection
- Role-based execution context tagging
- Forensic-grade logging for incident response

Usage:
    telemetry = ChainedAuditLog("audit.log", hmac_key=os.environ['UTM_LOG_KEY'])
    telemetry.log({
        "event": "command_executed",
        "user": "admin",
        "command": "ipconfig",
        "exit_code": 0
    })
    
    # Verify integrity
    is_valid, tampering_indices = telemetry.verify_integrity()
"""

import json
import hmac
import hashlib
import datetime
from typing import Dict, Tuple, List, Optional
from enum import Enum
import os


class EventSeverity(Enum):
    """Event severity classification"""
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class EventCategory(Enum):
    """Event categorization for forensic analysis"""
    AUTHENTICATION = "AUTHENTICATION"
    AUTHORIZATION = "AUTHORIZATION"
    COMMAND_EXECUTION = "COMMAND_EXECUTION"
    POLICY_CHANGE = "POLICY_CHANGE"
    THREAT_DETECTION = "THREAT_DETECTION"
    ARTIFACT_COLLECTION = "ARTIFACT_COLLECTION"
    LOG_VERIFICATION = "LOG_VERIFICATION"
    SYSTEM_STATE = "SYSTEM_STATE"


class ChainedAuditLog:
    """
    Tamper-evident audit log with hash-chaining for forensic integrity.
    
    Design:
    1. Each event is serialized as JSON (sorted keys for determinism)
    2. HMAC-SHA256 is computed over the event + previous hash
    3. Event is appended with its hash and sequence number
    4. If any event is modified, the chain breaks (detectable)
    5. Replay attacks are prevented via sequence numbering
    
    File format (one event per line):
    {"event": "...", "previous_hash": "...", "sequence": 0}|HMAC_DIGEST|EVENT_HASH
    """
    
    def __init__(self, log_path: str, hmac_key: Optional[str] = None):
        """
        Initialize chained audit logger.
        
        Args:
            log_path: Path to audit log file
            hmac_key: HMAC key (from environment if None)
        """
        self.log_path = log_path
        self.hmac_key = (hmac_key or os.environ.get('UTM_LOG_KEY', 'DEFAULT_KEY')).encode()
        self.event_chain: List[str] = []  # Hash chain
        self.sequence_counter = 0
        
        # Load existing chain if log exists
        if os.path.exists(log_path):
            self._load_existing_chain()
    
    def _load_existing_chain(self) -> None:
        """Load existing event chain from disk"""
        with open(self.log_path, 'r') as f:
            lines = f.readlines()
        
        for line in lines:
            if not line.strip():
                continue
            
            try:
                # Parse: event_json|event_hash
                event_str, event_hash = line.rsplit('|', 1)
                self.event_chain.append(event_hash.strip())
                self.sequence_counter += 1
            except ValueError:
                # Skip malformed lines
                pass
    
    def log(self, event_data: Dict, severity: EventSeverity = EventSeverity.INFO,
            category: EventCategory = EventCategory.SYSTEM_STATE) -> str:
        """
        Log an event with chain integrity.
        
        Args:
            event_data: Event dictionary
            severity: Event severity level
            category: Event classification
        
        Returns:
            Event hash (for reference in other logs)
        """
        
        # Get previous hash (or "0" * 64 for first event)
        prev_hash = self.event_chain[-1] if self.event_chain else "0" * 64
        
        # Build event with metadata
        event_with_metadata = {
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
            "severity": severity.value,
            "category": category.value,
            "sequence": self.sequence_counter,
            "previous_hash": prev_hash,
            **event_data
        }
        
        # Serialize deterministically (sorted keys)
        event_str = json.dumps(event_with_metadata, sort_keys=True, default=str)
        
        # Compute HMAC over event string
        h_hmac = hmac.new(self.hmac_key, event_str.encode(), hashlib.sha256)
        hmac_digest = h_hmac.hexdigest()
        
        # Compute event hash (for chain linking)
        h_event = hashlib.sha256(
            (prev_hash + event_str + hmac_digest).encode()
        )
        event_hash = h_event.hexdigest()
        
        # Write to log: event|event_hash (HMAC embedded in event)
        with open(self.log_path, 'a') as f:
            f.write(f"{event_str}|{event_hash}\n")
        
        # Update in-memory chain
        self.event_chain.append(event_hash)
        self.sequence_counter += 1
        
        return event_hash
    
    def verify_integrity(self) -> Tuple[bool, List[int]]:
        """
        Verify chain integrity and detect tampering.
        
        Returns:
            (is_valid, list_of_tampered_line_numbers)
        
        Example:
            is_valid, tampering = telemetry.verify_integrity()
            if not is_valid:
                for line_num in tampering:
                    print(f"Line {line_num}: Tampering detected!")
        """
        tampering_detected = []
        
        with open(self.log_path, 'r') as f:
            lines = f.readlines()
        
        prev_hash = "0" * 64
        
        for idx, line in enumerate(lines):
            if not line.strip():
                continue
            
            try:
                # Parse: event_json|event_hash
                event_str, claimed_hash = line.rsplit('|', 1)
                event_dict = json.loads(event_str)
                
                # 1. Verify HMAC
                h_hmac = hmac.new(self.hmac_key, event_str.encode(), hashlib.sha256)
                hmac_digest = h_hmac.hexdigest()
                
                # HMAC should be the same (it's deterministic)
                # If someone modifies event_str, HMAC will differ
                
                # 2. Verify event hash (chain linking)
                h_event = hashlib.sha256(
                    (prev_hash + event_str + hmac_digest).encode()
                )
                computed_hash = h_event.hexdigest()
                
                if computed_hash != claimed_hash.strip():
                    tampering_detected.append(idx)
                    continue
                
                # 3. Verify chain linkage (previous hash matches)
                if event_dict.get('previous_hash') != prev_hash:
                    tampering_detected.append(idx)
                    continue
                
                # 4. Verify sequence continuity
                if event_dict.get('sequence') != idx:
                    tampering_detected.append(idx)
                    continue
                
                # Update chain for next iteration
                prev_hash = claimed_hash.strip()
                
            except (ValueError, json.JSONDecodeError):
                tampering_detected.append(idx)
                continue
        
        return len(tampering_detected) == 0, tampering_detected
    
    def get_events_by_category(self, category: EventCategory) -> List[Dict]:
        """Query events by category (e.g., for incident investigation)"""
        events = []
        
        with open(self.log_path, 'r') as f:
            for line in f:
                if not line.strip():
                    continue
                
                try:
                    event_str, _ = line.rsplit('|', 1)
                    event_dict = json.loads(event_str)
                    
                    if event_dict.get('category') == category.value:
                        events.append(event_dict)
                except (ValueError, json.JSONDecodeError):
                    continue
        
        return sorted(events, key=lambda x: x.get('sequence', 0))
    
    def get_events_by_severity(self, min_severity: EventSeverity) -> List[Dict]:
        """Query events by minimum severity (WARNING, ERROR, CRITICAL)"""
        severity_order = {
            "INFO": 0,
            "WARNING": 1,
            "ERROR": 2,
            "CRITICAL": 3
        }
        
        min_level = severity_order.get(min_severity.value, 0)
        events = []
        
        with open(self.log_path, 'r') as f:
            for line in f:
                if not line.strip():
                    continue
                
                try:
                    event_str, _ = line.rsplit('|', 1)
                    event_dict = json.loads(event_str)
                    
                    event_level = severity_order.get(event_dict.get('severity'), 0)
                    if event_level >= min_level:
                        events.append(event_dict)
                except (ValueError, json.JSONDecodeError):
                    continue
        
        return sorted(events, key=lambda x: x.get('sequence', 0))
    
    def generate_forensic_report(self) -> Dict:
        """Generate forensic investigation report"""
        
        is_valid, tampering = self.verify_integrity()
        
        # Collect statistics
        all_events = []
        with open(self.log_path, 'r') as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    event_str, _ = line.rsplit('|', 1)
                    all_events.append(json.loads(event_str))
                except (ValueError, json.JSONDecodeError):
                    continue
        
        # Calculate event distribution
        category_counts = {}
        severity_counts = {}
        for event in all_events:
            category = event.get('category', 'UNKNOWN')
            severity = event.get('severity', 'UNKNOWN')
            category_counts[category] = category_counts.get(category, 0) + 1
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        report = {
            "report_timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
            "audit_log_path": self.log_path,
            "total_events": len(all_events),
            "integrity_status": "VALID" if is_valid else "TAMPERED",
            "tampering_detected_count": len(tampering),
            "tampering_line_numbers": tampering,
            "time_range": {
                "earliest": min([e.get('timestamp') for e in all_events]) if all_events else None,
                "latest": max([e.get('timestamp') for e in all_events]) if all_events else None
            },
            "event_distribution": {
                "by_category": category_counts,
                "by_severity": severity_counts
            },
            "critical_events": self.get_events_by_severity(EventSeverity.CRITICAL),
            "errors": self.get_events_by_severity(EventSeverity.ERROR)
        }
        
        return report
    
    def export_for_siem(self, output_path: str) -> None:
        """Export audit logs in JSON Lines format for SIEM ingestion"""
        
        events = []
        with open(self.log_path, 'r') as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    event_str, event_hash = line.rsplit('|', 1)
                    event_dict = json.loads(event_str)
                    event_dict['event_chain_hash'] = event_hash.strip()
                    events.append(event_dict)
                except (ValueError, json.JSONDecodeError):
                    continue
        
        # Write as JSON Lines (one event per line for streaming)
        with open(output_path, 'w') as f:
            for event in events:
                f.write(json.dumps(event) + '\n')


class TelemryContext:
    """Role-based execution context for audit logging"""
    
    def __init__(self, user: str, role: str, action: str, source_ip: Optional[str] = None):
        self.user = user
        self.role = role
        self.action = action
        self.source_ip = source_ip or "local"
        self.timestamp = datetime.datetime.now(datetime.UTC)
    
    def to_dict(self) -> Dict:
        return {
            "user": self.user,
            "role": self.role,
            "action": self.action,
            "source_ip": self.source_ip,
            "timestamp": self.timestamp.isoformat()
        }


# Example usage
if __name__ == '__main__':
    import tempfile
    
    # Create temp log
    with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
        log_path = f.name
    
    # Initialize audit log
    telemetry = ChainedAuditLog(log_path, hmac_key="test_key_12345")
    
    # Log events
    telemetry.log({
        "event": "orchestrator_started",
        "version": "3.0"
    }, severity=EventSeverity.INFO, category=EventCategory.SYSTEM_STATE)
    
    telemetry.log({
        "event": "command_executed",
        "command": "ipconfig",
        "exit_code": 0
    }, severity=EventSeverity.INFO, category=EventCategory.COMMAND_EXECUTION)
    
    telemetry.log({
        "event": "threat_detected",
        "malicious_ip": "192.0.2.1",
        "severity_level": "HIGH"
    }, severity=EventSeverity.WARNING, category=EventCategory.THREAT_DETECTION)
    
    # Verify integrity
    is_valid, tampering = telemetry.verify_integrity()
    print(f"Integrity check: {'VALID' if is_valid else 'TAMPERED'}")
    if tampering:
        print(f"Detected tampering at lines: {tampering}")
    
    # Generate report
    report = telemetry.generate_forensic_report()
    print(json.dumps(report, indent=2))
    
    # Cleanup
    import os
    os.unlink(log_path)
