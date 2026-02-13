"""
Unit tests for utm_telemetry.py - Chained audit logging with tamper-evidence

Tests cover:
- Event logging with HMAC integrity
- Hash-chain linking and tampering detection
- Sequence verification
- Forensic report generation
- SIEM export
"""

import pytest
import json
import os
import tempfile
from utm_telemetry import ChainedAuditLog, EventSeverity, EventCategory


class TestChainedAuditLog:
    """Test chained audit log functionality"""
    
    @pytest.fixture
    def temp_log(self):
        """Create temporary log file for testing"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
            log_path = f.name
        yield log_path
        # Cleanup
        if os.path.exists(log_path):
            os.unlink(log_path)
    
    def test_initialization(self, temp_log):
        """Test audit log initializes correctly"""
        log = ChainedAuditLog(temp_log, hmac_key="test_key")
        assert log.log_path == temp_log
        assert log.sequence_counter == 0
        assert len(log.event_chain) == 0
    
    def test_single_event_logging(self, temp_log):
        """Test logging a single event"""
        log = ChainedAuditLog(temp_log, hmac_key="test_key")
        
        event_hash = log.log(
            {"event": "test", "value": 123},
            severity=EventSeverity.INFO
        )
        
        assert event_hash is not None
        assert len(event_hash) == 64  # SHA256
        assert log.sequence_counter == 1
        assert len(log.event_chain) == 1
    
    def test_multiple_events_chaining(self, temp_log):
        """Test that events are properly chained"""
        log = ChainedAuditLog(temp_log, hmac_key="test_key")
        
        hash1 = log.log({"event": "first"})
        hash2 = log.log({"event": "second"})
        hash3 = log.log({"event": "third"})
        
        # All hashes should be different
        assert hash1 != hash2
        assert hash2 != hash3
        assert hash1 != hash3
        
        # Sequence should increment
        assert log.sequence_counter == 3
        assert len(log.event_chain) == 3
    
    def test_integrity_verification_valid(self, temp_log):
        """Test that valid logs pass integrity check"""
        log = ChainedAuditLog(temp_log, hmac_key="test_key")
        
        log.log({"event": "event1"})
        log.log({"event": "event2"})
        log.log({"event": "event3"})
        
        is_valid, tampering = log.verify_integrity()
        assert is_valid is True
        assert len(tampering) == 0
    
    def test_tampering_detection(self, temp_log):
        """Test that file tampering is detected"""
        log = ChainedAuditLog(temp_log, hmac_key="test_key")
        
        log.log({"event": "event1"})
        log.log({"event": "event2"})
        log.log({"event": "event3"})
        
        # Tamper with second event (modify JSON)
        with open(temp_log, 'r') as f:
            lines = f.readlines()
        
        # Modify the event value in line 1 (0-indexed)
        event_str, hash_val = lines[1].rsplit('|', 1)
        event_dict = json.loads(event_str)
        event_dict['event'] = "TAMPERED"
        modified_event_str = json.dumps(event_dict, sort_keys=True)
        
        with open(temp_log, 'w') as f:
            f.write(lines[0])
            f.write(f"{modified_event_str}|{hash_val}")
            f.writelines(lines[2:])
        
        # Reload and verify
        log2 = ChainedAuditLog(temp_log, hmac_key="test_key")
        is_valid, tampering = log2.verify_integrity()
        
        assert is_valid is False
        assert 1 in tampering  # Line 1 should be detected as tampered
    
    def test_chain_break_detection(self, temp_log):
        """Test detection when chain is broken (sequence skipped)"""
        log = ChainedAuditLog(temp_log, hmac_key="test_key")
        
        log.log({"event": "event1"})
        log.log({"event": "event2"})
        log.log({"event": "event3"})
        
        # Modify sequence number in event 2
        with open(temp_log, 'r') as f:
            lines = f.readlines()
        
        event_str, hash_val = lines[1].rsplit('|', 1)
        event_dict = json.loads(event_str)
        event_dict['sequence'] = 99  # Wrong sequence
        modified_event_str = json.dumps(event_dict, sort_keys=True)
        
        with open(temp_log, 'w') as f:
            f.write(lines[0])
            f.write(f"{modified_event_str}|{hash_val}")
            f.writelines(lines[2:])
        
        # Verify detects chain break
        log2 = ChainedAuditLog(temp_log, hmac_key="test_key")
        is_valid, tampering = log2.verify_integrity()
        
        assert is_valid is False
        assert 1 in tampering
    
    def test_severity_filtering(self, temp_log):
        """Test filtering events by severity"""
        log = ChainedAuditLog(temp_log, hmac_key="test_key")
        
        log.log({"event": "info1"}, severity=EventSeverity.INFO)
        log.log({"event": "warn1"}, severity=EventSeverity.WARNING)
        log.log({"event": "error1"}, severity=EventSeverity.ERROR)
        log.log({"event": "crit1"}, severity=EventSeverity.CRITICAL)
        
        # Query events >= WARNING
        warnings_up = log.get_events_by_severity(EventSeverity.WARNING)
        assert len(warnings_up) == 3  # WARNING, ERROR, CRITICAL
        
        # Query events >= CRITICAL
        criticals = log.get_events_by_severity(EventSeverity.CRITICAL)
        assert len(criticals) == 1
    
    def test_category_filtering(self, temp_log):
        """Test filtering events by category"""
        log = ChainedAuditLog(temp_log, hmac_key="test_key")
        
        log.log(
            {"event": "login"},
            category=EventCategory.AUTHENTICATION
        )
        log.log(
            {"event": "access_denied"},
            category=EventCategory.AUTHORIZATION
        )
        log.log(
            {"event": "cmd_exec"},
            category=EventCategory.COMMAND_EXECUTION
        )
        log.log(
            {"event": "threat"},
            category=EventCategory.THREAT_DETECTION
        )
        
        # Query by category
        cmd_events = log.get_events_by_category(EventCategory.COMMAND_EXECUTION)
        assert len(cmd_events) == 1
        assert cmd_events[0].get('event') == 'cmd_exec'
        
        threat_events = log.get_events_by_category(EventCategory.THREAT_DETECTION)
        assert len(threat_events) == 1
    
    def test_forensic_report(self, temp_log):
        """Test forensic report generation"""
        log = ChainedAuditLog(temp_log, hmac_key="test_key")
        
        log.log(
            {"event": "started"},
            severity=EventSeverity.INFO,
            category=EventCategory.SYSTEM_STATE
        )
        log.log(
            {"event": "critical_issue"},
            severity=EventSeverity.CRITICAL,
            category=EventCategory.THREAT_DETECTION
        )
        
        report = log.generate_forensic_report()
        
        assert report['total_events'] == 2
        assert report['integrity_status'] == 'VALID'
        assert report['tampering_detected_count'] == 0
        assert 'by_category' in report['event_distribution']
        assert 'by_severity' in report['event_distribution']
    
    def test_siem_export(self, temp_log):
        """Test SIEM export in JSON Lines format"""
        log = ChainedAuditLog(temp_log, hmac_key="test_key")
        
        log.log({"event": "event1", "data": "test1"})
        log.log({"event": "event2", "data": "test2"})
        
        # Export to separate file
        siem_path = temp_log + ".siem.jsonl"
        log.export_for_siem(siem_path)
        
        try:
            # Verify SIEM export
            with open(siem_path, 'r') as f:
                lines = f.readlines()
            
            assert len(lines) == 2
            
            # Each line should be valid JSON
            for line in lines:
                event = json.loads(line)
                assert 'timestamp' in event
                assert 'event_chain_hash' in event  # Added by export
        finally:
            if os.path.exists(siem_path):
                os.unlink(siem_path)
    
    def test_persistence_across_instances(self, temp_log):
        """Test that log persists across instances"""
        # First instance
        log1 = ChainedAuditLog(temp_log, hmac_key="test_key")
        log1.log({"event": "from_instance_1"})
        log1.log({"event": "another_from_1"})
        
        # Second instance (loads existing chain)
        log2 = ChainedAuditLog(temp_log, hmac_key="test_key")
        assert log2.sequence_counter == 2
        assert len(log2.event_chain) == 2
        
        # Add more events
        log2.log({"event": "from_instance_2"})
        
        # Verify all events are there
        assert log2.sequence_counter == 3
        
        # Verify integrity
        is_valid, tampering = log2.verify_integrity()
        assert is_valid is True
    
    def test_empty_log(self, temp_log):
        """Test empty log handling"""
        log = ChainedAuditLog(temp_log, hmac_key="test_key")
        
        # Verify empty log is valid
        is_valid, tampering = log.verify_integrity()
        assert is_valid is True
        assert len(tampering) == 0
    
    def test_different_hmac_keys_fail(self, temp_log):
        """Test that events signed with one key fail verification with another"""
        # Log with key1
        log1 = ChainedAuditLog(temp_log, hmac_key="key1")
        log1.log({"event": "event1"})
        
        # Verify with key2 (should fail)
        log2 = ChainedAuditLog(temp_log, hmac_key="key2")
        is_valid, tampering = log2.verify_integrity()
        
        assert is_valid is False  # HMAC verification fails with different key
        assert len(tampering) > 0


class TestEventSeverity:
    """Test EventSeverity enum"""
    
    def test_severity_values(self):
        """Verify severity values"""
        assert EventSeverity.INFO.value == "INFO"
        assert EventSeverity.WARNING.value == "WARNING"
        assert EventSeverity.ERROR.value == "ERROR"
        assert EventSeverity.CRITICAL.value == "CRITICAL"


class TestEventCategory:
    """Test EventCategory enum"""
    
    def test_category_values(self):
        """Verify category values"""
        assert EventCategory.AUTHENTICATION.value == "AUTHENTICATION"
        assert EventCategory.COMMAND_EXECUTION.value == "COMMAND_EXECUTION"
        assert EventCategory.THREAT_DETECTION.value == "THREAT_DETECTION"
        assert EventCategory.POLICY_CHANGE.value == "POLICY_CHANGE"


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
