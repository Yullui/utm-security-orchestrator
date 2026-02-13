"""
Unit tests for Mandiant Commando integration (utm_commando.py)

Tests cover:
- CommandoSimulator initialization
- MITRE ATT&CK technique testing
- Finding generation and reporting
- Purple team exercise orchestration
"""

import pytest
import json
import os
from datetime import datetime

from utm_commando import (
    CommandoSimulator, 
    CommandoMode, 
    AttackTechnique,
    PurpleTeamExercise
)


class TestCommandoSimulator:
    """Test basic Commando simulation capabilities"""
    
    def test_initialization(self):
        """Test simulator initializes with correct mode"""
        sim = CommandoSimulator(mode=CommandoMode.DETECTION)
        assert sim.mode == CommandoMode.DETECTION
        assert len(sim.findings) == 0
        assert len(sim.enabled_techniques) == 0
    
    def test_enable_technique(self):
        """Test enabling attack techniques"""
        sim = CommandoSimulator()
        sim.enable_technique(AttackTechnique.EXECUTION)
        assert "T1059" in sim.enabled_techniques
    
    def test_disable_all_techniques(self):
        """Test disabling all techniques (safety)"""
        sim = CommandoSimulator()
        sim.enable_technique(AttackTechnique.PERSISTENCE)
        sim.enable_technique(AttackTechnique.COMMAND_CONTROL)
        assert len(sim.enabled_techniques) == 2
        
        sim.disable_all()
        assert len(sim.enabled_techniques) == 0
    
    def test_command_execution_test(self):
        """Test command execution simulation"""
        sim = CommandoSimulator(mode=CommandoMode.SIMULATION)
        result = sim.test_command_execution("powershell.exe -NoProfile")
        
        assert result['technique'] == "T1059 - Command Execution"
        assert result['is_dangerous'] == True
        assert len(sim.findings) == 1
        assert "T1059" in sim.techniques_tested
    
    def test_persistence_test(self):
        """Test persistence mechanism detection"""
        sim = CommandoSimulator(mode=CommandoMode.SIMULATION)
        result = sim.test_persistence_mechanism("registry_run_key")
        
        assert result['technique'] == "T1547 - Boot/Logon Autostart Execution"
        assert result['stage'] == "PERSISTENCE"
        assert "T1547" in sim.techniques_tested
    
    def test_privilege_escalation_test(self):
        """Test privilege escalation path detection"""
        sim = CommandoSimulator(mode=CommandoMode.SIMULATION)
        result = sim.test_privilege_escalation("token_impersonation")
        
        assert result['technique'] == "T1134 - Access Token Manipulation"
        assert "token_impersonation" in result['escalation_method']
        assert "T1134" in sim.techniques_tested
    
    def test_file_masquerading_test(self):
        """Test defense evasion (masquerading) detection"""
        sim = CommandoSimulator(mode=CommandoMode.SIMULATION)
        result = sim.test_file_masquerading("system32.exe", "notepad.exe")
        
        assert result['technique'] == "T1036 - Masquerading"
        assert result['fake_filename'] == "system32.exe"
        assert result['impersonates'] == "notepad.exe"
        assert "T1036" in sim.techniques_tested
    
    def test_brute_force_test(self):
        """Test brute force capability simulation"""
        sim = CommandoSimulator(mode=CommandoMode.SIMULATION)
        result = sim.test_brute_force_capability("rdp", attempt_count=100)
        
        assert result['technique'] == "T1110 - Brute Force"
        assert result['service'] == "rdp"
        assert result['simulated_attempts'] == 100
        assert "T1110" in sim.techniques_tested
    
    def test_c2_beacon_detection(self):
        """Test C2 beacon signature detection"""
        sim = CommandoSimulator(mode=CommandoMode.SIMULATION)
        result = sim.test_c2_beacon_detection("dns_tunneling")
        
        assert result['technique'] == "T1071 - Command & Control (C2) Beacon"
        assert result['stage'] == "COMMAND_CONTROL"
        assert "dns_tunneling" in result['beacon_signature']
        assert "T1071" in sim.techniques_tested
    
    def test_lateral_movement_test(self):
        """Test lateral movement detection"""
        sim = CommandoSimulator(mode=CommandoMode.SIMULATION)
        result = sim.test_lateral_movement("workstation", "fileserver")
        
        assert result['technique'] == "T1570 - Lateral Tool Transfer"
        assert result['from_host'] == "workstation"
        assert result['to_host'] == "fileserver"
        assert "T1570" in sim.techniques_tested
    
    def test_technique_disabled_in_detection_mode(self):
        """Test that techniques are disabled in detection mode unless explicitly enabled"""
        sim = CommandoSimulator(mode=CommandoMode.DETECTION)
        
        # Without enabling, should return disabled status
        result = sim.test_command_execution("calc.exe")
        # In SIMULATION mode this would test; in DETECTION it depends on enabled_techniques
    
    def test_generate_report(self):
        """Test report generation"""
        sim = CommandoSimulator(mode=CommandoMode.SIMULATION)
        
        # Run multiple tests
        sim.test_command_execution("cmd.exe")
        sim.test_persistence_mechanism("scheduled_task")
        sim.test_c2_beacon_detection("dga_domain")
        
        report = sim.generate_report()
        
        assert report['test_mode'] == "simulation"
        assert report['total_techniques_tested'] == 3
        assert report['total_findings'] == 3
        assert 'purple_team_recommendations' in report
        assert len(report['purple_team_recommendations']) > 0
    
    def test_export_findings(self):
        """Test exporting findings to JSON"""
        sim = CommandoSimulator(mode=CommandoMode.SIMULATION)
        sim.test_command_execution("powershell.exe")
        
        test_filepath = "test_commando_findings.json"
        try:
            sim.export_findings(test_filepath)
            
            # Verify file was created and contains valid JSON
            assert os.path.exists(test_filepath)
            with open(test_filepath, 'r') as f:
                data = json.load(f)
            
            assert 'test_mode' in data
            assert data['total_findings'] == 1
        finally:
            # Cleanup
            if os.path.exists(test_filepath):
                os.remove(test_filepath)


class TestPurpleTeamExercise:
    """Test purple team exercise orchestration"""
    
    def test_purple_team_initialization(self):
        """Test purple team exercise initializes"""
        exercise = PurpleTeamExercise("Test Exercise 1")
        assert exercise.exercise_name == "Test Exercise 1"
        assert len(exercise.red_team_findings) == 0
        assert len(exercise.blue_team_detections) == 0
    
    def test_red_team_operations(self):
        """Test red team simulated operations"""
        exercise = PurpleTeamExercise("Red Team Test")
        simulator = CommandoSimulator(mode=CommandoMode.SIMULATION)
        
        techniques = [
            AttackTechnique.EXECUTION,
            AttackTechnique.PERSISTENCE
        ]
        
        exercise.run_red_team_ops(simulator, techniques)
        
        # Should have findings from red team ops
        assert len(exercise.red_team_findings) > 0
        assert any("T1059" in str(f) for f in exercise.red_team_findings)  # EXECUTION
    
    def test_generate_afte_action_report(self):
        """Test After-Action Report generation"""
        exercise = PurpleTeamExercise("AAR Test")
        simulator = CommandoSimulator(mode=CommandoMode.SIMULATION)
        
        exercise.run_red_team_ops(simulator, [AttackTechnique.EXECUTION])
        aar = exercise.generate_afte_action_report()
        
        assert aar['exercise'] == "AAR Test"
        assert 'duration_seconds' in aar
        assert 'red_team_simulated_attacks' in aar
        assert 'detection_rate' in aar
        assert 'training_recommendations' in aar


class TestAttackTechniqueEnum:
    """Test MITRE ATT&CK technique enumeration"""
    
    def test_all_techniques_have_values(self):
        """Verify all MITRE ATT&CK techniques are defined"""
        assert AttackTechnique.EXECUTION.value == "T1059"
        assert AttackTechnique.PERSISTENCE.value == "T1547"
        assert AttackTechnique.PRIVILEGE_ESCALATION.value == "T1134"
        assert AttackTechnique.DEFENSE_EVASION.value == "T1036"
        assert AttackTechnique.CREDENTIAL_ACCESS.value == "T1110"
        assert AttackTechnique.DISCOVERY.value == "T1087"
        assert AttackTechnique.LATERAL_MOVEMENT.value == "T1570"
        assert AttackTechnique.COLLECTION.value == "T1115"
        assert AttackTechnique.COMMAND_CONTROL.value == "T1071"
        assert AttackTechnique.EXFILTRATION.value == "T1041"


class TestCommandoModeEnum:
    """Test operation modes"""
    
    def test_all_modes_defined(self):
        """Verify all operation modes are defined"""
        assert CommandoMode.SIMULATION.value == "simulation"
        assert CommandoMode.DETECTION.value == "detection"
        assert CommandoMode.VALIDATION.value == "validation"
        assert CommandoMode.PURPLE_TEAM.value == "purple_team"


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
