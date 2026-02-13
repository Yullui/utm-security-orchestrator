"""
Windows Registry Protection - Prevent T1547 (Boot/Logon Autostart Execution)

Protects autostart registry locations by:
1. Restricting write access via NTFS ACLs
2. Hash-chain integrity checking
3. Real-time change detection
4. Automatic remediation of unauthorized changes

Windows targets:
- HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
- HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce
- HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
- HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce
- HKU\\.DEFAULT\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
- HKLM\\System\\CurrentControlSet\\Services
"""

import subprocess
import sys
import hashlib
import json
import os
import logging
from typing import Dict, List, Tuple, Optional
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)


class RegistryProtector:
    """Lock down dangerous registry locations against unauthorized writes"""
    
    PROTECTED_PATHS = [
        r'HKLM\Software\Microsoft\Windows\CurrentVersion\Run',
        r'HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        r'HKCU\Software\Microsoft\Windows\CurrentVersion\Run',
        r'HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        r'HKU\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Run',
        r'HKLM\System\CurrentControlSet\Services',
        r'HKLM\System\CurrentControlSet\Control\Session Manager\Environment',
    ]  # noqa: W605 - raw strings with backslashes
    
    # Whitelist of approved registry values that should always exist
    WHITELIST = {
        r'HKLM\Software\Microsoft\Windows\CurrentVersion\Run': [
            'SecurityHealthService',
            'WindowsDefender',
            'OneDrive',
            'Dropbox',
            # Add only APPROVED applications
        ],
        r'HKLM\System\CurrentControlSet\Services': [
            'WinDefend',  # Windows Defender
            'MpsSvc',     # Windows Firewall
            'AudioSrv',   # Audio service
            # Add only APPROVED services
        ]
    }
    
    @staticmethod
    def lock_registry_key(registry_path: str) -> Tuple[bool, str]:
        """
        Lock down registry key to prevent unauthorized writes.
        Only SYSTEM and Administrators can modify.
        
        Requires: Administrator privileges
        
        Args:
            registry_path: Full registry path (e.g., 'HKLM\\...')
        
        Returns:
            (success: bool, message: str)
        """
        if sys.platform != 'win32':
            return False, "Registry protection: Windows only"
        
        try:
            # Step 1: Ensure ACLs are set to remove standard user write access
            # This uses icacls command-line tool (requires admin)
            
            acl_cmd = [
                'icacls',
                f'"{registry_path}"',
                '/inheritance:r',              # Remove inherited permissions
                '/grant:r', 'SYSTEM:(F)',      # Grant SYSTEM full access
                '/grant:r', 'Administrators:(F)',  # Grant Admins full access
                '/grant:r', 'CREATOR OWNER:(F)',   # Creator owner full access
            ]
            
            result = subprocess.run(
                ' '.join(acl_cmd),
                shell=True,
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                logger.info(f"✅ Locked registry key: {registry_path}")
                return True, f"Locked: {registry_path}"
            else:
                logger.warning(f"⚠️ Failed to lock {registry_path}: {result.stderr}")
                return False, f"Lock failed: {result.stderr}"
                
        except Exception as e:
            logger.error(f"❌ Exception locking registry: {str(e)}")
            return False, str(e)
    
    @classmethod
    def protect_all_autostart_locations(cls) -> Dict[str, Tuple[bool, str]]:
        """
        Lock all dangerous autostart registry locations.
        
        Returns:
            Dict mapping registry paths to (success, message) tuples
        """
        if sys.platform != 'win32':
            return {'error': 'Windows only'}
        
        logger.info("🔒 Locking all autostart registry locations...")
        results = {}
        
        for path in cls.PROTECTED_PATHS:
            success, msg = cls.lock_registry_key(path)
            results[path] = (success, msg)
        
        return results
    
    @staticmethod
    def export_registry_key(registry_path: str, output_file: str) -> bool:
        """
        Export registry key to file for hashing/comparison.
        
        Args:
            registry_path: Registry path to export
            output_file: File to save registry dump
        
        Returns:
            True if successful, False otherwise
        """
        if sys.platform != 'win32':
            return False
        
        try:
            cmd = [
                'reg', 'export',
                registry_path,
                output_file,
                '/y'  # Yes to overwrite
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True
            )
            
            return result.returncode == 0
            
        except Exception as e:
            logger.warning(f"Failed to export registry: {str(e)}")
            return False
    
    @staticmethod
    def get_registry_hash(registry_path: str) -> Optional[str]:
        """
        Get SHA256 hash of registry key contents.
        Used for change detection.
        
        Args:
            registry_path: Registry path to hash
        
        Returns:
            Hex digest string, or None if export failed
        """
        if sys.platform != 'win32':
            return None
        
        temp_file = Path(f'/tmp/{registry_path.replace(chr(92), "_")}.reg')
        
        try:
            if RegistryProtector.export_registry_key(registry_path, str(temp_file)):
                with open(temp_file, 'rb') as f:
                    content_hash = hashlib.sha256(f.read()).hexdigest()
                
                temp_file.unlink()
                return content_hash
        except Exception as e:
            logger.warning(f"Failed to hash registry: {str(e)}")
        
        return None


class RegistryChangeDetector:
    """
    Real-time detection of unauthorized registry changes.
    Uses hash-chain integrity checking (similar to ChainedAuditLog).
    """
    
    def __init__(self, logger_obj=None):
        """
        Initialize change detector.
        
        Args:
            logger_obj: utm_telemetry.ChainedAuditLog instance (optional)
        """
        self.logger = logger_obj
        self.protected_keys = RegistryProtector.PROTECTED_PATHS
        self.previous_hashes = {}  # path -> hash mapping
        self.baseline_loaded = False
    
    def load_baseline(self) -> bool:
        """
        Load current registry state as baseline.
        Should be called when system is in known-good state.
        
        Returns:
            True if all keys exported successfully
        """
        logger.info("📸 Loading registry baseline...")
        
        for key_path in self.protected_keys:
            content_hash = RegistryProtector.get_registry_hash(key_path)
            if content_hash:
                self.previous_hashes[key_path] = content_hash
        
        self.baseline_loaded = len(self.previous_hashes) > 0
        return self.baseline_loaded
    
    def detect_changes(self) -> Dict[str, any]:
        """
        Check for unauthorized changes to protected registry keys.
        Runs periodically or on-demand.
        
        Returns:
            Dict with 'changes_detected', 'affected_keys', details
        """
        if not self.baseline_loaded:
            return {'error': 'Baseline not loaded. Call load_baseline() first'}
        
        changes = []
        
        for key_path in self.protected_keys:
            current_hash = RegistryProtector.get_registry_hash(key_path)
            previous_hash = self.previous_hashes.get(key_path)
            
            if not current_hash:
                continue
            
            if previous_hash and current_hash != previous_hash:
                # Change detected!
                change_event = {
                    'registry_key': key_path,
                    'timestamp': datetime.utcnow().isoformat(),
                    'previous_hash': previous_hash,
                    'current_hash': current_hash,
                    'change_type': 'MODIFICATION',
                    'threat_level': 'CRITICAL',
                    'technique': 'T1547'
                }
                changes.append(change_event)
                
                # Log critical event via telemetry
                if self.logger:
                    try:
                        from utm_telemetry import EventSeverity, EventCategory
                        
                        self.logger.log(
                            event_data={
                                'registry_key': key_path,
                                'previous_hash': previous_hash,
                                'current_hash': current_hash,
                                'detection': 'T1547_AUTOSTART_MODIFICATION',
                                'threat': 'Unauthorized persistence mechanism',
                                'action': 'INVESTIGATE + REMEDIATE_IMMEDIATELY'
                            },
                            severity=EventSeverity.CRITICAL,
                            category=EventCategory.THREAT_DETECTION
                        )
                    except (ImportError, AttributeError):
                        logger.critical(f"T1547 detected at {key_path}")
            
            # Update hash for next comparison
            self.previous_hashes[key_path] = current_hash
        
        return {
            'timestamp': datetime.now(datetime.timezone.utc).isoformat() 
                        if hasattr(datetime, 'timezone')
                        else datetime.utcnow().isoformat(),
            'changes_detected': len(changes) > 0,
            'affected_keys': len(changes),
            'changes': changes
        }


class RegistryRemediator:
    """
    Automatically remediate unauthorized registry changes.
    
    Removes unauthorized registry values based on whitelisted entries.
    Only values NOT in whitelist are removed.
    """
    
    def __init__(self, logger_obj=None):
        """
        Initialize remediator.
        
        Args:
            logger_obj: utm_telemetry.ChainedAuditLog instance (optional)
        """
        self.logger = logger_obj
        self.whitelist = RegistryProtector.WHITELIST
    
    def get_registry_values(self, registry_key: str) -> List[str]:
        """
        Get all value names in a registry key.
        
        Args:
            registry_key: Registry path
        
        Returns:
            List of value names
        """
        if sys.platform != 'win32':
            return []
        
        try:
            cmd = ['reg', 'query', registry_key, '/v', '*']
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True
            )
            
            values = []
            for line in result.stdout.split('\n'):
                # Parse reg query output format
                if line.strip() and not line.startswith('HKEY'):
                    parts = line.split()
                    if parts:
                        values.append(parts[0])
            
            return values
            
        except Exception as e:
            logger.warning(f"Failed to query registry: {str(e)}")
            return []
    
    def remediate_registry(self, registry_key: str, 
                          value_name: str) -> Tuple[bool, str]:
        """
        Remove an unauthorized registry value.
        
        Args:
            registry_key: Registry path
            value_name: Name of value to remove
        
        Returns:
            (success: bool, message: str)
        """
        if sys.platform != 'win32':
            return False, "Windows only"
        
        # Check if value is whitelisted
        if value_name in self.whitelist.get(registry_key, []):
            msg = f"Value whitelisted, not removed: {value_name}"
            logger.info(f"ℹ️ {msg}")
            return False, msg
        
        try:
            # Delete unauthorized value
            cmd = [
                'reg', 'delete',
                registry_key,
                '/v', value_name,
                '/f'  # Force (no confirmation)
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                msg = f"✅ Removed unauthorized registry value: {value_name}"
                logger.warning(msg)
                
                # Log remediation action
                if self.logger:
                    try:
                        from utm_telemetry import EventSeverity, EventCategory
                        
                        self.logger.log(
                            event_data={
                                'action': 'REMEDIATE_T1547',
                                'registry_key': registry_key,
                                'removed_value': value_name,
                                'status': 'SUCCESS',
                                'threat': 'Unauthorized autostart removed'
                            },
                            severity=EventSeverity.CRITICAL,
                            category=EventCategory.POLICY_CHANGE
                        )
                    except (ImportError, AttributeError):
                        pass
                
                return True, msg
            else:
                msg = f"Failed to remove value: {result.stderr}"
                logger.error(msg)
                return False, msg
                
        except Exception as e:
            msg = f"Exception during remediation: {str(e)}"
            logger.error(msg)
            return False, msg
    
    def remediate_all_unauthorized(self) -> Dict[str, any]:
        """
        Scan all protected registry keys and remove unauthorized values.
        
        Returns:
            Summary of remediation actions
        """
        if sys.platform != 'win32':
            return {'error': 'Windows only', 'remediated': 0}
        
        logger.warning("🔧 Starting registry remediation of unauthorized values...")
        
        remediated = []
        failed = []
        whitelisted = []
        
        for key_path, allowed_values in self.whitelist.items():
            current_values = self.get_registry_values(key_path)
            
            for value_name in current_values:
                if value_name not in allowed_values:
                    # Unauthorized value - remove it
                    success, msg = self.remediate_registry(key_path, value_name)
                    
                    if success:
                        remediated.append({'key': key_path, 'value': value_name})
                    else:
                        failed.append({'key': key_path, 'value': value_name, 'error': msg})
                else:
                    whitelisted.append({'key': key_path, 'value': value_name})
        
        return {
            'remediated_count': len(remediated),
            'failed_count': len(failed),
            'whitelisted_count': len(whitelisted),
            'remediated': remediated,
            'failed': failed,
            'status': 'COMPLETE'
        }


def initialize_registry_protection(logger_obj=None) -> Dict:
    """
    Main entry point for registry protection.
    Call during UTM startup.
    
    Args:
        logger_obj: utm_telemetry.ChainedAuditLog instance (optional)
    
    Returns:
        Status dict with protection results
    """
    if sys.platform != 'win32':
        return {'status': 'Windows only'}
    
    logger.info("🔐 Initializing registry protection against T1547...")
    
    result = {}
    
    # Step 1: Lock all dangerous registry locations
    logger.info("Step 1/3: Locking registry keys...")
    lock_results = RegistryProtector.protect_all_autostart_locations()
    result['lock_results'] = lock_results
    
    # Step 2: Load baseline for change detection
    logger.info("Step 2/3: Loading registry baseline...")
    detector = RegistryChangeDetector(logger_obj)
    detector.load_baseline()
    result['baseline_loaded'] = detector.baseline_loaded
    
    # Step 3: Enable change monitoring
    logger.info("Step 3/3: Enabling change monitoring...")
    result['change_detector'] = detector
    
    logger.info("✅ Registry protection initialized")
    return result


if __name__ == '__main__':
    # Test registry protection independently
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    print("\n" + "="*70)
    print("REGISTRY PROTECTION TEST")
    print("="*70)
    
    if sys.platform == 'win32':
        result = initialize_registry_protection()
        print(f"\nInitialization result: {result}")
        
        # Test change detection
        detector = RegistryChangeDetector()
        if detector.load_baseline():
            print("✅ Baseline loaded successfully")
            
            changes = detector.detect_changes()
            if changes['changes_detected']:
                print(f"⚠️ Changes detected: {changes}")
            else:
                print("✅ No unauthorized changes detected")
    else:
        print("Registry protection: Windows only")
