import platform
import os
import uuid
import logging
import secrets
import hashlib
import subprocess
import re

logger = logging.getLogger(__name__)

# Cache for system ID to avoid repeated system calls
_system_id_cache = None

def machine_id_v2() -> bytes:
    try:
        uname_str = '|'.join(platform.uname())
        login_str = os.getlogin()
        node_str = __safe_get_node()
        sys_id = __system_id()
        return hashlib.sha256(f"{uname_str}|{login_str}|{node_str}|{sys_id.decode('utf-8', errors='ignore') if sys_id else 'EMPTY'}".encode()).digest()
    except Exception as e:
        logger.warning(f"Failed to generate machine ID: {e}")
        return secrets.token_bytes(hashlib.sha256().digest_size)

def machine_id_v3() -> bytes:
    """Generate machine ID v3 (Python version independent)"""
    login_str = os.getlogin()
    node_str = __safe_get_node()
    sys_id = __system_id()
    # Exclude platform.uname() to avoid Python version dependencies
    return hashlib.sha256(f"{login_str}|{node_str}|{sys_id.decode('utf-8', errors='ignore') if sys_id else 'EMPTY'}".encode()).digest()

# Backward compatibility alias for protocol_client.py
machine_id = machine_id_v3

def __safe_get_node() -> str:
    """
    Universal implementation to get the PHYSICAL MAC address.
    Uses PowerShell to bypass language barriers and automatically ignore virtual adapters.
    """
    try:
        system = platform.system()
        if system == "Windows":
            # Deterministic PS command: Get Physical adapters, sort by name, pick the first one.
            ps_cmd = "(Get-NetAdapter -Physical | Sort-Object Name | Select-Object -First 1).MacAddress"
            ps_path = os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe')
            
            if os.path.exists(ps_path):
                try:
                    result = subprocess.run(
                        [ps_path, "-NoProfile", "-Command", ps_cmd],
                        capture_output=True, text=True, timeout=15
                    )
                    
                    if result.returncode == 0 and result.stdout.strip():
                        mac_str = result.stdout.strip().replace('-', '').replace(':', '')
                        if mac_str and mac_str != "000000000000":
                            return str(int(mac_str, 16))
                except Exception as ps_error:
                    logger.warning(f"PowerShell MAC extraction failed or timed out: {ps_error}")
        
        # Fallback to native uuid.getnode() for non-Windows or if PowerShell fails
        node = uuid.getnode()
        return str(node)
        
    except Exception as e:
        logger.warning(f"Failed to get custom node: {e}")
        return "fallback"

def __system_id_impl() -> bytes:
    """Internal implementation to get system ID using absolute paths to bypass PATH issues."""
    try:
        system = platform.system()
        
        if system == "Windows":
            wmic_path = os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32', 'wbem', 'wmic.exe')
            
            if not os.path.exists(wmic_path):
                return b""

            result = subprocess.run(
                [wmic_path, "csproduct", "get", "UUID", "/format:list"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if line.strip().startswith("UUID"):
                        return line.encode('utf-8')
            return b""
            
        elif system == "Darwin":  # macOS
            result = subprocess.run(
                ["system_profiler", "SPHardwareDataType"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if line.strip().startswith("Hardware UUID"):
                        return line.encode('utf-8')
            return b""
        else:
            return b""
            
    except Exception as e:
        logger.warning(f"Failed to get system ID: {e}")
        return b""

def __system_id() -> bytes:
    """Get system ID by calling platform-specific commands to get hardware UUID."""
    global _system_id_cache
    if _system_id_cache is None:
        _system_id_cache = __system_id_impl()
    return _system_id_cache