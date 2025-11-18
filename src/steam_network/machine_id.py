import platform
import os
import uuid
import logging
import secrets
import hashlib
import subprocess

logger = logging.getLogger(__name__)

# Cache for system ID to avoid repeated system calls
_system_id_cache = None

def machine_id_v2() -> bytes:
    try:
        return hashlib.sha256(f"{'|'.join(platform.uname())}|{os.getlogin()}|{__safe_get_node()}|{__system_id()}".encode()).digest()
    except Exception as e:
        logger.warning(f"Failed to generate machine ID: {e}")
        return secrets.token_bytes(hashlib.sha256().digest_size)

def machine_id_v3() -> bytes:
    """Generate machine ID v3 (Python version independent)"""
    # Exclude platform.uname() to avoid Python version dependencies
    return hashlib.sha256(f"{os.getlogin()}|{__safe_get_node()}|{__system_id()}".encode()).digest()

# Backward compatibility alias for protocol_client.py
machine_id = machine_id_v3

def __safe_get_node() -> str:
    try:
        node = uuid.getnode()
        if node != uuid.getnode():
            logger.warning("getnode is not deterministic, using fallback")
            return "fallback"
        return str(node)
    except Exception as e:
        logger.warning(f"Failed to get node: {e}")
        return "fallback"

def __system_id_impl() -> bytes:
    """Internal implementation to get system ID by calling platform-specific commands."""
    try:
        system = platform.system()
        
        if system == "Windows":
            # Execute the wmic command to get the UUID on Windows
            result = subprocess.run(
                ["wmic", "csproduct", "get", "UUID", "/format:list"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode != 0:
                logger.warning(f"wmic command failed with return code {result.returncode}: {result.stderr}")
                return b""
            
            # Filter output to get only the line starting with "UUID"
            for line in result.stdout.splitlines():
                if line.strip().startswith("UUID"):
                    return line.encode('utf-8')
            
            logger.warning("UUID not found in wmic output")
            return b""
            
        elif system == "Darwin":  # macOS
            # Execute system_profiler command to get the hardware UUID on macOS
            result = subprocess.run(
                ["system_profiler", "SPHardwareDataType"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode != 0:
                logger.warning(f"system_profiler command failed with return code {result.returncode}: {result.stderr}")
                return b""
            
            # Filter output to get only the line starting with "Hardware UUID"
            for line in result.stdout.splitlines():
                if line.strip().startswith("Hardware UUID"):
                    return line.encode('utf-8')
            
            logger.warning("Hardware UUID not found in system_profiler output")
            return b""
            
        else:
            logger.warning(f"__system_id is not supported on {system}")
            return b""
            
    except subprocess.TimeoutExpired:
        logger.warning("System ID command timed out")
        return b""
    except FileNotFoundError:
        logger.warning("System ID command not found")
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
