import platform
import os
import uuid
import base64
import logging
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from .machine_id import machine_id_v2, machine_id_v3

logger = logging.getLogger(__name__)

# Sensitive fields that require encryption
SENSITIVE_FIELDS = ['steam_id', 'refresh_token', 'account_username', 'persona_name']

# Format versions
FORMAT_VERSION_V2_ENCRYPTED = 'v2_encrypted'
FORMAT_VERSION_V3_ENCRYPTED = 'v3_encrypted'

# Dictionary keys
KEY_FORMAT_VERSION = '_format_version'


class SecureCredentialStorage:
    """Handles secure encryption/decryption of credentials using system-bound keys"""
    
    @staticmethod
    def _derive_key(system_data: bytes) -> bytes:
        """Derive encryption key from system-specific data"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'galaxy_steam_salt',  # Fixed salt for this plugin
            iterations=100000,
        )
        return kdf.derive(system_data)
    
    @staticmethod
    def _derive_key_v2() -> bytes:
        """Derive encryption key from system-specific data (v2)"""
        system_data = machine_id_v2()
        return SecureCredentialStorage._derive_key(system_data)
    
    @staticmethod
    def _decrypt_credentials_with_key(encrypted_creds: dict, key: bytes) -> dict:
        """Decrypt sensitive credentials using the provided key"""
        aesgcm = AESGCM(key)
        
        decrypted_creds = {}
        for field, value in encrypted_creds.items():
            # Only decrypt if the field is sensitive and has a value
            if field in SENSITIVE_FIELDS and value:
                try:
                    encrypted_data = base64.b64decode(value)
                    nonce = encrypted_data[:12]
                    ciphertext = encrypted_data[12:]
                    decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
                    decrypted_creds[field] = decrypted_data.decode('utf-8')
                except Exception as e:
                    logger.error(f"Failed to decrypt {field}: {e}")
                    raise ValueError(f"Failed to decrypt {field}: {e}")
            else:
                decrypted_creds[field] = value
        
        return decrypted_creds
    
    @staticmethod
    def decrypt_credentials_v2(encrypted_creds: dict) -> dict:
        """Decrypt sensitive credentials using v2 logic"""
        key = SecureCredentialStorage._derive_key_v2()
        return SecureCredentialStorage._decrypt_credentials_with_key(encrypted_creds, key)
    
    @staticmethod
    def _derive_key_v3() -> bytes:
        """Derive encryption key from system-specific data (v3)"""
        system_data = machine_id_v3()
        return SecureCredentialStorage._derive_key(system_data)
    
    @staticmethod
    def encrypt_credentials_v3(credentials: dict) -> dict:
        """Encrypt sensitive credentials using v3 deterministic hardware binding"""
        key = SecureCredentialStorage._derive_key_v3()
        aesgcm = AESGCM(key)
        
        encrypted_creds = {}
        for field, value in credentials.items():
            if field in SENSITIVE_FIELDS and value:
                nonce = os.urandom(12)  # 96-bit nonce for GCM
                encrypted_data = aesgcm.encrypt(nonce, value.encode('utf-8'), None)
                encrypted_creds[field] = base64.b64encode(nonce + encrypted_data).decode('utf-8')
            else:
                encrypted_creds[field] = value
        
        # Add format version metadata
        encrypted_creds[KEY_FORMAT_VERSION] = FORMAT_VERSION_V3_ENCRYPTED
        
        return encrypted_creds
    
    @staticmethod
    def decrypt_credentials_v3(encrypted_creds: dict) -> dict:
        """Decrypt sensitive credentials using v3 deterministic hardware binding"""
        key = SecureCredentialStorage._derive_key_v3()
        return SecureCredentialStorage._decrypt_credentials_with_key(encrypted_creds, key)
    
    @staticmethod
    def decrypt_credentials(credentials: dict) -> dict:
        """Decrypt credentials with automatic format detection"""
        if not credentials:
            return credentials
        
        # Check format version
        if KEY_FORMAT_VERSION in credentials:
            format_version = credentials[KEY_FORMAT_VERSION]
            
            if format_version == FORMAT_VERSION_V2_ENCRYPTED:
                return SecureCredentialStorage.decrypt_credentials_v2(credentials)
            elif format_version == FORMAT_VERSION_V3_ENCRYPTED:
                return SecureCredentialStorage.decrypt_credentials_v3(credentials)
        
        # Fallback for legacy or unencrypted formats
        decoded_creds = {}
        for key, value in credentials.items():
            if key.startswith('_'):
                continue
            try:
                decoded_creds[key] = base64.b64decode(value).decode('utf-8')
            except:
                decoded_creds[key] = value
        
        return decoded_creds