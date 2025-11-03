import platform
import os
import uuid
import base64
import logging
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from .machine_id import machine_id

logger = logging.getLogger(__name__)

# Sensitive fields that require encryption
SENSITIVE_FIELDS = ['steam_id', 'refresh_token', 'account_username', 'persona_name']

# Format versions
FORMAT_VERSION_V2_ENCRYPTED = 'v2_encrypted'

# Dictionary keys
KEY_FORMAT_VERSION = '_format_version'


class SecureCredentialStorage:
    """Handles secure encryption/decryption of credentials using system-bound keys"""
    
    @staticmethod
    def _derive_key() -> bytes:
        """Derive encryption key from system-specific data"""
        # Use the same system identifiers as machine ID
        system_data = machine_id()
        
        # Derive key using PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'galaxy_steam_salt',  # Fixed salt for this plugin
            iterations=100000,
        )
        return kdf.derive(system_data)
    
    @staticmethod
    def encrypt_credentials(credentials: dict) -> dict:
        """Encrypt sensitive credentials"""
        key = SecureCredentialStorage._derive_key()
        aesgcm = AESGCM(key)
        
        encrypted_creds = {}
        for field, value in credentials.items():
            if field in SENSITIVE_FIELDS:
                # Encrypt sensitive fields
                nonce = os.urandom(12)  # 96-bit nonce for GCM
                encrypted_data = aesgcm.encrypt(nonce, value.encode('utf-8'), None)
                encrypted_creds[field] = base64.b64encode(nonce + encrypted_data).decode('utf-8')
            else:
                encrypted_creds[field] = value
        
        # Add format version metadata
        encrypted_creds[KEY_FORMAT_VERSION] = FORMAT_VERSION_V2_ENCRYPTED
        
        return encrypted_creds
    
    @staticmethod
    def decrypt_credentials(encrypted_creds: dict) -> dict:
        """Decrypt sensitive credentials"""
        key = SecureCredentialStorage._derive_key()
        aesgcm = AESGCM(key)
        
        decrypted_creds = {}
        for field, value in encrypted_creds.items():
            if field in SENSITIVE_FIELDS:
                try:
                    encrypted_data = base64.b64decode(value)
                    nonce = encrypted_data[:12]
                    ciphertext = encrypted_data[12:]
                    decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
                    decrypted_creds[field] = decrypted_data.decode('utf-8')
                except Exception as e:
                    raise ValueError(f"Failed to decrypt {field}: {e}")
            else:
                decrypted_creds[field] = value
        
        return decrypted_creds


class CredentialMigration:
    """Handles migration between different credential storage formats"""
    
    @staticmethod
    def migrate_credentials(credentials: dict) -> dict:
        """Migrate credentials from any supported format to current format"""
        if not credentials:
            return credentials
        
        # Check if already in current format
        if KEY_FORMAT_VERSION in credentials and credentials[KEY_FORMAT_VERSION] == FORMAT_VERSION_V2_ENCRYPTED:
            return credentials
        
        # Assume legacy Base64 format if no format version
        return CredentialMigration._migrate_from_base64(credentials)
    
    @staticmethod
    def _migrate_from_base64(credentials: dict) -> dict:
        """Migrate from old Base64 format to new encrypted format"""
        logger.info("Migrating credentials from Base64 to encrypted format")
        
        try:
            # Decode old format
            decoded_creds = {}
            for key, value in credentials.items():
                if key.startswith('_'):
                    continue  # Skip metadata
                try:
                    decoded_creds[key] = base64.b64decode(value).decode('utf-8')
                except:
                    # If it's not Base64, keep as-is
                    decoded_creds[key] = value
            
            # Encrypt with new format
            encrypted_creds = SecureCredentialStorage.encrypt_credentials(decoded_creds)
            
            logger.info("Successfully migrated credentials to encrypted format")
            return encrypted_creds
            
        except Exception as e:
            logger.error(f"Failed to migrate from Base64 format: {e}")
            # Return original credentials - let the system handle the error
            return credentials
