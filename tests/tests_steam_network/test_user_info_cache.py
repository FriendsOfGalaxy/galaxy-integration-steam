import pytest
import base64
from unittest.mock import patch, MagicMock

from steam_network.user_info_cache import UserInfoCache
from steam_network.secure_credential_storage import (
    SecureCredentialStorage,
    CredentialMigration,
    KEY_FORMAT_VERSION,
    FORMAT_VERSION_V2_ENCRYPTED
)

_STEAM_ID = 123
_ACCOUNT_USERNAME = "😋学中文Не́кот"
_PERSONA_NAME = "Ptester"
_REFRESH_TOKEN = "refresh_token"
_ACCESS_TOKEN = "access_token"

# Legacy Base64 format (old format) - constructed from constants
legacy_serialized_creds = {
    'steam_id': base64.b64encode(str(_STEAM_ID).encode()).decode(),
    'refresh_token': base64.b64encode(_REFRESH_TOKEN.encode()).decode(),
    'account_username': base64.b64encode(_ACCOUNT_USERNAME.encode()).decode(),
    'persona_name': base64.b64encode(_PERSONA_NAME.encode()).decode()
}

# New encrypted format
encrypted_serialized_creds = {
    'steam_id': 'encrypted_steam_id_data',
    'refresh_token': 'encrypted_refresh_token_data',
    'account_username': 'encrypted_account_username_data',
    'persona_name': 'encrypted_persona_name_data',
    KEY_FORMAT_VERSION: FORMAT_VERSION_V2_ENCRYPTED
}


def test_credentials_cache_store_encrypted():
    """Test storing credentials with new encrypted format"""
    with patch.object(SecureCredentialStorage, 'encrypt_credentials') as mock_encrypt:
        mock_encrypt.return_value = encrypted_serialized_creds
        
        user_info_cache = UserInfoCache()
        user_info_cache.steam_id = _STEAM_ID
        user_info_cache.account_username = _ACCOUNT_USERNAME
        user_info_cache.persona_name = _PERSONA_NAME
        user_info_cache.refresh_token = _REFRESH_TOKEN

        assert user_info_cache.initialized.is_set()
        
        result = user_info_cache.to_dict()
        assert result == encrypted_serialized_creds
        assert KEY_FORMAT_VERSION in result
        assert result[KEY_FORMAT_VERSION] == FORMAT_VERSION_V2_ENCRYPTED


def test_credentials_cache_load_encrypted():
    """Test loading credentials from new encrypted format"""
    with patch.object(SecureCredentialStorage, 'decrypt_credentials') as mock_decrypt:
        mock_decrypt.return_value = {
            'steam_id': str(_STEAM_ID),
            'account_username': _ACCOUNT_USERNAME,
            'persona_name': _PERSONA_NAME,
            'refresh_token': _REFRESH_TOKEN
        }
        
        user_info_cache = UserInfoCache()
        user_info_cache.from_dict(encrypted_serialized_creds)

        assert user_info_cache.steam_id == _STEAM_ID
        assert user_info_cache.account_username == _ACCOUNT_USERNAME
        assert user_info_cache.persona_name == _PERSONA_NAME
        assert user_info_cache.refresh_token == _REFRESH_TOKEN


def test_credentials_cache_load_legacy_migration():
    """Test loading and migrating legacy Base64 credentials"""
    with patch.object(CredentialMigration, 'migrate_credentials') as mock_migrate:
        mock_migrate.return_value = encrypted_serialized_creds
        
        with patch.object(SecureCredentialStorage, 'decrypt_credentials') as mock_decrypt:
            mock_decrypt.return_value = {
                'steam_id': str(_STEAM_ID),
                'account_username': _ACCOUNT_USERNAME,
                'persona_name': _PERSONA_NAME,
                'refresh_token': _REFRESH_TOKEN
            }
            
            user_info_cache = UserInfoCache()
            user_info_cache.from_dict(legacy_serialized_creds)

            # Verify migration was called
            mock_migrate.assert_called_once_with(legacy_serialized_creds)
            
            # Verify decryption was called with migrated data
            mock_decrypt.assert_called_once_with(encrypted_serialized_creds)

            assert user_info_cache.steam_id == _STEAM_ID
            assert user_info_cache.account_username == _ACCOUNT_USERNAME
            assert user_info_cache.persona_name == _PERSONA_NAME
            assert user_info_cache.refresh_token == _REFRESH_TOKEN


def test_credentials_cache_load_migration_failure():
    """Test graceful handling of migration failure"""
    with patch.object(CredentialMigration, 'migrate_credentials') as mock_migrate:
        mock_migrate.side_effect = Exception("Migration failed")
        
        with patch.object(SecureCredentialStorage, 'decrypt_credentials') as mock_decrypt:
            mock_decrypt.return_value = {
                'steam_id': str(_STEAM_ID),
                'account_username': _ACCOUNT_USERNAME,
                'persona_name': _PERSONA_NAME,
                'refresh_token': _REFRESH_TOKEN
            }
            
            user_info_cache = UserInfoCache()
            user_info_cache.from_dict(legacy_serialized_creds)

            # Should fall back to original credentials
            mock_decrypt.assert_called_once_with(legacy_serialized_creds)

            assert user_info_cache.steam_id == _STEAM_ID
            assert user_info_cache.account_username == _ACCOUNT_USERNAME
            assert user_info_cache.persona_name == _PERSONA_NAME
            assert user_info_cache.refresh_token == _REFRESH_TOKEN


def test_credentials_cache_load_decryption_failure():
    """Test graceful handling of decryption failure"""
    with patch.object(CredentialMigration, 'migrate_credentials') as mock_migrate:
        mock_migrate.return_value = encrypted_serialized_creds
        
        with patch.object(SecureCredentialStorage, 'decrypt_credentials') as mock_decrypt:
            mock_decrypt.side_effect = Exception("Decryption failed")
            
            user_info_cache = UserInfoCache()
            user_info_cache.from_dict(encrypted_serialized_creds)

            # Should not crash, credentials should remain uninitialized
            assert user_info_cache.steam_id is None
            assert user_info_cache.account_username is None
            assert user_info_cache.persona_name is None
            assert user_info_cache.refresh_token is None
            assert not user_info_cache.initialized.is_set()


def test_credentials_cache_load_empty_dict():
    """Test loading empty credentials"""
    user_info_cache = UserInfoCache()
    user_info_cache.from_dict({})

    assert user_info_cache.steam_id is None
    assert user_info_cache.account_username is None
    assert user_info_cache.persona_name is None
    assert user_info_cache.refresh_token is None
    assert not user_info_cache.initialized.is_set()


def test_credentials_cache_load_none():
    """Test loading None credentials"""
    user_info_cache = UserInfoCache()
    user_info_cache.from_dict(None)

    assert user_info_cache.steam_id is None
    assert user_info_cache.account_username is None
    assert user_info_cache.persona_name is None
    assert user_info_cache.refresh_token is None
    assert not user_info_cache.initialized.is_set()


def test_credentials_cache_to_dict_empty():
    """Test to_dict with uninitialized cache"""
    user_info_cache = UserInfoCache()
    result = user_info_cache.to_dict()
    
    assert result == {}


def test_credentials_cache_roundtrip():
    """Test complete roundtrip: store -> load"""
    with patch.object(SecureCredentialStorage, 'encrypt_credentials') as mock_encrypt:
        with patch.object(SecureCredentialStorage, 'decrypt_credentials') as mock_decrypt:
            # Setup mocks
            mock_encrypt.return_value = encrypted_serialized_creds
            mock_decrypt.return_value = {
                'steam_id': str(_STEAM_ID),
                'account_username': _ACCOUNT_USERNAME,
                'persona_name': _PERSONA_NAME,
                'refresh_token': _REFRESH_TOKEN
            }
            
            # Store credentials
            user_info_cache1 = UserInfoCache()
            user_info_cache1.steam_id = _STEAM_ID
            user_info_cache1.account_username = _ACCOUNT_USERNAME
            user_info_cache1.persona_name = _PERSONA_NAME
            user_info_cache1.refresh_token = _REFRESH_TOKEN
            
            stored_creds = user_info_cache1.to_dict()
            
            # Load credentials
            user_info_cache2 = UserInfoCache()
            user_info_cache2.from_dict(stored_creds)
            
            # Verify roundtrip
            assert user_info_cache2.steam_id == _STEAM_ID
            assert user_info_cache2.account_username == _ACCOUNT_USERNAME
            assert user_info_cache2.persona_name == _PERSONA_NAME
            assert user_info_cache2.refresh_token == _REFRESH_TOKEN


def test_access_token_property():
    user_info_cache = UserInfoCache()
    
    # Test setting access_token
    user_info_cache.access_token = _ACCESS_TOKEN
    assert user_info_cache.access_token == _ACCESS_TOKEN
    
    # Test that access_token is not included in serialization (not required for initialization)
    assert 'access_token' not in user_info_cache.to_dict()


# Additional tests for migration functionality


def test_credential_migration_base64_to_encrypted():
    """Test migration from Base64 to encrypted format"""
    with patch.object(SecureCredentialStorage, 'encrypt_credentials') as mock_encrypt:
        mock_encrypt.return_value = encrypted_serialized_creds
        
        result = CredentialMigration._migrate_from_base64(legacy_serialized_creds)
        
        # Verify encryption was called with decoded data
        expected_decoded = {
            'steam_id': '123',
            'account_username': '😋学中文Не́кот',
            'persona_name': 'Ptester',
            'refresh_token': 'refresh_token'
        }
        mock_encrypt.assert_called_once_with(expected_decoded)
        
        # Verify result has version info
        assert result[KEY_FORMAT_VERSION] == FORMAT_VERSION_V2_ENCRYPTED


def test_credential_migration_already_encrypted():
    """Test that already encrypted credentials are not migrated"""
    result = CredentialMigration.migrate_credentials(encrypted_serialized_creds)
    assert result == encrypted_serialized_creds


def test_credential_migration_empty_credentials():
    """Test migration with empty credentials"""
    result = CredentialMigration.migrate_credentials({})
    assert result == {}


def test_credential_migration_unknown_format():
    """Test migration with unknown format (treated as Base64)"""
    unknown_creds = {
        'steam_id': 'some_unknown_format',
        'account_username': 'testuser'
    }
    
    with patch.object(SecureCredentialStorage, 'encrypt_credentials') as mock_encrypt:
        mock_encrypt.return_value = encrypted_serialized_creds
        
        # Unknown format should be treated as Base64 and migrated
        result = CredentialMigration.migrate_credentials(unknown_creds)
        
        # Should have been encrypted (treated as Base64)
        assert KEY_FORMAT_VERSION in result
        assert result[KEY_FORMAT_VERSION] == FORMAT_VERSION_V2_ENCRYPTED


def test_credential_migration_failure_handling():
    """Test migration failure handling"""
    with patch.object(SecureCredentialStorage, 'encrypt_credentials') as mock_encrypt:
        mock_encrypt.side_effect = Exception("Encryption failed")
        
        result = CredentialMigration._migrate_from_base64(legacy_serialized_creds)
        
        # Should return original credentials on failure
        assert result == legacy_serialized_creds


def test_user_info_cache_initialization_state():
    """Test UserInfoCache initialization state"""
    user_info_cache = UserInfoCache()
    
    # Initially not initialized
    assert not user_info_cache.initialized.is_set()
    assert not user_info_cache.is_initialized()
    
    # Set required fields one by one
    user_info_cache.steam_id = _STEAM_ID
    assert not user_info_cache.is_initialized()  # Still missing other fields
    
    user_info_cache.account_username = _ACCOUNT_USERNAME
    assert not user_info_cache.is_initialized()  # Still missing other fields
    
    user_info_cache.persona_name = _PERSONA_NAME
    assert not user_info_cache.is_initialized()  # Still missing refresh_token
    
    user_info_cache.refresh_token = _REFRESH_TOKEN
    assert user_info_cache.is_initialized()  # Now fully initialized
    assert user_info_cache.initialized.is_set()


def test_user_info_cache_clear():
    """Test UserInfoCache clear functionality"""
    user_info_cache = UserInfoCache()
    user_info_cache.steam_id = _STEAM_ID
    user_info_cache.account_username = _ACCOUNT_USERNAME
    user_info_cache.persona_name = _PERSONA_NAME
    user_info_cache.refresh_token = _REFRESH_TOKEN
    user_info_cache.access_token = _ACCESS_TOKEN
    
    assert user_info_cache.is_initialized()
    
    user_info_cache.Clear()
    
    assert user_info_cache.steam_id is None
    assert user_info_cache.account_username is None
    assert user_info_cache.persona_name is None
    assert user_info_cache.refresh_token is None
    assert user_info_cache.access_token is None
    assert not user_info_cache.is_initialized()
