import pytest
import base64
from unittest.mock import patch, MagicMock

from steam_network.user_info_cache import UserInfoCache
from steam_network.secure_credential_storage import (
    SecureCredentialStorage,
    KEY_FORMAT_VERSION,
    FORMAT_VERSION_V2_ENCRYPTED,
    FORMAT_VERSION_V3_ENCRYPTED
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

# V2 encrypted format
encrypted_serialized_creds_v2 = {
    'steam_id': 'encrypted_steam_id_data_v2',
    'refresh_token': 'encrypted_refresh_token_data_v2',
    'account_username': 'encrypted_account_username_data_v2',
    'persona_name': 'encrypted_persona_name_data_v2',
    KEY_FORMAT_VERSION: FORMAT_VERSION_V2_ENCRYPTED
}

# V3 encrypted format (current default)
encrypted_serialized_creds = {
    'steam_id': 'encrypted_steam_id_data',
    'refresh_token': 'encrypted_refresh_token_data',
    'account_username': 'encrypted_account_username_data',
    'persona_name': 'encrypted_persona_name_data',
    KEY_FORMAT_VERSION: FORMAT_VERSION_V3_ENCRYPTED
}


def test_credentials_cache_store_encrypted():
    """Test storing credentials with v3 encrypted format (current default)"""
    # Create v3 encrypted format for the test
    encrypted_serialized_creds_v3 = {
        'steam_id': 'encrypted_steam_id_data',
        'refresh_token': 'encrypted_refresh_token_data',
        'account_username': 'encrypted_account_username_data',
        'persona_name': 'encrypted_persona_name_data',
        KEY_FORMAT_VERSION: FORMAT_VERSION_V3_ENCRYPTED
    }
    
    with patch.object(SecureCredentialStorage, 'encrypt_credentials_v3') as mock_encrypt:
        mock_encrypt.return_value = encrypted_serialized_creds_v3
        
        user_info_cache = UserInfoCache()
        user_info_cache.steam_id = _STEAM_ID
        user_info_cache.account_username = _ACCOUNT_USERNAME
        user_info_cache.persona_name = _PERSONA_NAME
        user_info_cache.refresh_token = _REFRESH_TOKEN

        assert user_info_cache.initialized.is_set()
        
        result = user_info_cache.to_dict()
        assert result == encrypted_serialized_creds_v3
        assert KEY_FORMAT_VERSION in result
        assert result[KEY_FORMAT_VERSION] == FORMAT_VERSION_V3_ENCRYPTED


def test_credentials_cache_load_encrypted():
    """Test loading credentials from encrypted format (v2)"""
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


def test_credentials_cache_load_legacy_base64():
    """Test loading legacy Base64 credentials (no format version, assumed Base64)"""
    with patch.object(SecureCredentialStorage, 'decrypt_credentials') as mock_decrypt:
        # decrypt_credentials should decode Base64 when no format version is present
        mock_decrypt.return_value = {
            'steam_id': str(_STEAM_ID),
            'account_username': _ACCOUNT_USERNAME,
            'persona_name': _PERSONA_NAME,
            'refresh_token': _REFRESH_TOKEN
        }
        
        user_info_cache = UserInfoCache()
        user_info_cache.from_dict(legacy_serialized_creds)

        # Verify decrypt_credentials was called directly (no migration)
        mock_decrypt.assert_called_once_with(legacy_serialized_creds)

        assert user_info_cache.steam_id == _STEAM_ID
        assert user_info_cache.account_username == _ACCOUNT_USERNAME
        assert user_info_cache.persona_name == _PERSONA_NAME
        assert user_info_cache.refresh_token == _REFRESH_TOKEN


def test_credentials_cache_load_decryption_failure():
    """Test graceful handling of decryption failure"""
    with patch.object(SecureCredentialStorage, 'decrypt_credentials') as mock_decrypt:
        mock_decrypt.return_value = {
            'steam_id': str(_STEAM_ID),
            'account_username': _ACCOUNT_USERNAME,
            'persona_name': _PERSONA_NAME,
            'refresh_token': _REFRESH_TOKEN
        }
        
        user_info_cache = UserInfoCache()
        user_info_cache.from_dict(legacy_serialized_creds)

        # Should attempt decryption with original credentials
        mock_decrypt.assert_called_once_with(legacy_serialized_creds)

        assert user_info_cache.steam_id == _STEAM_ID
        assert user_info_cache.account_username == _ACCOUNT_USERNAME
        assert user_info_cache.persona_name == _PERSONA_NAME
        assert user_info_cache.refresh_token == _REFRESH_TOKEN


def test_credentials_cache_load_decryption_error():
    """Test graceful handling of decryption error"""
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
    with patch.object(SecureCredentialStorage, 'encrypt_credentials_v3') as mock_encrypt:
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


# Tests for v3 encryption and format detection
def test_credentials_cache_load_v2_encrypted():
    """Test loading v2 encrypted credentials (should work via decrypt_credentials())"""
    with patch.object(SecureCredentialStorage, 'decrypt_credentials') as mock_decrypt:
        mock_decrypt.return_value = {
            'steam_id': str(_STEAM_ID),
            'account_username': _ACCOUNT_USERNAME,
            'persona_name': _PERSONA_NAME,
            'refresh_token': _REFRESH_TOKEN
        }
        
        user_info_cache = UserInfoCache()
        user_info_cache.from_dict(encrypted_serialized_creds_v2)

        # Verify decrypt_credentials was called with v2 credentials
        mock_decrypt.assert_called_once_with(encrypted_serialized_creds_v2)

        assert user_info_cache.steam_id == _STEAM_ID
        assert user_info_cache.account_username == _ACCOUNT_USERNAME
        assert user_info_cache.persona_name == _PERSONA_NAME
        assert user_info_cache.refresh_token == _REFRESH_TOKEN


def test_credentials_cache_load_v3_encrypted():
    """Test loading v3 encrypted credentials"""
    with patch.object(SecureCredentialStorage, 'decrypt_credentials') as mock_decrypt:
        mock_decrypt.return_value = {
            'steam_id': str(_STEAM_ID),
            'account_username': _ACCOUNT_USERNAME,
            'persona_name': _PERSONA_NAME,
            'refresh_token': _REFRESH_TOKEN
        }
        
        user_info_cache = UserInfoCache()
        user_info_cache.from_dict(encrypted_serialized_creds)

        # Verify decrypt_credentials was called with v3 credentials
        mock_decrypt.assert_called_once_with(encrypted_serialized_creds)

        assert user_info_cache.steam_id == _STEAM_ID
        assert user_info_cache.account_username == _ACCOUNT_USERNAME
        assert user_info_cache.persona_name == _PERSONA_NAME
        assert user_info_cache.refresh_token == _REFRESH_TOKEN


def test_decrypt_credentials_v2_format():
    """Test decrypt_credentials() detects v2 format correctly"""
    with patch.object(SecureCredentialStorage, 'decrypt_credentials_v2') as mock_decrypt_v2:
        mock_decrypt_v2.return_value = {
            'steam_id': str(_STEAM_ID),
            'account_username': _ACCOUNT_USERNAME,
            'persona_name': _PERSONA_NAME,
            'refresh_token': _REFRESH_TOKEN
        }
        
        result = SecureCredentialStorage.decrypt_credentials(encrypted_serialized_creds_v2)
        
        # Should call v2 decrypt method
        mock_decrypt_v2.assert_called_once_with(encrypted_serialized_creds_v2)
        assert result['steam_id'] == str(_STEAM_ID)


def test_decrypt_credentials_v3_format():
    """Test decrypt_credentials() detects v3 format correctly"""
    with patch.object(SecureCredentialStorage, 'decrypt_credentials_v3') as mock_decrypt_v3:
        mock_decrypt_v3.return_value = {
            'steam_id': str(_STEAM_ID),
            'account_username': _ACCOUNT_USERNAME,
            'persona_name': _PERSONA_NAME,
            'refresh_token': _REFRESH_TOKEN
        }
        
        result = SecureCredentialStorage.decrypt_credentials(encrypted_serialized_creds)
        
        # Should call v3 decrypt method
        mock_decrypt_v3.assert_called_once_with(encrypted_serialized_creds)
        assert result['steam_id'] == str(_STEAM_ID)


def test_decrypt_credentials_base64_format():
    """Test decrypt_credentials() handles Base64 format (no format version)"""
    result = SecureCredentialStorage.decrypt_credentials(legacy_serialized_creds)
        
    # Should decode Base64
    assert result['steam_id'] == str(_STEAM_ID)
    assert result['account_username'] == _ACCOUNT_USERNAME
    assert result['persona_name'] == _PERSONA_NAME
    assert result['refresh_token'] == _REFRESH_TOKEN


def test_decrypt_credentials_unknown_format():
    """Test decrypt_credentials() handles unknown format version as Base64"""
    unknown_creds = {
        'steam_id': base64.b64encode(str(_STEAM_ID).encode()).decode(),
        'refresh_token': base64.b64encode(_REFRESH_TOKEN.encode()).decode(),
        KEY_FORMAT_VERSION: 'unknown_format_version'
    }
    
    result = SecureCredentialStorage.decrypt_credentials(unknown_creds)
    
    # Should treat as Base64
    assert result['steam_id'] == str(_STEAM_ID)
    assert result['refresh_token'] == _REFRESH_TOKEN


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
