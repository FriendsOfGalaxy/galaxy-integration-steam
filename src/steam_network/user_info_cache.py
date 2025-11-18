import asyncio
import base64
import logging
from typing import Optional, Dict

from .secure_credential_storage import SecureCredentialStorage

logger = logging.getLogger(__name__)

class UserInfoCache:
    def __init__(self):
        self._steam_id: Optional[int] = None #unique id Steam assigns to the user
        self._account_username: Optional[str] = None #user name for the steam account.
        self._persona_name: Optional[str] = None #friendly name the user goes by in their display. It's what we use when saying "logged in" in the integration page.
        #Note: The tokens below are strings, but they are formatted as JSON Web Tokens (JWT). We can parse them to determine when the refresh token will expire.
        self._refresh_token : Optional[str] = None #persistent token. Used to log in, despite the fact that we should use an access token. weird quirk in how steam does things.
        self._access_token : Optional[str] = None #session login token. Largely useless. May be useful in future if steam fixes their login to use an access token instead of refresh token. 

        self._changed = False
        
        self.initialized = asyncio.Event()

    def _check_initialized(self):
        if self.is_initialized():
            logger.info("User info cache initialized")
            self.initialized.set()
            self._changed = True

    def is_initialized(self) -> bool:
        #if testing and you want to disable login from saved token, you can return false here. 

        return all([self._steam_id is not None, self._account_username, self._persona_name, self._refresh_token])


    def to_dict(self):
        """Return encrypted credentials with version info"""
        creds = {}
        if self.is_initialized():
            raw_creds = {
                'steam_id': str(self._steam_id),
                'refresh_token': self._refresh_token,
                'account_username': self._account_username,
                'persona_name': self._persona_name,
            }
            creds = SecureCredentialStorage.encrypt_credentials_v3(raw_creds)
        return creds

    def from_dict(self, lookup: Dict[str, str]):
        """Load and decrypt credentials with graceful error handling"""
        if not lookup:
            return
        
        # Decrypt credentials with automatic format detection
        # decrypt_credentials() detects format (v2, v3, or Base64) and decrypts accordingly
        try:
            decrypted_creds = SecureCredentialStorage.decrypt_credentials(lookup)
            
            # Load decrypted values
            if 'steam_id' in decrypted_creds:
                self._steam_id = int(decrypted_creds['steam_id'])
            if 'account_username' in decrypted_creds:
                self._account_username = decrypted_creds['account_username']
            if 'persona_name' in decrypted_creds:
                self._persona_name = decrypted_creds['persona_name']
            if 'refresh_token' in decrypted_creds:
                self._refresh_token = decrypted_creds['refresh_token']
                
        except Exception as e:
            logger.warning(f"Failed to decrypt credentials: {e}")
            # Gracefully handle decryption failure - mimic current behavior
            # Don't raise exception, just log and continue with empty state
            pass

    @property
    def changed(self):
        if self._changed:
            self._changed = False
            return True
        return False

    @property
    def steam_id(self):
        return self._steam_id

    @steam_id.setter
    def steam_id(self, val):
        if self._steam_id != val and self.initialized.is_set():
            self._changed = True
        self._steam_id = val
        if not self.initialized.is_set():
            self._check_initialized()

    @property
    def account_username(self):
        return self._account_username

    @account_username.setter
    def account_username(self, val):
        if self._account_username != val and self.initialized.is_set():
            self._changed = True
        self._account_username = val
        if not self.initialized.is_set():
            self._check_initialized()

    @property
    def persona_name(self):
        return self._persona_name

    @persona_name.setter
    def persona_name(self, val):
        if self._persona_name != val and self.initialized.is_set():
            self._changed = True
        self._persona_name = val
        if not self.initialized.is_set():
            self._check_initialized()

    @property
    def access_token(self):
        return self._access_token

    @access_token.setter
    def access_token(self, val):
        if self._access_token != val and self.initialized.is_set():
            self._changed = True
        self._access_token = val
        if not self.initialized.is_set():
            self._check_initialized()

    @property
    def refresh_token(self):
        return self._refresh_token

    @refresh_token.setter
    def refresh_token(self, val):
        if self._refresh_token != val and self.initialized.is_set():
            self._changed = True
        self._refresh_token = val
        if not self.initialized.is_set():
            self._check_initialized()

    def Clear(self):
        self._refresh_token = None
        self._steam_id = None 
        self._account_username = None 
        self._persona_name = None 
        self._access_token  = None 
