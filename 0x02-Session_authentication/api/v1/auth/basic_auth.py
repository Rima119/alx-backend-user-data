#!/usr/bin/env python3
""" Module for API authentication
"""
from typing import List, TypeVar, Tuple
from .auth import Auth
import base64
import binascii


class BasicAuth(Auth):
    """ BasicAuth class
    """
    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """ Extract base64 authorization header method
        """
        if authorization_header is None or \
           type(authorization_header) is not str or \
           not authorization_header.startswith('Basic '):
            return None
        return authorization_header[6:]

    def decode_base64_authorization_header(self,
                                           base64_authorization_header: str
                                           ) -> str:
        """ Decode base64 authorization header method
        """
        if base64_authorization_header is None or \
              type(base64_authorization_header) is not str:
                return None
        try:
            return base64.b64decode(
                base64_authorization_header).decode('utf-8')
        except binascii.Error:
            return None
        
    def extract_user_credentials(self,
                                    decoded_base64_authorization_header: str
                                    ) -> Tuple['str', 'str']:
            """ Extract user credentials method
            """
            if decoded_base64_authorization_header is None or \
            type(decoded_base64_authorization_header) is not str or \
            ':' not in decoded_base64_authorization_header:
                return (None, None)
            return tuple(decoded_base64_authorization_header.split(':', 1))

    def user_object_from_credentials(self, user_email: str, user_pwd: str
                                     ) -> TypeVar('User'):
        """ User object from credentials method
        """
        if user_email is None or type(user_email) is not str or \
           user_pwd is None or type(user_pwd) is not str:
            return None
        from models.user import User
        try:
            users = User.search({'email': user_email})
        except Exception:
            return None
        if users is None or users == []:
            return None
        for user in users:
            if user.is_valid_password(user_pwd):
                return user
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """ Current user method
        """
        auth_header = self.authorization_header(request)
        b64_auth_header = self.extract_base64_authorization_header(
            auth_header)
        decoded_auth_header = self.decode_base64_authorization_header(
            b64_auth_header)
        user_credentials = self.extract_user_credentials(decoded_auth_header)
        return self.user_object_from_credentials(
            user_credentials[0], user_credentials[1])
