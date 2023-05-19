#!/usr/bin/env python3
""" Module for API authentication
"""
from flask import request
from typing import List, TypeVar
import os
from models.user import User


class Auth:
    """ Auth class
    """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """ Require auth method
        allowing * at the end of excluded paths
        """
        if path is None or excluded_paths is None or excluded_paths == []:
            return True
        if path[-1] != '/':
            path += '/'
        for p in excluded_paths:
            if p[-1] == '*':
                if path.startswith(p[:-1]):
                    return False
            elif path == p:
                return False
        return True

    def authorization_header(self, request=None) -> str:
        """ Authorization header method
        """
        if request is None or 'Authorization' not in request.headers:
            return None
        return request.headers['Authorization']

    def current_user(self, request=None) -> TypeVar('User'):
        """ Current user method
        """
        return None

    def session_cookie(self, request=None):
        """Returns a cookie value from a request"""
        if request is None:
            return None
        return request.cookies.get(os.getenv('SESSION_NAME'))
