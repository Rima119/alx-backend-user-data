#!/usr/bin/env python3
"""Auth class Module
"""

from flask import request
from typing import List, Pattern, TypeVar


class Auth:
    """Auth class"""
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """require auth method, allowing * at the end of excluded paths"""
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
        """adds authorization header"""
        if request is not None:
            return request.headers.get('Authorization', None)
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """gets the current user"""
        None

    def session_cookie(self, request=None):
        """returns a cookie value from a request
        """
        if request is None:
            return None
        _my_session_id = getenv("SESSION_NAME")
        return request.cookies.get(_my_session_id)
