#!/usr/bin/env python3
"""Session authentication with expiration module for the API.
"""
import os
import re
from flask import request
from datetime import datetime, timedelta

# Importing the base class
from api.v1.auth.session_auth import SessionAuth


class SessionExpAuth(SessionAuth):
    """Session authentication class with expiration.
    """

    def __init__(self) -> None:
        """Initializes a new SessionExpAuth instance.
        """
        super().__init__()
        tmp = os.getenv('SESSION_DURATION', '0')
        if re.fullmatch(r'[+-]?\d+', tmp) is not None:
            self.session_duration = int(tmp)
        else:
            self.session_duration = 0

    def create_session(self, user_id=None):
        """Creates a session id for the user.
        """
        session_id = super().create_session(user_id)
        if session_id is None:
            return None
        self.user_id_by_session_id[session_id] = {
            'user_id': user_id,
            'created_at': datetime.now(),
        }
        return session_id

    def user_id_for_session_id(self, session_id=None):
        """Retrieves the user id of the user associated with
        a given session id.
        """
        if session_id in self.user_id_by_session_id:
            session_dict = self.user_id_by_session_id[session_id]
            if self.session_duration > 0 and 'created_at' in session_dict:
                cur_time = datetime.now()
                time_span = timedelta(seconds=self.session_duration)
                exp_time = session_dict['created_at'] + time_span
                if exp_time < cur_time:
                    return None
            return session_dict['user_id']
        return None

