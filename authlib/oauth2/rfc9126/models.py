import time


class PushedAuthorizationRequestMixin:
    def get_client_id(self):
        raise NotImplementedError()

    def get_data(self):
        raise NotImplementedError()

    def get_expires_at(self):
        raise NotImplementedError()

    def is_expired(self):
        return self.get_expires_at() < time.time()


class PushedAuthorizationRequestInfo(dict, PushedAuthorizationRequestMixin):
    def __init__(self, request_uri, client_id, data, expires_at):
        super().__init__(
            request_uri=request_uri,
            client_id=client_id,
            data=data,
            expires_at=expires_at,
        )

    @property
    def request_uri(self):
        return self["request_uri"]

    def get_client_id(self):
        return self["client_id"]

    def get_data(self):
        return self["data"]

    def get_expires_at(self):
        return self["expires_at"]


class PushedAuthorizationRequestNotFoundError(Exception):
    """Raised when a pushed request does not exist or was already consumed."""
