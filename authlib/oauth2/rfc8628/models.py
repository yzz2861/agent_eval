import time


class DeviceCredentialMixin:
    def get_client_id(self):
        raise NotImplementedError()

    def get_scope(self):
        raise NotImplementedError()

    def get_user_code(self):
        raise NotImplementedError()

    def is_expired(self):
        raise NotImplementedError()


class DeviceCredentialDict(dict, DeviceCredentialMixin):
    def get_client_id(self):
        return self["client_id"]

    def get_scope(self):
        return self.get("scope")

    def get_authorization_details(self):
        value = self.get("authorization_details")
        if isinstance(value, str):
            from ..rfc9396.authorization_details import get_authorization_details

            value = get_authorization_details(value)
        return value

    def get_user_code(self):
        return self["user_code"]

    def get_nonce(self):
        return self.get("nonce")

    def get_auth_time(self):
        return self.get("auth_time")

    def is_expired(self):
        expires_at = self.get("expires_at")
        if expires_at is not None:
            return expires_at < time.time()
        return False
