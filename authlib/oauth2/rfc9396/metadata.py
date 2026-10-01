from ..rfc8414.models import validate_array_value


class AuthorizationServerMetadata(dict):
    """Authorization Server Metadata extension for RFC 9396 (Rich
    Authorization Requests).

    This class can be used with
    :meth:`~authlib.oauth2.rfc8414.AuthorizationServerMetadata.validate
    to validate the metadata defined by RFC 9396::

        from authlib.oauth2 import rfc8414, rfc9396

        metadata = rfc8414.AuthorizationServerMetadata(data)
        metadata.validate(metadata_classes=[rfc9396.AuthorizationServerMetadata])
    """

    REGISTRY_KEYS = ["authorization_details_types_supported"]

    def validate_authorization_details_types_supported(self):
        """OPTIONAL. JSON array containing a list of the authorization
        details ``type`` values supported by the authorization server.
        """
        validate_array_value(self, "authorization_details_types_supported")
        values = self.get("authorization_details_types_supported")
        if values is not None and not all(isinstance(v, str) for v in values):
            raise ValueError(
                '"authorization_details_types_supported" MUST contain string values'
            )

    def __getattr__(self, key):
        try:
            return object.__getattribute__(self, key)
        except AttributeError as error:
            if key in self.REGISTRY_KEYS:
                return self.get(key)
            raise error
