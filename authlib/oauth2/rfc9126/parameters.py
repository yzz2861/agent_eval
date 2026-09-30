from authlib.common.urls import add_params_to_uri


def prepare_pushed_authorization_grant_uri(uri, request_uri, client_id=None):
    params = [("request_uri", request_uri)]
    if client_id is not None:
        params.append(("client_id", client_id))
    return add_params_to_uri(uri, params)
