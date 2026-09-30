from authlib.common.urls import add_params_to_qs


def prepare_pushed_authorization_request(body="", **kwargs):
    params = []
    for key, value in kwargs.items():
        if value is None:
            continue
        if isinstance(value, (list, tuple)):
            params.extend((key, item) for item in value if item is not None)
        elif value is not False:
            params.append((key, value))
    return add_params_to_qs(body, params)
