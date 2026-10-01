from collections import defaultdict

from .authorization_details import AuthorizationDetailType
from .authorization_details import copy_authorization_details
from .authorization_details import get_authorization_details
from .authorization_details import read_request_authorization_details
from .authorization_details import validate_authorization_details_structure
from .errors import InvalidAuthorizationDetailsError

__all__ = ["register_authorization_detail_type"]


def register_authorization_detail_type(
    server, type_name, validator=None, narrower=None
):
    if isinstance(type_name, AuthorizationDetailType):
        handler = type_name
    else:
        if not isinstance(type_name, str) or not type_name:
            raise ValueError("Authorization detail type must be a non-empty string.")
        if not callable(validator):
            raise ValueError("Authorization detail validator must be callable.")
        if not callable(narrower):
            raise ValueError("Authorization detail narrower must be callable.")
        handler = AuthorizationDetailType(type_name, validator, narrower)

    server._authorization_detail_types[handler.type_name] = handler
    return handler


def validate_request_authorization_details(server, request):
    details = read_request_authorization_details(request)
    if details is None:
        request.authorization_details = None
        return None

    grouped = defaultdict(list)
    for detail in details:
        handler = server._authorization_detail_types.get(detail["type"])
        if handler is None:
            raise InvalidAuthorizationDetailsError(
                f"Unsupported authorization detail type '{detail['type']}'."
            )
        grouped[detail["type"]].append(detail)

    for type_name, requested in grouped.items():
        handler = server._authorization_detail_types[type_name]
        for detail in requested:
            try:
                handler.validate(request.client, detail, request)
            except InvalidAuthorizationDetailsError:
                raise
            except Exception as error:
                raise InvalidAuthorizationDetailsError() from error

    request.authorization_details = details
    return details


def grant_authorization_details(server, request, user):
    requested = request.authorization_details
    if not requested:
        return None

    grouped = defaultdict(list)
    for detail in requested:
        grouped[detail["type"]].append(detail)

    approved = []
    for type_name, requested_for_type in grouped.items():
        handler = server._authorization_detail_types.get(type_name)
        if handler is None:
            raise InvalidAuthorizationDetailsError(
                f"Unsupported authorization detail type '{type_name}'."
            )

        try:
            granted_for_type = []
            for detail in requested_for_type:
                granted_for_type.append(
                    handler.narrow(request.client, detail, user, request)
                )
        except InvalidAuthorizationDetailsError:
            raise
        except Exception as error:
            raise InvalidAuthorizationDetailsError() from error
        if not isinstance(granted_for_type, list):
            raise InvalidAuthorizationDetailsError()

        for detail in granted_for_type:
            if not isinstance(detail, dict) or detail.get("type") != type_name:
                raise InvalidAuthorizationDetailsError()
            handler.validate(request.client, detail, request)
        approved.extend(granted_for_type)

    approved = validate_authorization_details_structure(approved)
    request.authorization_details = approved
    return copy_authorization_details(approved)


def read_authorization_code_details(authorization_code):
    if hasattr(authorization_code, "get_authorization_details"):
        value = authorization_code.get_authorization_details()
    else:
        value = getattr(authorization_code, "authorization_details", None)
    return get_authorization_details(value)


def read_token_authorization_details(token):
    if hasattr(token, "get_authorization_details"):
        value = token.get_authorization_details()
    else:
        value = getattr(token, "authorization_details", None)
    return get_authorization_details(value)


def reject_token_authorization_details(request):
    if "authorization_details" in request.form:
        raise InvalidAuthorizationDetailsError(
            "'authorization_details' cannot be expanded during token exchange."
        )


def add_authorization_details(token, details):
    details = get_authorization_details(details)
    if details is not None:
        token["authorization_details"] = details
