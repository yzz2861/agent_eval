from typing import Annotated, Any

from annotated_doc import Doc
from fastapi.exceptions import HTTPException
from fastapi.openapi.models import SecurityBase as SecurityBaseModel


class SecurityBase:
    model: SecurityBaseModel
    scheme_name: str


class SecurityGroupBase:
    """
    Base class for groups of security schemes.

    Groups combine several security schemes (or nested groups) so that the
    runtime authentication and the OpenAPI security requirements express the
    same AND/OR rules.

    Use AllOf to require that all the schemes in the group succeed, and
    AnyOf to try several alternatives in order, using the first one that
    succeeds.
    """

    def __init__(
        self,
        *dependencies: Annotated[
            Any,
            Doc(
                """
                The security schemes, security groups, or Security() /
                Depends() declarations wrapping them, that compose this
                group.
                """
            ),
        ],
    ):
        if not dependencies:
            raise ValueError(
                "Security groups require at least one security scheme or group"
            )
        self.dependencies = list(dependencies)


class AllOf(SecurityGroupBase):
    """
    Security group that requires all the contained security schemes to
    succeed (logical AND).

    All the schemes in the group are resolved, if any of them fails, the
    whole group fails with that scheme's error.

    In OpenAPI, the schemes in the group are declared together in a single
    security requirement object.
    """


class AnyOf(SecurityGroupBase):
    """
    Security group that tries each contained security scheme or group in
    order and uses the first one that succeeds (logical OR).

    If a branch fails, its partial results are discarded and the next branch
    is tried. If all the branches fail, a single configurable error is
    raised, without exposing the internal errors of the individual branches.

    In OpenAPI, each branch is declared as a separate security requirement
    object.
    """

    def __init__(
        self,
        *dependencies: Annotated[
            Any,
            Doc(
                """
                The security schemes, security groups, or Security() /
                Depends() declarations wrapping them, to try in order.
                """
            ),
        ],
        status_code: Annotated[
            int,
            Doc(
                """
                The HTTP status code to use when all the alternatives fail.
                """
            ),
        ] = 401,
        detail: Annotated[
            Any,
            Doc(
                """
                The error detail to use when all the alternatives fail.
                """
            ),
        ] = "Not authenticated",
        authenticate_header: Annotated[
            str | None,
            Doc(
                """
                The value for the WWW-Authenticate header to use when all
                the alternatives fail. If not set, the header is not sent.
                """
            ),
        ] = None,
    ):
        super().__init__(*dependencies)
        self.status_code = status_code
        self.detail = detail
        self.authenticate_header = authenticate_header

    def make_error(self) -> HTTPException:
        headers = None
        if self.authenticate_header is not None:
            headers = {"WWW-Authenticate": self.authenticate_header}
        return HTTPException(
            status_code=self.status_code, detail=self.detail, headers=headers
        )
