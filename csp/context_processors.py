from __future__ import annotations

from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from django.http import HttpRequest


def nonce(request: HttpRequest) -> dict[Literal["CSP_NONCE"], str]:
    # Evaluate the lazy object so the nonce is generated exactly once per
    # request and ends up in the CSP header written by the middleware.
    csp_nonce = str(getattr(request, "csp_nonce", ""))

    return {"CSP_NONCE": csp_nonce}
