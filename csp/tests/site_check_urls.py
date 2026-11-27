from __future__ import annotations

from django.http import HttpRequest, HttpResponse, HttpResponseRedirect, HttpResponseServerError
from django.urls import path

from csp.decorators import csp_update


def ok(request: HttpRequest) -> HttpResponse:
    return HttpResponse("ok")


@csp_update({"img-src": ["cdn.example.com"]})
def ok_with_own_config(request: HttpRequest) -> HttpResponse:
    return HttpResponse("ok")


def error(request: HttpRequest) -> HttpResponse:
    raise ValueError("synthetic error")


def redirect(request: HttpRequest) -> HttpResponseRedirect:
    return HttpResponseRedirect("/ok/")


def server_error(request: HttpRequest) -> HttpResponseServerError:
    return HttpResponseServerError("shared layer error page")


handler500 = server_error

urlpatterns = [
    path("ok/", ok),
    path("ok-own/", ok_with_own_config),
    path("error/", error),
    path("redirect/", redirect),
]
