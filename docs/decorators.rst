.. _decorator-chapter:

====================================
Modifying the Policy with Decorators
====================================

Content Security Policies should be restricted and paranoid by default.  You may, on some views,
need to expand or change the policy. django-csp includes four decorators to help.

All decorators take an optional keyword argument, ``REPORT_ONLY``, which defaults to ``False``. If
set to ``True``, the decorator will update the report-only policy instead of the enforced policy.

``@csp_exempt``
===============

Using the ``@csp_exempt`` decorator disables the CSP header on a given
view.

.. code-block:: python

    from csp.decorators import csp_exempt


    # Will not have a CSP header.
    @csp_exempt()
    def myview(request):
        return render(...)


    # Will not have a CSP report-only header.
    @csp_exempt(REPORT_ONLY=True)
    def myview(request):
        return render(...)

You can manually set this on a per-response basis by setting the ``_csp_exempt``
or ``_csp_exempt_ro`` attribute on the response to ``True``:

.. code-block:: python

    # Also will not have a CSP header.
    def myview(request):
        response = render(...)
        response._csp_exempt = True
        return response


``@csp_update``
===============

The ``@csp_update`` header allows you to **append** values to the source lists specified in the
settings. If there is no setting, the value passed to the decorator will be used verbatim.

.. note::

   To quote the CSP spec: "There's no inheritance; ... the default list is not used for that
   resource type" if it is set. E.g., the following will not allow images from 'self':

    default-src 'self'; img-src imgsrv.com

The arguments to the decorator are the same as the :ref:`settings <configuration-chapter>`. The
decorator expects a single dictionary argument, where the keys are the directives and the values
are either strings, lists or tuples. An optional argument, ``REPORT_ONLY``, can be set to ``True``
to update the report-only policy instead of the enforced policy.

.. code-block:: python

    from csp.decorators import csp_update


    # Will append imgsrv.com to the list of values for `img-src` in the enforced policy.
    @csp_update({"img-src": "imgsrv.com"})
    def myview(request):
        return render(...)


    # Will append cdn-img.com to the list of values for `img-src` in the report-only policy.
    @csp_update({"img-src": "cdn-img.com"}, REPORT_ONLY=True)
    def myview(request):
        return render(...)


``@csp_replace``
================

The ``@csp_replace`` decorator allows you to **replace** a source list specified in settings. If
there is no setting, the value passed to the decorator will be used verbatim. (See the note under
``@csp_update``.) If the specified value is None, the corresponding key will not be included.

The arguments and values are the same as ``@csp_update``:

.. code-block:: python

    from csp.decorators import csp_replace


    # Will allow images only from imgsrv2.com in the enforced policy.
    @csp_replace({"img-src": "imgsrv2.com"})
    def myview(request):
        return render(...)


    # Will allow images only from cdn-img2.com in the report-only policy.
    @csp_replace({"img-src": "cdn-img2.com"}, REPORT_ONLY=True)
    def myview(request):
        return render(...)

The ``csp_replace`` decorator can also be used to remove a directive from the policy by setting the
value to ``None``. For example, if the ``frame-ancestors`` directive is set in the Django settings
and you want to remove the ``frame-ancestors`` directive from the policy for this view:

.. code-block:: python

    from csp.decorators import csp_replace


    @csp_replace({"frame-ancestors": None})
    def myview(request):
        return render(...)


``@csp``
========

If you need to set the entire policy on a view, ignoring all the settings, you can use the ``@csp``
decorator. This can be stacked to update both the enforced policy and the report-only policy if both
are in use, as shown below.

.. code-block:: python

    from csp.constants import SELF, UNSAFE_INLINE
    from csp.decorators import csp


    @csp(
        {
            "default-src": [SELF],
            "img-src": ["imgsrv.com"],
            "script-src": ["scriptsrv.com", "googleanalytics.com", UNSAFE_INLINE],
        }
    )
    @csp(
        {
            "default-src": [SELF],
            "img-src": ["imgsrv.com"],
            "script-src": ["scriptsrv.com", "googleanalytics.com"],
            "frame-src": [SELF],
        },
        REPORT_ONLY=True,
    )
    def myview(request):
        return render(...)


Per-request overrides
======================

All of the per-view decorators above work by setting attributes on the
``HttpResponse``. The same overrides can also be applied directly to the
``HttpRequest``, which is useful when the policy must be decided by another
middleware or by logic that runs before the view returns a response.

The request attributes mirror the response attributes used by the decorators:

.. code-block:: python

    from csp.request_attrs import (
        REQUEST_CONFIG,
        REQUEST_UPDATE,
        REQUEST_REPLACE,
        REQUEST_EXEMPT,
        REQUEST_REPORT_ONLY,
    )


    def my_view(request):
        # Replace the whole enforced policy for this request.
        setattr(request, REQUEST_CONFIG, {"default-src": ["example.com"]})
        # Or append / replace individual directives.
        setattr(request, REQUEST_UPDATE, {"img-src": ["img.example.com"]})
        setattr(request, REQUEST_REPLACE, {"font-src": ["font.example.com"]})
        # Or exempt the request entirely.
        setattr(request, REQUEST_EXEMPT, True)
        return render(...)

Each attribute also has a report-only counterpart suffixed with ``_RO``
(``REQUEST_CONFIG_RO``, ``REQUEST_UPDATE_RO``, ``REQUEST_REPLACE_RO`` and
``REQUEST_EXEMPT_RO``). When both a response attribute (set by a decorator)
and a request attribute are present, the response attribute takes precedence.

Switching enforcement to report-only per request
-------------------------------------------------

Setting ``REQUEST_REPORT_ONLY`` to ``True`` routes the *enforced* policy
through the ``Content-Security-Policy-Report-Only`` header for that request
instead of ``Content-Security-Policy``. The standalone report-only policy is
suppressed while the switch is active so the effective policy is not emitted
twice:

.. code-block:: python

    from csp.request_attrs import REQUEST_REPORT_ONLY


    def my_view(request):
        setattr(request, REQUEST_REPORT_ONLY, True)
        return render(...)

The equivalent decorator is ``csp.decorators.csp_report_only``:

.. code-block:: python

    from csp.decorators import csp_report_only


    @csp_report_only
    def my_view(request):
        return render(...)
