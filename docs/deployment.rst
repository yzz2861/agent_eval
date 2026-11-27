Deployment timing
=================

.. py:module:: jks.deployment

PyJKS can expose the X.509 validity period of public certificates and use
those values to calculate cutover timing.

Certificate views
-----------------

.. autoclass:: jks.x509.X509Certificate
    :members:
    :member-order: groupwise

Trusted certificate entries provide ``public_certificate`` and
``public_certificates``. Private key and BKS key entries provide
``public_certificates`` for their certificate chains.

Cutover planning
----------------

.. autofunction:: plan_service_cutover

.. autoclass:: DeploymentPlan
    :members:

.. autoclass:: ServicePlan
    :members:

.. autoclass:: Constraint
    :members:

Each service-level ``start_interval`` contains the valid actual start time
for that service. The top-level ``start_interval`` contains valid start times
for the whole cutover, after each service's ``start_offset`` is applied.
An empty tuple means that no start time satisfies every constraint. The
``waiting_for_keystore`` tuple names services whose keystore is not available
at the supplied fixed clock value.
