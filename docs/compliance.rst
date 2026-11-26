.. # Licensed under the Apache License, Version 2.0 (the "License");
   # you may not use this file except in compliance with the License.
   # You may obtain a copy of the License at
   #
   #     http://www.apache.org/licenses/LICENSE-2.0
   #
   # Unless required by applicable law or agreed to in writing, software
   # distributed under the License is distributed on an "AS IS" BASIS,
   # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   # See the License for the specific language governing permissions and
   # limitations under the License.
   #
   # SPDX-License-Identifier: Apache-2.0

Offline Residency Compliance
=============================

``cyclonedx.compliance`` evaluates a CycloneDX service inventory without contacting
the services or proof providers. It follows every condition-enabled service-reference
route, including failover routes, and applies the data categories carried along the
route to every processing node.

Declaring regions and proofs
----------------------------

The standard service provider address is used as a region claim. More precise claims
can be supplied as service properties::

   "properties": [
     {"name": "residency:region", "value": "DE"},
     {"name": "residency:proof", "value": "urn:evidence:region-de-2026"}
   ]

An ``evidence``, ``attestation``, or ``certification-report`` external reference is also
accepted as a traceable proof. A region without such a reference is reported as
``proof_missing``; it is not silently treated as compliant. Set ``require_proof=False``
only when a declaration-only policy is explicitly intended.

The checker also accepts a non-schema extension block for graph-level conditions::

   "x-residency": {
     "entrypoints": ["gateway"],
     "endpoints": ["archive-eu", "analytics-us"],
     "edges": [
       {"from": "gateway", "to": "backup-router", "condition": "failover"}
     ]
   }

The same data can be carried in BOM-level ``residency:edges``, ``residency:nodes``,
``residency:conditions``, ``residency:entrypoints``, and ``residency:endpoints``
JSON-valued properties.

Policy
------

A policy maps data classifications to allowed regions::

   policy = {
       "allowed_regions": {
           "PII": ["EU"],
           "Customer": ["EU", "US"],
           "Public": ["*"],
       },
       "enabled_conditions": ["failover"],
       "require_proof": True,
   }

Region matching is offline and case-insensitive. Country codes, compound region names
such as ``us-east-1``, and the ``EU`` grouping are understood. An empty condition set
disables conditional branches; skipped branches are listed separately from endpoint
compliance findings.

Python API
----------

.. code-block:: python

   from cyclonedx.compliance import check_residency

   report = check_residency("service-manifest.json", policy)
   for finding in report.non_compliant_endpoints:
       print(finding.endpoint, finding.path.refs)

Each endpoint finding contains ``shortest_paths``. Every step includes the carried data
categories, region claims, proof references, and violations, so the path can be traced
back through the manifest. Circular service references are reported in ``cycles``;
unreachable endpoints and unreferenced services are not listed as reachable findings.

Command line
------------

.. code-block:: shell

   python -m cyclonedx.compliance service-manifest.json \
       --policy residency-policy.json \
       --enable-condition failover \
       --output report.json

The command prints JSON by default. Use ``--fail-on-noncompliance`` in CI to return a
non-zero status when a reachable endpoint cannot be proven compliant.
