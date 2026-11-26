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

Modelling
=========

You can create a BOM Model from either manually using the methods available
directly on the :py:class:`cyclonedx.model.bom.Bom` class,
or deserialize a JSON/XML via :py:meth:`cyclonedx.model.bom.Bom.from_json`/:py:meth:`cyclonedx.model.bom.Bom.from_xml`

Vulnerabilities are supported by the Model as of version 0.3.0.

    **Note:** Known vulnerabilities associated with Components can be sourced from various data sources, but this library
    will not source them for you. Perhaps look at `Jake`_ if you're interested in this.

Example BOM created programmatically
------------------------------------

.. note::

    It is recommended that you have a good understanding of the `CycloneDX Schema`_ before attempting to create a BOM
    programmatically with this library.


For the most up-to-date in-depth examples, look at our `Unit Tests`_.

Example BOM created from existing CycloneDX BOM
------------------------------------

.. note::

    Supported from version 4.0.0 of this library.

Deserializing from a CycloneDX JSON BOM
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Each model class in this library that is serializable provides a magic ``from_json()`` method.

See the example below to read and deserialize a JSON CycloneDX document. Note that reading the file and loading as JSON
is the programmers responsibility.

.. code-block:: python

    import json
    from cyclonedx.model.bom import Bom

    with open('/path/to/my/cyclonedx.json') as input_json:
        deserialized_bom = Bom.from_json(data=json.loads(input_json.read()))


Deserializing from a CycloneDX XML BOM
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Each model class in this library that is serializable provides a magic ``from_xml()`` method.

See the example below to read and deserialize a XML CycloneDX document. Note that reading the file and loading as XML
is the programmers responsibility. Be careful to avoid XML vulnerabilities as documented `here`_. It is recommended that
you use a library such as `defusedxml` instead of the native `xml.etree.ElementTree`.

.. code-block:: python

    from xml.etree import ElementTree
    from cyclonedx.model.bom import Bom

    with open('/path/to/my/cyclonedx.xml') as input_xml:
        deserialized_bom = cast(Bom, Bom.from_xml(data=ElementTree.fromstring(input_xml.read())))


Evidence provenance and on-site review
--------------------------------------

CycloneDX evidence records *what* was observed.  When several on-site unpacking
events share a part number, the part number alone cannot say which local sample a
conclusion belongs to.  The optional provenance overlay binds every evidence
``Identity`` (a conclusion point) to:

* a ``LocalSample`` -- the on-site unpacking sample;
* a ``BatchInterval`` -- the batch interval the evidence can support; and
* an ``EvidenceSeal`` plus ``photo_index`` -- the two checks needed to establish
  ownership.

The overlay is kept outside the CycloneDX wire format because the CycloneDX
schema does not allow extension fields on evidence.  It is attached to the public
``ComponentEvidence`` and ``Identity`` models and is therefore available while
reviewing imported BOMs.

Attribution follows these rules:

1. A batch-interval intersection makes a sample a **candidate** only.
2. A candidate is **attributed** only if its photo index **and** seal confirmation
   both match.
3. Evidence shared by samples from different batches is reported as **contested**
   with a warning naming the competing batches and samples.
4. Evidence imported from a legacy manifest carries
   ``BatchInterval.unknown()`` and is preserved as an explicit *batch unknown*
   layer.  Unknown batches are never treated as wildcards.

.. code-block:: python

    from cyclonedx.model.component_evidence import (
        BatchInterval,
        ComponentEvidence,
        EvidenceProvenance,
        EvidenceSeal,
        Identity,
        IdentityField,
        LocalSample,
    )

    first = LocalSample(
        sample_id='UNPACK-1', batch=BatchInterval(1, 3),
        photo_index='PHOTO-1', seal=EvidenceSeal('SEAL-1'))
    second = LocalSample(
        sample_id='UNPACK-2', batch=BatchInterval(4, 6),
        photo_index='PHOTO-2', seal=EvidenceSeal('SEAL-2'))

    evidence = ComponentEvidence(identity=[Identity(
        field=IdentityField.HASH,
        concluded_value='tamper-check-ok',
        provenance=EvidenceProvenance(
            sample_id='UNPACK-2',
            batch=BatchInterval(4, 6),
            photo_index='PHOTO-2',
            seal=EvidenceSeal('SEAL-2'),
        ),
    )])

    review = evidence.review([first, second])
    print(review.trace_sample_ids())  # conclusion -> original sample ids
    for warning in review.warnings:
        print(warning)

When a manifest predates provenance tracking, every conclusion is layered as a
legacy record automatically.  ``ComponentEvidence.from_legacy(evidence)`` can
also be used to re-layer evidence explicitly as batch-unknown.




.. _CycloneDX Python: https://github.com/CycloneDX/cyclonedx-python
.. _Jake: https://pypi.org/project/jake
.. _CycloneDX Schema: https://cyclonedx.org/docs/latest
.. _Unit Tests: https://github.com/CycloneDX/cyclonedx-python-lib/tree/main/tests
.. _here: https://docs.python.org/3/library/xml.html#xml-vulnerabilities
