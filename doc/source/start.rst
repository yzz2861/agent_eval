Getting Started
===============

Installation
------------

Bandit is distributed on PyPI. The best way to install it is with pip.

Create a virtual environment and activate it using `virtualenv` (optional):

.. code-block:: console

    virtualenv bandit-env
    source bandit-env/bin/activate

Alternatively, use `venv` instead of `virtualenv` (optional):

.. code-block:: console

    python3 -m venv bandit-env
    source bandit-env/bin/activate

Install Bandit:

.. code-block:: console

    pip install bandit

If you want to include TOML support, install it with the `toml` extras:

.. code-block:: console

    pip install bandit[toml]

If you want to use the bandit-baseline CLI, install it with the `baseline`
extras:

.. code-block:: console

    pip install bandit[baseline]

If you want to include SARIF output formatter support, install it with the
`sarif` extras:

.. code-block:: console

    pip install bandit[sarif]

Run Bandit:

.. code-block:: console

    bandit -r path/to/your/code

Bandit can also be installed from source. To do so, either clone the
repository or download the source tarball from PyPI, then install it:

.. code-block:: console

    python setup.py install

Alternatively, let pip do the downloading for you, like this:

.. code-block:: console

    pip install git+https://github.com/PyCQA/bandit#egg=bandit

Usage
-----

Example usage across a code tree:

.. code-block:: console

    bandit -r ~/your_repos/project

Two examples of usage across the ``examples/`` directory, showing three lines of
context and only reporting on the high-severity issues:

.. code-block:: console

    bandit examples/*.py -n 3 --severity-level=high

.. code-block:: console

    bandit examples/*.py -n 3 -lll

Bandit can be run with profiles. To run Bandit against the examples directory
using only the plugins listed in the ``ShellInjection`` profile:

.. code-block:: console

    bandit examples/*.py -p ShellInjection

Bandit also supports passing lines of code to scan using standard input. To
run Bandit with standard input:

.. code-block:: console

    cat examples/imports.py | bandit -

Multi-target syntax scanning
----------------------------

If a project supports more than one Python version, a file can be valid for
one grammar target and invalid for another.  The host interpreter is still
the only parser used; ``ast.parse(feature_version=...)`` emulates older
grammars, and no extra Python installation is required.

.. code-block:: console

    bandit -r path/to/code --target-versions 3.8,3.12,3.14 -f json

``--target-versions`` may also be repeated (for example
``--target-version 3.8 --target-version 3.12``).

The JSON report keeps the normal ``results``, ``errors`` and ``metrics``
fields and adds a ``target_results`` block.  Each file has one entry per
target with an explicit status:

``CHECKED``
    The file parsed and every applicable rule completed.

``REJECTED``
    The file is not valid syntax for this target, so no rule result exists.

``UNCOVERED``
    The host cannot emulate this grammar (for example a target newer than
    the running interpreter).  It was not scanned; an empty result must not
    be read as a clean result.

``INCONCLUSIVE``
    The file was readable but at least one rule could not complete.  Any
    findings are partial.

Findings at the same location and with the same rule ID are merged across
targets.  ``python_versions`` lists the targets in which the finding
applies, while ``suppressed``, ``suppressed_versions``,
``suppressed_test_ids`` and ``blanket_nosec`` preserve the original rule ID
and the ``# nosec`` state.

For more usage information:

.. code-block:: console

    bandit -h

Baseline
--------

Bandit allows specifying the path of a baseline report to compare against using the base line argument (i.e. ``-b BASELINE`` or ``--baseline BASELINE``).

.. code-block:: console

   bandit -b BASELINE

This is useful for ignoring known vulnerabilities that you believe are non-issues (e.g. a cleartext password in a unit test). To generate a baseline report simply run Bandit with the output format set to ``json`` (only JSON-formatted files are accepted as a baseline) and output file path specified:

.. code-block:: console

    bandit -f json -o PATH_TO_OUTPUT_FILE

Version control integration
---------------------------

Use `pre-commit`_. Once you `have it installed`_, add this to the
``.pre-commit-config.yaml`` in your repository
(be sure to update `rev` to point to a `real git tag/revision`_!):

.. code-block:: yaml

    repos:
    - repo: https://github.com/PyCQA/bandit
      rev: '' # Update me!
      hooks:
      - id: bandit

Then run ``pre-commit install`` and you're ready to go.

.. _pre-commit: https://pre-commit.com/
.. _have it installed: https://pre-commit.com/#install
.. _`real git tag/revision`: https://github.com/PyCQA/bandit/releases
