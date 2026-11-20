ngclient
========

The ngclient module contains a complete TUF client library implementation.

* :doc:`tuf.ngclient.updater` implements the `detailed client workflow`_
* :doc:`tuf.ngclient.config` provides optional configuration for the updater
* :doc:`tuf.ngclient.fetcher` can be used for optional low-level network I/O control
* :doc:`tuf.ngclient.quarantine` provides a local, caller-managed quarantine policy


.. toctree::
   :hidden:

   tuf.ngclient.updater
   tuf.ngclient.config
   tuf.ngclient.fetcher
   tuf.ngclient.quarantine

.. _detailed client workflow: https://theupdateframework.github.io/specification/latest/#detailed-client-workflow
