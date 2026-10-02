Support for ``wsgi.file_wrapper``
---------------------------------

Waitress supports the Python Web Server Gateway Interface v1.0 as specified in :pep:`3333`.  Here's a usage example:

.. code-block:: python

    import os

    here = os.path.dirname(os.path.abspath(__file__))

    def myapp(environ, start_response):
        f = open(os.path.join(here, 'myphoto.jpg'), 'rb')
        headers = [('Content-Type', 'image/jpeg')]
        start_response(
            '200 OK',
            headers
            )
        return environ['wsgi.file_wrapper'](f, 32768)

The file wrapper constructor is accessed via
``environ['wsgi.file_wrapper']``.  The signature of the file wrapper
constructor is ``(filelike_object, block_size)``.  Both arguments must be
passed as positional (not keyword) arguments.  The result of creating a file
wrapper should be **returned** as the ``app_iter`` from a WSGI application.

The object passed as ``filelike_object`` to the wrapper must be a file-like
object which supports *at least* the ``read()`` method, and the ``read()``
method must support an optional size hint argument and the ``read()`` method
*must* return **bytes** objects (never unicode).  It *should* support the
``seek()`` and ``tell()`` methods.  If it does not, normal iteration over the
``filelike_object`` using the provided ``block_size`` is used (and copying is
done, negating any benefit of the file wrapper). It *should* support a
``close()`` method.

The specified ``block_size`` argument to the file wrapper constructor will be
used only when the ``filelike_object`` doesn't support ``seek`` and/or
``tell`` methods.  Waitress needs to use normal iteration to serve the file
in this degenerate case (as per the WSGI pec), and this block size will be
used as the iteration chunk size.  The ``block_size`` argument is optional;
if it is not passed, a default value ``32768`` is used.

Waitress will set a ``Content-Length`` header on behalf of an application
when a file wrapper with a sufficiently file-like object is used if the
application hasn't already set one.

When both the response socket and wrapped file support ``os.sendfile()``,
Waitress uses it to transfer the response without copying the file contents
through Python. The requested range is limited to the current file position
and response length established by ``Content-Length`` (or the remaining file
size when the application does not set one). Short writes resume from the
same offset, and retryable errors or an unsupported file/socket combination
fall back to the buffered read-and-send path without repeating or omitting
bytes. A client disconnection is handled by the normal connection close path.
