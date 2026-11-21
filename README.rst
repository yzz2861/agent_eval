filetype.py |PyPI| |Pyversions| |API|
=====================================

Small and dependency free `Python`_ package to infer file type and MIME
type checking the `magic numbers`_ signature of a file or buffer.

This is a Python port from `filetype`_ Go package.

Features
--------

-  Simple and friendly API
-  Supports a `wide range`_ of file types
-  Provides file extension and MIME type inference
-  File discovery by extension or MIME type
-  File discovery by kind (image, video, audio…)
-  `Pluggable`_: add new custom type matchers
-  `Fast`_, even processing large files
-  Only first 261 bytes representing the max file header is required, so
   you can just `pass a list of bytes`_
-  Dependency free (just Python code, no C extensions, no libmagic
   bindings)
-  Cross-platform file recognition

Installation
------------

::

    pip install filetype

API
---

See `annotated API reference`_.

Examples
--------

Simple file type checking
^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

    import filetype

    def main():
        kind = filetype.guess('tests/fixtures/sample.jpg')
        if kind is None:
            print('Cannot guess file type!')
            return

        print('File extension: %s' % kind.extension)
        print('File MIME type: %s' % kind.mime)

    if __name__ == '__main__':
        main()

Matcher impact assessment
-------------------------

A new matcher is registered at the front of the registry, so it can silently
shadow a matcher that used to win. ``filetype.impact`` compares the same
offline file prefixes against two ordered registries and keeps two operational
findings separate:

- **new legitimate format**: the prefix had no match before and now resolves
  to a matcher (with no routing table this is still reported, with
  routed: false);
- **downgrade**: the prefix already matched an old type, but its route now has
  a lower processing ``capability`` (a weaker queue).

The report also records every matching candidate with its one based ``rank``,
so registration-order changes are visible even when the winning type stays the
same. If a third-party matcher raises, the failure is attached to the affected
sample and the registry side that raised it. Both full routing configurations
are embedded in every report.

.. code-block:: python

    import filetype
    from filetype.impact import assess, render_text

    report = assess(
        samples={"photo.jpg": open("tests/fixtures/sample.jpg", "rb").read(8192)},
        before=filetype.types,
        after=[MyNewMatcher()] + list(filetype.types),
        before_routes={"image/jpeg": {"queue": "image-strong", "capability": 10}},
        after_routes={
            "image/jpeg": {"queue": "image-strong", "capability": 10},
            "application/x-new": {"queue": "new-medium", "capability": 6},
        },
    )
    print(render_text(report))

The same comparison is available offline from the command line:

.. code-block:: console

    $ python -m filetype.impact \
        --samples examples/impact/samples.json \
        --before-routes examples/impact/before_routes.json \
        --after-matchers examples/impact/after_shadow.json \
        --after-routes examples/impact/after_routes.json \
        --format text

Swap ``after_shadow.json`` for ``after_append.json`` to change one registration
order. The changed isolation decisions section then shows the affected sample,
the old and new matcher ranks, and the old and new queue with capabilities.

Supported types
---------------

Image
^^^^^

-  **dwg** - ``image/vnd.dwg``
-  **xcf** - ``image/x-xcf``
-  **jpg** - ``image/jpeg``
-  **jpx** - ``image/jpx``
-  **jxl** - ``image/jxl``
-  **png** - ``image/png``
-  **apng** - ``image/apng``
-  **gif** - ``image/gif``
-  **webp** - ``image/webp``
-  **cr2** - ``image/x-canon-cr2``
-  **tif** - ``image/tiff``
-  **bmp** - ``image/bmp``
-  **jxr** - ``image/vnd.ms-photo``
-  **psd** - ``image/vnd.adobe.photoshop``
-  **ico** - ``image/x-icon``
-  **heic** - ``image/heic``
-  **avif** - ``image/avif``
-  **qoi** - ``image/qoi``
-  **dds** - ``image/dds``

Video
^^^^^

-  **3gp** - ``video/3gpp``
-  **mp4** - ``video/mp4``
-  **m4v** - ``video/x-m4v``
-  **mkv** - ``video/x-matroska``
-  **webm** - ``video/webm``
-  **mov** - ``video/quicktime``
-  **avi** - ``video/x-msvideo``
-  **wmv** - ``video/x-ms-wmv``
-  **mpg** - ``video/mpeg``
-  **flv** - ``video/x-flv``

Audio
^^^^^

-  **aac** - ``audio/aac``
-  **mid** - ``audio/midi``
-  **mp3** - ``audio/mpeg``
-  **m4a** - ``audio/mp4``
-  **ogg** - ``audio/ogg``
-  **flac** - ``audio/x-flac``
-  **wav** - ``audio/x-wav``
-  **amr** - ``audio/amr``
-  **aiff** - ``audio/x-aiff``

Archive
^^^^^^^

-  **br** - ``application/x-brotli``
-  **rpm** - ``application/x-rpm``
-  **dcm** - ``application/dicom``
-  **epub** - ``application/epub+zip``
-  **zip** - ``application/zip``
-  **tar** - ``application/x-tar``
-  **rar** - ``application/x-rar-compressed``
-  **gz** - ``application/gzip``
-  **bz2** - ``application/x-bzip2``
-  **7z** - ``application/x-7z-compressed``
-  **xz** - ``application/x-xz``
-  **pdf** - ``application/pdf``
-  **exe** - ``application/x-msdownload``
-  **swf** - ``application/x-shockwave-flash``
-  **rtf** - ``application/rtf``
-  **eot** - ``application/octet-stream``
-  **ps** - ``application/postscript``
-  **sqlite** - ``application/x-sqlite3``
-  **nes** - ``application/x-nintendo-nes-rom``
-  **crx** - ``application/x-google-chrome-extension``
-  **cab** - ``application/vnd.ms-cab-compressed``
-  **deb** - ``application/x-deb``
-  **ar** - ``application/x-unix-archive``
-  **Z** - ``application/x-compress``
-  **lzo** - ``application/x-lzop``
-  **lz** - ``application/x-lzip``
-  **lz4** - ``application/x-lz4``
-  **zstd** - ``application/zstd``

Document
^^^^^^^^

-  **doc** - ``application/msword``
-  **docx** - ``application/vnd.openxmlformats-officedocument.wordprocessingml.document``
-  **odt** - ``application/vnd.oasis.opendocument.text``
-  **xls** - ``application/vnd.ms-excel``
-  **xlsx** - ``application/vnd.openxmlformats-officedocument.spreadsheetml.sheet``
-  **ods** - ``application/vnd.oasis.opendocument.spreadsheet``
-  **ppt** - ``application/vnd.ms-powerpoint``
-  **pptx** - ``application/vnd.openxmlformats-officedocument.presentationml.presentation``
-  **odp** - ``application/vnd.oasis.opendocument.presentation``

Font
^^^^

-  **woff** - ``application/font-woff``
-  **woff2** - ``application/font-woff``
-  **ttf** - ``application/font-sfnt``
-  **otf** - ``application/font-sfnt``

Application
^^^^^^^^^^^

-  **wasm** - ``application/wasm``

.. _Python: http://python.org
.. _magic numbers: https://en.wikipedia.org/wiki/Magic_number_(programming)#Magic_numbers_in_files
.. _filetype: https://github.com/h2non/filetype
.. _wide range: #supported-types
.. _Pluggable: #add-additional-file-type-matchers
.. _Fast: #benchmarks
.. _pass a list of bytes: #file-header
.. _annotated API reference: https://h2non.github.io/filetype.py/

.. |PyPI| image:: https://img.shields.io/pypi/v/filetype.svg?maxAge=2592000?style=flat-square
   :target: https://pypi.python.org/pypi/filetype
.. |Pyversions| image:: https://img.shields.io/pypi/pyversions/filetype.svg?style=flat-square
    :target: https://pypi.python.org/pypi/filetype
.. |API| image:: https://img.shields.io/badge/api-docs-green.svg
   :target: https://h2non.github.io/filetype.py
