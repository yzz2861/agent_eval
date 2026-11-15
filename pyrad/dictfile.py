# dictfile.py
#
# Copyright 2009 Kristoffer Gronlund <kristoffer.gronlund@purplescout.se>

"""Dictionary file reader.

Implements an iterable over the lines of a dictionary file that handles
the $INCLUDE directives behind the scenes.
"""

import os
from types import MappingProxyType


# Maximum number of nested $INCLUDE directives. A cycle is always an error,
# the depth limit additionally protects against deep include chains built
# from many distinct files.
MAX_INCLUDE_DEPTH = 100


class IncludeSnapshot:
    """Read-only snapshot of the files making up an include graph.

    Records every file visited while reading a dictionary, in the order in
    which it was opened, together with the file it was included from. It is
    built by :class:`DictFile` and exposed through :attr:`DictFile.snapshot`;
    its mappings can't be modified after the parse.

    :ivar files: real paths of the visited files in open order; a dictionary
        read from a file-like object without a real path is listed as ``''``
    :vartype files: tuple[str, ...]
    :ivar included_by: real path of a file mapped to the real path of the
        file whose ``$INCLUDE`` directive opened it (``''`` for the root)
    :vartype included_by: types.MappingProxyType
    :ivar include_lines: ``(included_by, line)`` of the directive that
        opened a file, keyed by its real path
    :vartype include_lines: types.MappingProxyType
    """

    __slots__ = ('_files', '_included_by', '_include_lines')

    def __init__(self, files, included_by, include_lines):
        object.__setattr__(self, '_files', tuple(files))
        object.__setattr__(self, '_included_by',
                           MappingProxyType(dict(included_by)))
        object.__setattr__(self, '_include_lines',
                           MappingProxyType(dict(include_lines)))

    @property
    def files(self):
        return self._files

    @property
    def included_by(self):
        return self._included_by

    @property
    def include_lines(self):
        return self._include_lines

    def __setattr__(self, name, value):
        raise AttributeError('IncludeSnapshot is read-only')

    def __delattr__(self, name):
        raise AttributeError('IncludeSnapshot is read-only')

    def __len__(self):
        return len(self.files)

    def __contains__(self, path):
        return path in self.included_by

    def __eq__(self, other):
        if not isinstance(other, IncludeSnapshot):
            return NotImplemented
        return (self.files == other.files
                and dict(self.included_by) == dict(other.included_by)
                and dict(self.include_lines) == dict(other.include_lines))

    def __repr__(self):
        return 'IncludeSnapshot(%r)' % (self.files,)


class _Node:
    """A single dictionary file."""
    __slots__ = ('name', 'lines', 'current', 'length', 'dir', 'path',
                 'include_line')

    def __init__(self, fd, name, parentdir, path=None, include_line=-1):
        # real path of the file, None for file-like objects
        self.path = path
        self.lines = fd.readlines()
        self.length = len(self.lines)
        self.current = 0
        self.name = os.path.basename(name)
        # line number of the $INCLUDE directive that opened this node,
        # -1 for the root dictionary
        self.include_line = include_line
        path = os.path.dirname(name)
        if os.path.isabs(path):
            self.dir = path
        else:
            self.dir = os.path.join(parentdir, path)

    def Next(self):
        if self.current >= self.length:
            return None
        self.current += 1
        return self.lines[self.current - 1]


class DictFile:
    """Iterate over the lines of a dictionary file and its includes.

    $INCLUDE directives are handled internally: the lines of the included
    file are returned in place of the directive. A relative file name is
    relative to the directory of the current file, or to the current
    working directory for a file-like object. ``$INCLUDE-`` includes a file
    only if it exists. A recursive include, an include chain deeper than
    :data:`MAX_INCLUDE_DEPTH`, or an include that resolves outside of the
    dictionary root raises a :class:`pyrad.dictionary.ParseError`.

    When the dictionary is read from a path, all include targets are
    normalized with :func:`os.path.realpath` and checked against the
    dictionary root (the directory of the root file): an include whose
    normalized path escapes that directory, including ``..`` traversal, is
    rejected. Dictionaries read from file-like objects have no root and are
    not restricted. The files visited by a parse are recorded in
    :attr:`snapshot`.
    """
    __slots__ = ('stack', 'root', '_files', '_included_by',
                 '_include_lines', 'snapshot')

    def __init__(self, fil, root_directory=None):
        """
        :param fil: path of a dictionary file or a file-like object
        :type  fil: str or io.TextIOBase
        :param root_directory: directory the include graph is confined to.
            It defaults to the directory of a dictionary given as a path and
            is ``None`` (no confinement) for a file-like object. An include
            resolving outside of it raises a ParseError.
        :type  root_directory: str or None
        """
        self.stack = []
        self.root = None
        self._files = []
        self._included_by = {}
        self._include_lines = {}
        self.snapshot = IncludeSnapshot((), {}, {})
        if root_directory is not None:
            self.root = os.path.realpath(root_directory)
        elif isinstance(fil, str):
            # confine the include graph to the directory of the root file
            self.root = os.path.realpath(os.path.dirname(fil))
        self.__ReadNode(fil)

    def __TakeSnapshot(self):
        self.snapshot = IncludeSnapshot(self._files, self._included_by,
                                        self._include_lines)

    def __ReadNode(self, fil, optional=False, include_line=-1):
        active = {node.path for node in self.stack if node.path is not None}
        node = self.__OpenInclude(self.__CurDir(), fil, optional,
                                  self.stack[-1].path if self.stack else '',
                                  include_line, active)
        if node is None:
            return
        self.stack.append(node)
        self.__RecordNode(node,
                          self.stack[-2].path if len(self.stack) > 1 else '')
        self.__TakeSnapshot()

    def __OpenInclude(self, parentdir, fil, optional, parent_path,
                      include_line, active_paths):
        """Open an include target and return its node, or None.

        None means an optional include of a missing file. All path
        normalization, root confinement and recursion/depth checks happen
        here, shared by the line iterator and :meth:`BuildSnapshot`.
        """
        if isinstance(fil, str):
            if os.path.isabs(fil):
                fname = fil
            else:
                fname = os.path.join(parentdir, fil)
            if optional and not os.path.exists(fname):
                return None
            path = os.path.realpath(fname)
            if self.root is not None:
                self.__CheckInsideRoot(fil, path, parent_path,
                                       include_line)
            if path in active_paths:
                # imported here, pyrad.dictionary imports this module
                from pyrad.dictionary import ParseError
                raise ParseError(
                    'Recursive include of %s' % fil,
                    file=os.path.basename(parent_path) if parent_path else '',
                    line=include_line,
                    scope=os.path.basename(parent_path) if parent_path
                    else '')
            if len(active_paths) >= MAX_INCLUDE_DEPTH:
                from pyrad.dictionary import ParseError
                raise ParseError(
                    'Include depth limit of %d exceeded at %s'
                    % (MAX_INCLUDE_DEPTH, fil),
                    file=os.path.basename(parent_path) if parent_path else '',
                    line=include_line,
                    scope=os.path.basename(parent_path) if parent_path
                    else '')
            with open(fname, "rt") as fd:
                return _Node(fd, fil, parentdir, path, include_line)
        return _Node(fil, '', parentdir, include_line=include_line)

    def __RecordNode(self, node, parent_path):
        if node.path is not None and node.path not in self._included_by:
            self._files.append(node.path)
            self._included_by[node.path] = parent_path or ''
            self._include_lines[node.path] = (parent_path or '',
                                              node.include_line)

    def __CheckInsideRoot(self, fil, path, parent_path='', include_line=-1):
        """Reject an include whose normalized path escapes the root."""
        # imported here, pyrad.dictionary imports this module
        from pyrad.dictionary import ParseError
        root = self.root
        if path != root and not path.startswith(root + os.sep):
            name = os.path.basename(parent_path) if parent_path                 else self.File()
            line = include_line if include_line > -1 else self.Line()
            raise ParseError(
                'Include %r resolves outside of the dictionary directory'
                % fil,
                file=name, line=line, scope=name)

    def __ScopeName(self):
        """Name of the scope (the current file) for error messages."""
        if self.stack:
            node = self.stack[-1]
            return node.name or node.path or ''
        return ''

    def __CurDir(self):
        if self.stack:
            return self.stack[-1].dir
        else:
            return os.path.realpath(os.curdir)

    def __GetInclude(self, line):
        """Return (file name, optional) of an include directive.

        Returns (None, False) for other lines.
        """
        line = line.split("#", 1)[0].strip()
        tokens = line.split()
        if tokens and tokens[0].upper() in ('$INCLUDE', '$INCLUDE-'):
            return (" ".join(tokens[1:]), tokens[0].endswith('-'))
        else:
            return (None, False)

    def Line(self):
        """Return the line number in the current file."""
        if self.stack:
            return self.stack[-1].current
        else:
            return -1

    def File(self):
        """Return the name of the current file."""
        if self.stack:
            return self.stack[-1].name
        else:
            return ''

    def Scope(self):
        """Return the name of the current scope.

        The scope is the name of the current file, or ``''`` while reading
        a file-like object or after the parse has finished.
        """
        return self.__ScopeName()

    def BuildSnapshot(self):
        """Read the whole include graph and return its snapshot.

        The graph is walked without consuming the line iterator: the
        :class:`DictFile` can still be iterated normally afterwards. This
        lets a caller audit every file of the graph before processing its
        lines.
        """
        # each entry is (node, chain of real paths from the root); the
        # chain gives the recursion and depth checks the same view the
        # line iterator has
        pending = [(self.stack[0],
                    (self.stack[0].path,) if self.stack[0].path else ())]
        while pending:
            (node, chain) = pending.pop(0)
            for (number, line) in enumerate(node.lines, start=1):
                (inc, optional) = self.__GetInclude(line)
                if not inc:
                    continue
                child = self.__OpenInclude(node.dir, inc, optional,
                                           node.path, number,
                                           set(chain))
                if child is None:
                    continue
                self.__RecordNode(child, node.path)
                if child.path is not None:
                    pending.append((child, chain + (child.path,)))
        self.__TakeSnapshot()
        return self.snapshot

    def __iter__(self):
        return self

    def __next__(self):
        while self.stack:
            line = self.stack[-1].Next()
            if line is None:
                self.stack.pop()
                self.__TakeSnapshot()
            else:
                (inc, optional) = self.__GetInclude(line)
                if inc:
                    self.__ReadNode(inc, optional,
                                    include_line=self.Line())
                else:
                    return line
        raise StopIteration
