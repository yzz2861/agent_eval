"""Instance-isolated, authority-scoped custom tag handling on top of SafeLoader.

Two YAML configurations may be read by the same process with different tag
policies (for example an internal team registry vs. third-party uploads).
The historical workaround was to temporarily mutate ``SafeLoader``'s
class-level constructor table with :meth:`add_constructor`; such mutations are
global, so every loader and every thread shares them until they are manually
undone.

This module keeps the same safe-loading code path (``SafeLoader``) but gives
each loader a private copy of the constructor table. Custom tags are granted
to a :class:`TagAuthority`, and a loader only accepts tags currently granted
to the single authority it is bound to. Registration, rejection and revocation
are recorded in an audit log, including the acceptance scope ("受理范围") of
tags that have later been revoked.

Authorization semantics
-----------------------
* A tag is interpreted **only** against the authority bound to the loader
  instance that reads the document. Authorities never share grants, so a tag
  granted to the internal team is still rejected for third-party uploads.
* Inheritance: every loader keeps the full standard
  ``tag:yaml.org,2002:*`` safe-tag set from :class:`SafeLoader`. That
  inherited baseline is shared; only custom tags are authority-specific.
* Revocation is decided against the authority's *current* grant set when a
  loader is built. A previously accepted and then revoked tag is rejected;
  historical audit entries never grandfather ("沿用") a new decision.
"""

import logging
import threading

from .constructor import ConstructorError
from .loader import SafeLoader

__all__ = ['TagAuthorizationError', 'TagAuthority', 'AuthorizedSafeLoader',
           'authorized_safe_load', 'authorized_safe_load_all']

logger = logging.getLogger(__name__)


class TagAuthorizationError(ConstructorError):
    """Raised when a document uses a tag outside the authority's scope."""


class TagAuthority:
    """A named registry of custom tags that one loading policy may accept.

    Each authority owns its own grant set and audit trail. Granting a tag to
    one authority never registers it on :class:`SafeLoader` itself or on any
    other authority.
    """

    def __init__(self, name):
        self.name = name
        self._grants = {}
        self._events = []
        self._lock = threading.RLock()

    def grant(self, tag, constructor):
        """Register ``tag`` as accepted by this authority.

        Loaders created afterwards use ``constructor`` for the tag. If the tag
        had previously been revoked, the new grant becomes a fresh decision;
        the earlier revocation remains visible in the audit trail.
        """
        if not isinstance(tag, str):
            raise TypeError("tag must be a string, got %r" % type(tag))
        with self._lock:
            self._grants[tag] = constructor
            event = self._record('grant', tag, constructor)
            logger.info("authority %r granted tag %r (event #%d)",
                        self.name, tag, event['seq'])
            return event

    def revoke(self, tag):
        """Remove ``tag`` from this authority's current acceptance scope.

        Loaders created afterwards reject the tag. The event, including the
        scope that was in effect while the tag was accepted, is retained so
        the prior acceptance can be reviewed later.
        """
        with self._lock:
            constructor = self._grants.pop(tag, None)
            event = self._record('revoke', tag, constructor)
            logger.info("authority %r revoked tag %r (event #%d)",
                        self.name, tag, event['seq'])
            return event

    def is_granted(self, tag):
        with self._lock:
            return tag in self._grants

    def get_constructor(self, tag):
        with self._lock:
            return self._grants.get(tag)

    def accepted_tags(self):
        """Return a copy of the currently accepted (tag, constructor) pairs."""
        with self._lock:
            return dict(self._grants)

    def review(self, tag=None):
        """Return audit records for reviewing acceptance scope.

        With no argument every recorded event is returned. Pass a tag to get
        the full lifecycle of one tag, including ``grant``/``revoke`` events
        and per-loader ``accept``/``reject`` decisions. Each record carries
        ``scope``, a snapshot of the tags that authority accepted at the time.
        """
        with self._lock:
            if tag is None:
                return [dict(event) for event in self._events]
            return [dict(event) for event in self._events
                    if event['tag'] == tag]

    def _record(self, action, tag, constructor):
        event = {
            'seq': len(self._events),
            'authority': self.name,
            'action': action,
            'tag': tag,
            'constructor': getattr(constructor, '__name__',
                                   None if constructor is None
                                   else repr(constructor)),
            'scope': frozenset(self._grants),
        }
        self._events.append(event)
        return event


class AuthorizedSafeLoader(SafeLoader):
    """A :class:`SafeLoader` bound to exactly one :class:`TagAuthority`.

    The constructor and resolver tables are copied onto each instance, so
    :meth:`register` and authority grants never mutate class-level state.
    Standard safe YAML tags are inherited unchanged from ``SafeLoader``; only
    custom tags are gated by the bound authority.
    """

    def __init__(self, stream, authority):
        super().__init__(stream)
        self.authority = authority
        # Instance-private tables: this is the isolation point. Nothing here
        # touches SafeConstructor.yaml_constructors or the resolver table.
        self.yaml_constructors = self.yaml_constructors.copy()
        self.yaml_multi_constructors = self.yaml_multi_constructors.copy()
        self.yaml_implicit_resolvers = self.yaml_implicit_resolvers.copy()
        for tag, constructor in authority.accepted_tags().items():
            self.yaml_constructors[tag] = constructor
        logger.debug("loader built for authority %r with accepted tags %r",
                     authority.name, sorted(authority.accepted_tags()))

    def register(self, tag, constructor=None):
        """Instance-isolated registration entry point.

        Add a constructor for ``tag`` on this loader only. The tag must be
        granted to the bound authority right now: this cannot widen the
        authority's scope or re-register a revoked tag. The change dies with
        this instance and is never written back to any class-level table.
        """
        granted = self.authority.get_constructor(tag)
        if granted is None:
            raise TagAuthorizationError(
                None, None,
                "authority %r has not accepted tag %r; instance registration "
                "cannot widen its scope" % (self.authority.name, tag),
                None)
        self.yaml_constructors[tag] = granted if constructor is None \
            else constructor
        logger.info("instance for authority %r registered tag %r locally",
                    self.authority.name, tag)

    def construct_object(self, node, deep=False):
        # Decide against this authority's current scope only. The class-level
        # table still contains the inherited None -> construct_undefined
        # fallback, so unknown custom tags raise ConstructorError as usual.
        if node.tag not in self.yaml_constructors \
                and self.authority.get_constructor(node.tag) is None:
            event = self.authority._record(
                'reject', node.tag, None)
            logger.warning(
                "loader for authority %r rejected tag %r (event #%d)",
                self.authority.name, node.tag, event['seq'])
        elif node.tag in self.yaml_constructors \
                and not node.tag.startswith('tag:yaml.org,2002:'):
            event = self.authority._record(
                'accept', node.tag, self.yaml_constructors[node.tag])
            logger.info(
                "loader for authority %r accepted tag %r (event #%d)",
                self.authority.name, node.tag, event['seq'])
        return super().construct_object(node, deep=deep)


def authorized_safe_load(stream, authority):
    """Parse the first document with a loader bound to ``authority``."""
    loader = AuthorizedSafeLoader(stream, authority)
    try:
        return loader.get_single_data()
    finally:
        loader.dispose()


def authorized_safe_load_all(stream, authority):
    """Parse every document with a loader bound to ``authority``."""
    loader = AuthorizedSafeLoader(stream, authority)
    try:
        while loader.check_data():
            yield loader.get_data()
    finally:
        loader.dispose()
