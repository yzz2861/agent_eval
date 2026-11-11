from collections.abc import Iterable
from itertools import chain
import threading

from django.contrib.auth.models import Permission
from django.db import DEFAULT_DB_ALIAS, connections, transaction
from django.db.models import Model
from django.db.models.query import QuerySet
from django.utils.encoding import force_str

from guardian.conf import settings as guardian_settings
from guardian.ctypes import get_content_type
from guardian.utils import get_group_obj_perms_model, get_identity, get_user_obj_perms_model

# Object-permission caches are process-local and are invalidated with a
# monotonic generation.  Outside an atomic block a successful mutation bumps
# the published generation immediately.  Inside an atomic block the generation
# stays unpublished until the transaction commits; a transaction-local token
# keeps the mutation visible to this process in the meantime.  Tokens are tied
# to ``on_commit`` callbacks so a rolled-back savepoint restores the previous
# effective generation instead of leaving an unpersisted generation behind.
_permission_generation_lock = threading.RLock()
_permission_generation = 0
_permission_token_sequence = 0
_transaction_generations: dict[tuple[str, int], "_TransactionGeneration"] = {}


class _TransactionGeneration:
    __slots__ = ("last_savepoints", "root", "tokens")

    def __init__(self, root: object, savepoints: tuple) -> None:
        self.root = root
        self.last_savepoints = savepoints
        self.tokens: list[tuple[int, object]] = []

    @property
    def pending(self) -> int | None:
        return self.tokens[-1][0] if self.tokens else None


def _db_connection():
    return connections[DEFAULT_DB_ALIAS]


def _atomic_root(conn) -> object | None:
    if not conn.in_atomic_block:
        return None
    # ``atomic_blocks`` exists on supported Django versions; keep the
    # connection itself as a fallback for older releases.
    blocks = getattr(conn, "atomic_blocks", None)
    if blocks:
        return blocks[0]
    return conn


def _transaction_key(conn) -> tuple[str, int]:
    return conn.alias, id(conn)


def _sync_transaction_generation(conn) -> _TransactionGeneration | None:
    """Return transaction-local generation state, discarding stale state."""
    root = _atomic_root(conn)
    key = _transaction_key(conn)
    if root is None:
        _transaction_generations.pop(key, None)
        return None

    savepoints = tuple(conn.savepoint_ids)
    state = _transaction_generations.get(key)
    if state is None or state.root is not root:
        state = _TransactionGeneration(root, savepoints)
        _transaction_generations[key] = state
    elif state.last_savepoints != savepoints:
        # A savepoint was released or rolled back since the last check. Django
        # removes ``on_commit`` callbacks registered under a rolled-back
        # savepoint, which is exactly the signal we need to drop those tokens.
        active_callbacks = {id(func) for _, func, _ in conn.run_on_commit}
        state.tokens = [(token, callback) for token, callback in state.tokens if id(callback) in active_callbacks]
        state.last_savepoints = savepoints
    return state


def get_permission_generation() -> tuple[int, int | None]:
    """Return the process-local generation used to validate permission caches.

    The second element is a transaction-local mutation token: it is non-None
    only while the current atomic block contains mutations that have not been
    committed yet. Querying this function never hits the database.
    """
    with _permission_generation_lock:
        state = _sync_transaction_generation(_db_connection())
        return _permission_generation, state.pending if state is not None else None


def invalidate_permission_cache() -> None:
    """Invalidate every process-local object-permission cache.

    Calls made inside an atomic block become visible immediately through a
    transaction-local token, but the published generation is advanced only if
    (and when) the enclosing transaction commits.
    """
    global _permission_generation, _permission_token_sequence

    conn = _db_connection()
    if _atomic_root(conn) is None:
        with _permission_generation_lock:
            _permission_generation += 1
        return

    with _permission_generation_lock:
        state = _sync_transaction_generation(conn)
        if state is None:
            _permission_generation += 1
            return
        _permission_token_sequence += 1
        token = _permission_token_sequence
        key = _transaction_key(conn)

        def publish():
            global _permission_generation
            with _permission_generation_lock:
                _permission_generation += 1
                if _transaction_generations.get(key) is state:
                    _transaction_generations.pop(key, None)

        state.tokens.append((token, publish))
        state.last_savepoints = tuple(conn.savepoint_ids)
        transaction.on_commit(publish, using=conn.alias)


def _commit_cache_if_generation_current(generation: tuple[int, int | None], commit) -> bool:
    with _permission_generation_lock:
        if get_permission_generation() != generation:
            return False
        commit()
        return True


def _get_pks_model_and_ctype(objects):
    """
    Returns the primary keys, model and content type of an iterable of Django model objects.
    Assumes that all objects are of the same content type.
    """

    model = None
    ctype = None
    pks = None

    if isinstance(objects, QuerySet):
        model = objects.model
        pks = [force_str(pk) for pk in objects.values_list("pk", flat=True)]
        ctype = get_content_type(model)
    else:
        pks = []
        for idx, obj in enumerate(objects):
            if not idx:
                model = type(obj)
                ctype = get_content_type(model)
            pks.append(force_str(obj.pk))

    return pks, model, ctype


class ObjectPermissionChecker:
    """Generic object permissions checker class being the heart of `django-guardian`.

    Note:
       Once checked for a single object, permissions are stored, and we don't hit
       the database again if another check is called for this object. This is great
       for templates, views or other request-based checks (assuming we don't
       have hundreds of permissions on a single object as we fetch all
       permissions for checked object).

       Cache entries are scoped to a process-local generation. Mutations made
       through guardian's public APIs invalidate them, so checking again with the
       same checker observes the change. Changes made outside this process still
       require a new checker or ``evict_obj_perms_cache``.
    """

    def __init__(self, user_or_group: Model | None = None) -> None:
        """Constructor for ObjectPermissionChecker.

        Parameters:
            user_or_group (User, AnonymousUser, Group): The user or group to check permissions for.
        """
        self.user, self.group = get_identity(user_or_group)  # type: ignore[arg-type] # None is not allowed
        self._obj_perms_cache: dict = {}
        self._obj_perms_cache_generation: tuple[int, int | None] | None = None

    def _sync_local_cache(self, generation: tuple[int, int | None] | None = None) -> tuple[int, int | None]:
        if generation is None:
            generation = get_permission_generation()
        if self._obj_perms_cache_generation != generation:
            self._obj_perms_cache = {}
            self._obj_perms_cache_generation = generation
        return generation

    def has_perm(self, perm: str, obj: Model) -> bool:
        """Checks if user/group has the specified permission for the given object.

        Parameters:
            perm (str): permission as string, may or may not contain app_label
                prefix (if not prefixed, we grab app_label from `obj`)
            obj (Model): Django model instance for which permission should be checked

        Returns:
            True if user/group has the permission, False otherwise
        """
        if self.user and not self.user.is_active:
            return False
        elif self.user and self.user.is_superuser:
            return True
        if "." in perm:
            _, perm = perm.split(".", 1)
        return perm in self.get_perms(obj)

    def get_group_filters(self, obj):
        ctype = get_content_type(obj)
        model = get_group_obj_perms_model(obj)
        related_name = model.permission.field.related_query_name()

        if self.user:
            group_filters = {f"{related_name}__group__in": self.user.groups.all()}
        else:
            group_filters = {f"{related_name}__group": self.group}

        if model.objects.is_generic():
            group_filters.update(
                {
                    "%s__content_type" % related_name: ctype,
                    "%s__object_pk" % related_name: obj.pk,
                }
            )
        else:
            group_filters["%s__content_object" % related_name] = obj

        return group_filters

    def get_user_filters(self, obj: Model):
        ctype = get_content_type(obj)
        model = get_user_obj_perms_model(obj)
        related_name = model.permission.field.related_query_name()  # type: ignore[attr-defined]

        user_filters = {f"{related_name}__user": self.user}

        if model.objects.is_generic():  # type: ignore[attr-defined]
            user_filters.update(
                {
                    "%s__content_type" % related_name: ctype,
                    "%s__object_pk" % related_name: obj.pk,
                }
            )
        else:
            user_filters["%s__content_object" % related_name] = obj

        return user_filters

    def get_user_perms(self, obj: Model) -> QuerySet[str]:
        if self.user and not self.user.is_active:
            return Permission.objects.none().values_list("codename", flat=True)

        ctype = get_content_type(obj)

        perms_qs = Permission.objects.filter(content_type=ctype)
        user_filters = self.get_user_filters(obj)
        user_perms_qs = perms_qs.filter(**user_filters)
        user_perms: QuerySet[str] = user_perms_qs.values_list("codename", flat=True)

        return user_perms

    def get_group_perms(self, obj: Model) -> QuerySet[str]:
        if self.user and not self.user.is_active:
            return Permission.objects.none().values_list("codename", flat=True)

        ctype = get_content_type(obj)

        perms_qs = Permission.objects.filter(content_type=ctype)
        group_filters = self.get_group_filters(obj)
        group_perms_qs = perms_qs.filter(**group_filters)
        group_perms: QuerySet[str] = group_perms_qs.values_list("codename", flat=True)

        return group_perms

    def get_perms(self, obj: Model) -> list[str]:
        """Get a list of permissions for the given object.

        Parameters:
            obj (Model): Django model instance for which permission should be checked.

        Returns:
            list of codenames for all permissions for given `obj`.
        """
        if self.user and not self.user.is_active:
            return []

        prefetched = False
        prefetch_generation = None
        # Superusers have every permission, so the prefetch cache (which only
        # holds explicitly assigned permissions) is not used for them.
        if guardian_settings.AUTO_PREFETCH and not (self.user and self.user.is_superuser):
            prefetched = self._prefetch_cache()
            prefetch_generation = self._obj_perms_cache_generation

        ctype = get_content_type(obj)
        key = self.get_local_cache_key(obj)

        # Validate the cache against the generation atomically with the lookup:
        # a concurrent invalidation must never be missed between these two
        # steps. No database query is performed on a cache hit.
        with _permission_generation_lock:
            generation = self._sync_local_cache()
            if key in self._obj_perms_cache:
                return self._obj_perms_cache[key]
            if prefetched and prefetch_generation == generation:
                # If auto-prefetching enabled, do not hit the database
                return []

        generation = get_permission_generation()
        if self.user and self.user.is_superuser:
            perms: list[str] = list(Permission.objects.filter(content_type=ctype).values_list("codename", flat=True))
        elif self.user:
            # Query user and group permissions separately and then combine
            # the results to avoid a slow query
            user_perms = self.get_user_perms(obj)
            group_perms = self.get_group_perms(obj)
            perms = list(set(chain(user_perms, group_perms)))
        else:
            perms = list(set(self.get_group_perms(obj)))

        def commit() -> None:
            self._obj_perms_cache[key] = perms

        if _commit_cache_if_generation_current(generation, commit):
            return perms
        # A mutation raced with this query. Return the freshly read value but
        # leave the cache empty so the next check starts from the new
        # generation.
        self._sync_local_cache(get_permission_generation())
        return perms

    def get_local_cache_key(self, obj: Model) -> tuple:
        """Returns cache key for `_obj_perms_cache` dict."""
        ctype = get_content_type(obj)
        return ctype.id, force_str(obj.pk)

    def prefetch_perms(self, objects: QuerySet):
        """Prefetches the permissions for objects in `objects` and puts them in the cache.

        Parameters:
            objects (list[Model]): Iterable of Django model objects.
        """
        if self.user and not self.user.is_active:
            return []

        generation = get_permission_generation()
        self._sync_local_cache(generation)
        pks, model, ctype = _get_pks_model_and_ctype(objects)
        batch_cache: dict = {}

        if self.user and self.user.is_superuser:
            perms: Iterable = list(Permission.objects.filter(content_type=ctype).values_list("codename", flat=True))

            for pk in pks:
                key = (ctype.id, force_str(pk))
                batch_cache[key] = perms

            def commit_superuser_cache() -> None:
                self._obj_perms_cache.update(batch_cache)
                self._obj_perms_cache_generation = generation

            if not _commit_cache_if_generation_current(generation, commit_superuser_cache):
                self._sync_local_cache(get_permission_generation())
            return True

        if self.user:
            group_filters = {"group__in": self.user.groups.all()}
        else:
            group_filters = {"group": self.group}

        group_model = get_group_obj_perms_model(model)
        if group_model.objects.is_generic():  # type: ignore[attr-defined]
            group_filters.update(
                {
                    "content_type": ctype,
                    "object_pk__in": pks,
                }
            )
        else:
            group_filters.update({"content_object_id__in": pks})

        if self.user:
            model = get_user_obj_perms_model(model)
            user_filters = {
                "user": self.user,
            }

            if model.objects.is_generic():
                user_filters.update({"content_type": ctype, "object_pk__in": pks})
            else:
                user_filters.update({"content_object_id__in": pks})

            # Query user and group permissions separately and then combine
            # the results to avoid a slow query
            user_perms_qs = model.objects.filter(**user_filters).select_related("permission")
            group_perms_qs = group_model.objects.filter(**group_filters).select_related("permission")
            perms = chain(user_perms_qs, group_perms_qs)
        else:
            perms = group_model.objects.filter(**group_filters).select_related("permission")

        # initialize entry in '_obj_perms_cache' for all prefetched objects
        # The ctype is assumed above to be homogenous, so leave `objects` unevaluated.
        for key in ((ctype.id, pk) for pk in pks):
            batch_cache.setdefault(key, [])

        for perm in perms:
            if type(perm).objects.is_generic():
                key = (ctype.id, perm.object_pk)
            else:
                key = (ctype.id, force_str(perm.content_object_id))

            batch_cache[key].append(perm.permission.codename)

        def commit_prefetch_cache() -> None:
            self._obj_perms_cache.update(batch_cache)
            self._obj_perms_cache_generation = generation

        if not _commit_cache_if_generation_current(generation, commit_prefetch_cache):
            # A concurrent mutation happened while the batch was being read.
            # Its results belong to the old generation and must not be
            # published under the new one.
            self._sync_local_cache(get_permission_generation())
        return True

    @staticmethod
    def _init_obj_prefetch_cache(obj, *querysets):
        cache = {}
        for qs in querysets:
            model = qs.model
            if model.objects.is_generic():
                perms = qs.select_related("permission__codename").values_list(
                    "content_type_id", "object_pk", "permission__codename"
                )
            else:
                # Direct models have no content_type/object_pk columns of their
                # own: they point at one target model via `content_object`, so
                # that target's content type is constant for the whole queryset
                # and already available off the joined `permission` row - reuse
                # it instead of resolving the target's ContentType separately.
                rows = qs.values_list("permission__content_type_id", "content_object_id", "permission__codename")
                perms = ((ctype_id, force_str(object_pk), codename) for ctype_id, object_pk, codename in rows)
            for p in perms:
                if p[:2] not in cache:
                    cache[p[:2]] = []
                cache[p[:2]] += [
                    p[2],
                ]
        return obj, cache

    def _prefetch_cache(self) -> bool:
        obj = self.user if self.user else self.group

        generation = get_permission_generation()
        self._sync_local_cache(generation)

        # Cache hits should stay O(1): bail out before scanning the app
        # registry for direct permission models and building their querysets.
        if (
            hasattr(obj, "_guardian_perms_cache")
            and getattr(obj, "_guardian_perms_cache_generation", None) == generation
        ):
            self._obj_perms_cache = obj._guardian_perms_cache
            self._obj_perms_cache_generation = generation
            return True

        # The object-level cache may also be stale even when this checker still
        # holds a usable local dictionary; make sure both are discarded together.
        if hasattr(obj, "_guardian_perms_cache"):
            delattr(obj, "_guardian_perms_cache")
        if hasattr(obj, "_guardian_perms_cache_generation"):
            delattr(obj, "_guardian_perms_cache_generation")

        from guardian.models import GroupObjectPermissionBase, UserObjectPermissionBase
        from guardian.utils import get_direct_obj_perms_models, get_group_obj_perms_model, get_user_obj_perms_model

        UserObjectPermission = get_user_obj_perms_model()
        GroupObjectPermission = get_group_obj_perms_model()
        direct_user_models = get_direct_obj_perms_models(UserObjectPermissionBase, UserObjectPermission)
        direct_group_models = get_direct_obj_perms_models(GroupObjectPermissionBase, GroupObjectPermission)

        if self.user:
            querysets = (
                [UserObjectPermission.objects.filter(user=obj)]
                + [model.objects.filter(user=obj) for model in direct_user_models]
                + [GroupObjectPermission.objects.filter(group__user=obj)]
                + [model.objects.filter(group__user=obj) for model in direct_group_models]
            )
        else:
            querysets = [GroupObjectPermission.objects.filter(group=obj)] + [
                model.objects.filter(group=obj) for model in direct_group_models
            ]

        obj, cache = self._init_obj_prefetch_cache(obj, *querysets)

        def commit_object_cache() -> None:
            obj._guardian_perms_cache = cache
            obj._guardian_perms_cache_generation = generation
            self._obj_perms_cache = cache
            self._obj_perms_cache_generation = generation

        if _commit_cache_if_generation_current(generation, commit_object_cache):
            return True

        # The batch raced with a mutation. Discard it rather than publishing
        # stale rows under the new generation; the caller can query directly.
        if hasattr(obj, "_guardian_perms_cache"):
            delattr(obj, "_guardian_perms_cache")
        if hasattr(obj, "_guardian_perms_cache_generation"):
            delattr(obj, "_guardian_perms_cache_generation")
        self._sync_local_cache(get_permission_generation())
        return False
