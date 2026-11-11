from collections.abc import Iterable
from itertools import chain

from django.contrib.auth.models import Permission
from django.db.models import Model
from django.db.models.query import QuerySet
from django.utils import timezone
from django.utils.encoding import force_str

from guardian.conf import settings as guardian_settings
from guardian.ctypes import get_content_type
from guardian.temporal import (
    active_validity_q,
    get_cache_generation,
    is_active_window,
    next_cache_transition,
    non_expired_q,
)
from guardian.utils import get_group_obj_perms_model, get_identity, get_user_obj_perms_model


def _collect_records(records, at):
    """Collect active codenames and the next cache transition from rows."""
    perms = []
    transition = None
    for codename, valid_from, valid_until in records:
        if is_active_window(valid_from, valid_until, at):
            perms.append(codename)
        boundary = next_cache_transition(valid_from, valid_until, at)
        if boundary is not None and (transition is None or boundary < transition):
            transition = boundary
    return perms, transition


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

       Temporary grants are cached only until their next window boundary, and
       assign/revoke operations performed through guardian managers invalidate
       existing checker caches within the same process.
    """

    def __init__(self, user_or_group: Model | None = None) -> None:
        """Constructor for ObjectPermissionChecker.

        Parameters:
            user_or_group (User, AnonymousUser, Group): The user or group to check permissions for.
        """
        self.user, self.group = get_identity(user_or_group)  # type: ignore[arg-type] # None is not allowed
        self._obj_perms_cache: dict = {}
        self._obj_perms_cache_expiry: dict = {}
        self._cache_generation = get_cache_generation()

    def _sync_cache_generation(self) -> bool:
        """Drop cached results after an assign/revoke in this process."""
        generation = get_cache_generation()
        if generation == self._cache_generation:
            return False
        self._obj_perms_cache.clear()
        self._obj_perms_cache_expiry.clear()
        self._cache_generation = generation
        return True

    def _cache_is_usable(self, key, at) -> bool:
        if key not in self._obj_perms_cache:
            return False
        expiry = self._obj_perms_cache_expiry.get(key)
        return expiry is None or at < expiry

    def _cache_perms(self, key, perms, expiry) -> None:
        self._obj_perms_cache[key] = perms
        self._obj_perms_cache_expiry[key] = expiry

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

        now = timezone.now()
        ctype = get_content_type(obj)

        perms_qs = Permission.objects.filter(content_type=ctype)
        user_filters = self.get_user_filters(obj)
        related_name = get_user_obj_perms_model(obj).permission.field.related_query_name()
        user_perms_qs = perms_qs.filter(**user_filters).filter(
            active_validity_q(at=now, prefix=f"{related_name}__")
        )
        user_perms: QuerySet[str] = user_perms_qs.values_list("codename", flat=True)

        return user_perms

    def get_group_perms(self, obj: Model) -> QuerySet[str]:
        if self.user and not self.user.is_active:
            return Permission.objects.none().values_list("codename", flat=True)

        now = timezone.now()
        ctype = get_content_type(obj)

        perms_qs = Permission.objects.filter(content_type=ctype)
        group_filters = self.get_group_filters(obj)
        related_name = get_group_obj_perms_model(obj).permission.field.related_query_name()
        group_perms_qs = perms_qs.filter(**group_filters).filter(
            active_validity_q(at=now, prefix=f"{related_name}__")
        )
        group_perms: QuerySet[str] = group_perms_qs.values_list("codename", flat=True)

        return group_perms

    def _record_queryset(self, obj, now, *, user: bool):
        """Return non-expired permission records for one object.

        Future ``valid_from`` rows are included so the cache can record when a
        negative result must be re-evaluated.  Already-expired rows are
        excluded in SQL and never enter Python or the cache.
        """
        ctype = get_content_type(obj)
        if user:
            model = get_user_obj_perms_model(obj)
            qs = model.objects.filter(user=self.user)
        else:
            model = get_group_obj_perms_model(obj)
            if self.user:
                qs = model.objects.filter(group__in=self.user.groups.all())
            else:
                qs = model.objects.filter(group=self.group)

        if model.objects.is_generic():
            qs = qs.filter(content_type=ctype, object_pk=str(obj.pk))
        else:
            qs = qs.filter(content_object=obj)
        return qs.filter(non_expired_q(at=now)).values_list("permission__codename", "valid_from", "valid_until")

    def _compute_perms_for_obj(self, obj: Model, now) -> tuple[list[str], object]:
        records = list(self._record_queryset(obj, now, user=True)) if self.user else []
        records.extend(self._record_queryset(obj, now, user=False))
        perms, transition = _collect_records(records, now)
        return list(set(perms)), transition

    def get_perms(self, obj: Model) -> list[str]:
        """Get a list of permissions for the given object.

        Parameters:
            obj (Model): Django model instance for which permission should be checked.

        Returns:
            list of codenames for all permissions for given `obj`.
        """
        if self.user and not self.user.is_active:
            return []

        now = timezone.now()
        self._sync_cache_generation()

        # Superusers have every permission, so the prefetch cache (which only
        # holds explicitly assigned permissions) is not used for them.
        if guardian_settings.AUTO_PREFETCH and not (self.user and self.user.is_superuser):
            self._prefetch_cache(now=now)

        ctype = get_content_type(obj)
        key = self.get_local_cache_key(obj)
        if not self._cache_is_usable(key, now):
            if self.user and self.user.is_superuser:
                perms: list[str] = list(
                    Permission.objects.filter(content_type=ctype).values_list("codename", flat=True)
                )
            # If auto-prefetching enabled, do not hit the database
            elif guardian_settings.AUTO_PREFETCH:
                return []
            else:
                perms, transition = self._compute_perms_for_obj(obj, now)
                self._cache_perms(key, perms, transition)
                return perms
            self._cache_perms(key, perms, None)
        return self._obj_perms_cache[key]

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

        now = timezone.now()
        self._sync_cache_generation()
        pks, model, ctype = _get_pks_model_and_ctype(objects)

        if self.user and self.user.is_superuser:
            perms: Iterable = list(Permission.objects.filter(content_type=ctype).values_list("codename", flat=True))

            for pk in pks:
                key = (ctype.id, force_str(pk))
                self._cache_perms(key, perms, None)

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
            user_perms_qs = model.objects.filter(**user_filters).filter(non_expired_q(now)).select_related("permission")
            group_perms_qs = group_model.objects.filter(**group_filters).filter(non_expired_q(now)).select_related(
                "permission"
            )
            perms = chain(user_perms_qs, group_perms_qs)
        else:
            perms = group_model.objects.filter(**group_filters).filter(non_expired_q(now)).select_related("permission")

        # initialize entry in '_obj_perms_cache' for all prefetched objects
        # The ctype is assumed above to be homogenous, so leave `objects` unevaluated.
        for key in ((ctype.id, pk) for pk in pks):
            if key not in self._obj_perms_cache:
                self._cache_perms(key, [], None)

        for perm in perms:
            if type(perm).objects.is_generic():
                key = (ctype.id, perm.object_pk)
            else:
                key = (ctype.id, force_str(perm.content_object_id))

            if is_active_window(perm.valid_from, perm.valid_until, now):
                self._obj_perms_cache[key].append(perm.permission.codename)
            boundary = next_cache_transition(perm.valid_from, perm.valid_until, now)
            if boundary is not None:
                current = self._obj_perms_cache_expiry.get(key)
                if current is None or boundary < current:
                    self._obj_perms_cache_expiry[key] = boundary

        return True

    @staticmethod
    def _init_obj_prefetch_cache(obj, *querysets, at=None):
        at = timezone.now() if at is None else at
        cache = {}
        expiry = {}
        for qs in querysets:
            model = qs.model
            if model.objects.is_generic():
                perms = qs.select_related("permission__codename").values_list(
                    "content_type_id", "object_pk", "permission__codename", "valid_from", "valid_until"
                )
            else:
                # Direct models have no content_type/object_pk columns of their
                # own: they point at one target model via `content_object`, so
                # that target's content type is constant for the whole queryset
                # and already available off the joined `permission` row - reuse
                # it instead of resolving the target's ContentType separately.
                rows = qs.values_list(
                    "permission__content_type_id",
                    "content_object_id",
                    "permission__codename",
                    "valid_from",
                    "valid_until",
                )
                perms = (
                    (ctype_id, force_str(object_pk), codename, valid_from, valid_until)
                    for ctype_id, object_pk, codename, valid_from, valid_until in rows
                )
            for ctype_id, object_pk, codename, valid_from, valid_until in perms:
                key = (ctype_id, object_pk)
                if key not in cache:
                    cache[key] = []
                    expiry[key] = None
                if is_active_window(valid_from, valid_until, at):
                    cache[key].append(codename)
                boundary = next_cache_transition(valid_from, valid_until, at)
                if boundary is not None and (expiry[key] is None or boundary < expiry[key]):
                    expiry[key] = boundary
        obj._guardian_perms_cache = cache
        obj._guardian_perms_cache_expiry = expiry
        obj._guardian_perms_cache_generation = get_cache_generation()
        return obj, cache

    def _prefetch_cache(self, now=None):
        now = timezone.now() if now is None else now
        self._sync_cache_generation()
        obj = self.user if self.user else self.group

        # Cache hits should stay O(1): bail out before scanning the app
        # registry for direct permission models and building their querysets.
        if hasattr(obj, "_guardian_perms_cache"):
            generation = getattr(obj, "_guardian_perms_cache_generation", None)
            expiry = getattr(obj, "_guardian_perms_cache_expiry", {})
            still_current = generation == get_cache_generation() and all(
                boundary is None or now < boundary for boundary in expiry.values()
            )
            if still_current:
                self._obj_perms_cache = dict(obj._guardian_perms_cache)
                self._obj_perms_cache_expiry = dict(expiry)
                return
            delattr(obj, "_guardian_perms_cache")
            if hasattr(obj, "_guardian_perms_cache_expiry"):
                delattr(obj, "_guardian_perms_cache_expiry")
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

        querysets = [qs.filter(non_expired_q(at=now)) for qs in querysets]
        obj, cache = self._init_obj_prefetch_cache(obj, *querysets, at=now)
        self._obj_perms_cache = cache
        self._obj_perms_cache_expiry = obj._guardian_perms_cache_expiry
