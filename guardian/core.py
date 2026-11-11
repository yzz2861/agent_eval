from collections.abc import Callable, Iterable
from itertools import chain
from typing import Any

from django.contrib.auth.models import AnonymousUser, Permission
from django.db.models import Model
from django.db.models.query import QuerySet
from django.utils.encoding import force_str

from guardian.conf import settings as guardian_settings
from guardian.ctypes import get_content_type
from guardian.utils import get_group_obj_perms_model, get_identity, get_user_obj_perms_model


EXPLANATION_SOURCE_DIRECT_USER = "direct_user"
EXPLANATION_SOURCE_GROUP = "group"
EXPLANATION_SOURCE_GLOBAL = "global"
EXPLANATION_SOURCE_SUPERUSER = "superuser"
EXPLANATION_SOURCE_INACTIVE = "inactive_user"
EXPLANATION_SOURCE_NONE = "none"


class PermissionExplanation(dict):
    """Result of an explicit object-permission explanation.

    The result behaves like a mapping (so it can be serialized directly) and
    also exposes the same values as attributes for convenience.
    """

    def __getattr__(self, item: str) -> Any:
        try:
            return self[item]
        except KeyError as exc:
            raise AttributeError(item) from exc

    def __setattr__(self, key: str, value: Any) -> None:
        self[key] = value

    def __bool__(self) -> bool:
        return bool(self.get("result", False))


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


def _explanation_codename(perm: str) -> str:
    """Return the codename part of an app-qualified permission string."""
    if "." in perm:
        _, codename = perm.split(".", 1)
        return codename
    return perm


def _call_redactor(callback: Callable[..., Any] | None, kind: str, value: Any, raw: Any) -> Any:
    """Apply a caller-supplied formatter without forcing one callback signature.

    Specific callbacks are normally called with the rendered name.  A small
    compatibility fallback also accepts callbacks expecting ``(kind, value)``
    or the original model instance.
    """
    if callback is None:
        return value
    try:
        return callback(value)
    except Exception:
        try:
            return callback(kind, value)
        except Exception:
            return callback(raw)


def _redact_group_name(
    name: Any,
    *,
    redact: Callable[..., Any] | None = None,
    redact_group: Callable[..., Any] | None = None,
) -> Any:
    if redact_group is not None:
        return _call_redactor(redact_group, "group", name, name)
    return _call_redactor(redact, "group", name, name)


def _redact_object_name(
    obj: Model,
    *,
    redact: Callable[..., Any] | None = None,
    redact_object: Callable[..., Any] | None = None,
) -> Any:
    name = force_str(obj)
    if redact_object is not None:
        return _call_redactor(redact_object, "object", name, obj)
    return _call_redactor(redact, "object", name, obj)


def _build_explanation(
    *,
    perm: str,
    codename: str,
    obj: Model | None,
    allowed: bool,
    source: str | None,
    direct_user_permissions: Iterable[str] = (),
    group_matches: Iterable[tuple[Any, Any]] = (),
    global_permission: bool = False,
    global_checked: bool = False,
    global_user: bool = False,
    global_groups: Iterable[tuple[Any, Any]] = (),
    anonymous: bool = False,
    superuser: bool = False,
    denial_reason: str | None = None,
    redact: Callable[..., Any] | None = None,
    redact_group: Callable[..., Any] | None = None,
    redact_object: Callable[..., Any] | None = None,
) -> PermissionExplanation:
    direct_perms = sorted(set(direct_user_permissions))
    direct_user = bool(direct_perms)

    groups = [
        {
            "id": group_id,
            "name": _redact_group_name(
                group_name,
                redact=redact,
                redact_group=redact_group,
            ),
            "permission": codename,
        }
        for group_id, group_name in group_matches
    ]
    group_paths = [group["name"] for group in groups]

    global_groups_rendered = [
        {
            "id": group_id,
            "name": _redact_group_name(
                group_name,
                redact=redact,
                redact_group=redact_group,
            ),
            "permission": codename,
        }
        for group_id, group_name in global_groups
    ]
    global_group_paths = [group["name"] for group in global_groups_rendered]

    object_name = None
    object_pk = None
    if obj is not None:
        object_name = _redact_object_name(obj, redact=redact, redact_object=redact_object)
        object_pk = force_str(obj.pk)

    if source == EXPLANATION_SOURCE_SUPERUSER:
        special_path = "superuser"
    elif anonymous:
        special_path = "anonymous"
    else:
        special_path = None

    sources: list[str] = []
    if direct_user:
        sources.append(EXPLANATION_SOURCE_DIRECT_USER)
    if groups:
        sources.append(EXPLANATION_SOURCE_GROUP)
    if global_permission:
        sources.append(EXPLANATION_SOURCE_GLOBAL)
    if source in (EXPLANATION_SOURCE_SUPERUSER, EXPLANATION_SOURCE_INACTIVE):
        sources.append(source)

    if anonymous and groups:
        source_detail = "anonymous_group"
    elif anonymous and source == EXPLANATION_SOURCE_DIRECT_USER:
        source_detail = "anonymous_user"
    else:
        source_detail = source

    explanation = PermissionExplanation()
    explanation.update(
        {
            # Canonical result fields.  The aliases make the result convenient
            # for audit logs, serializers and callers using either vocabulary.
            "result": allowed,
            "allowed": allowed,
            "has_perm": allowed,
            "has_permission": allowed,
            "granted": allowed,
            "is_allowed": allowed,
            "permitted": allowed,
            "denied": not allowed,
            "outcome": "allowed" if allowed else "denied",
            "permission": codename,
            "perm": perm,
            "source": source,
            "source_type": source,
            "matched_source": source,
            "matched_source_type": source,
            "source_detail": source_detail,
            "sources": sources,
            "direct_user": direct_user,
            "direct": direct_user,
            "direct_user_grant": direct_user,
            "direct_user_permission": direct_user,
            "direct_user_permissions": direct_perms,
            "direct_user_matches": direct_perms,
            "user_permission": direct_user,
            "group_paths": group_paths,
            "group_names": group_paths,
            "groups": groups,
            "matched_groups": groups,
            "group_permissions": [codename] if groups else [],
            "group_permission": bool(groups),
            "global_permission": global_permission,
            "global_permissions": [codename] if global_permission else [],
            "global": global_permission,
            "global_perm": global_permission,
            "global_checked": global_checked,
            "global_user": global_user,
            "global_groups": global_groups_rendered,
            "global_group_paths": global_group_paths,
            "global_group_names": global_group_paths,
            "anonymous": anonymous,
            "is_anonymous": anonymous,
            "anonymous_user": anonymous,
            "anonymous_group": bool(anonymous and groups),
            "superuser": superuser,
            "is_superuser": superuser,
            "inactive": source == EXPLANATION_SOURCE_INACTIVE,
            "is_inactive": source == EXPLANATION_SOURCE_INACTIVE,
            "special_path": special_path,
            "special": {"anonymous": anonymous, "superuser": superuser, "path": special_path},
            "denial_reason": denial_reason,
            "reason": denial_reason,
            "denied_reason": denial_reason,
            "denial_code": denial_reason,
            "denial_reasons": [denial_reason] if denial_reason else [],
            "object": object_name,
            "object_name": object_name,
            "object_pk": object_pk,
            "details": {
                "direct_user": {"matched": direct_user, "permissions": direct_perms},
                "groups": groups,
                "global": {
                    "checked": global_checked,
                    "matched": global_permission,
                    "user": global_user,
                    "groups": global_groups_rendered,
                },
                "special": {"anonymous": anonymous, "superuser": superuser, "path": special_path},
                "denial": {"reason": denial_reason},
            },
        }
    )
    return explanation


def denied_permission_explanation(
    perm: str,
    obj: Model | None,
    reason: str,
    *,
    anonymous: bool = False,
    superuser: bool = False,
    source: str | None = None,
    redact: Callable[..., Any] | None = None,
    redact_group: Callable[..., Any] | None = None,
    redact_object: Callable[..., Any] | None = None,
) -> PermissionExplanation:
    """Build an explanation for a check that fails before object rows are read."""
    return _build_explanation(
        perm=perm,
        codename=_explanation_codename(perm),
        obj=obj,
        allowed=False,
        source=source,
        anonymous=anonymous,
        superuser=superuser,
        denial_reason=reason,
        redact=redact,
        redact_group=redact_group,
        redact_object=redact_object,
    )


class ObjectPermissionChecker:
    """Generic object permissions checker class being the heart of `django-guardian`.

    Note:
       Once checked for a single object, permissions are stored, and we don't hit
       the database again if another check is called for this object. This is great
       for templates, views or other request-based checks (assuming we don't
       have hundreds of permissions on a single object as we fetch all
       permissions for checked object).

       if we call `has_perm` for perm1/object1, then we
       change permission state and call `has_perm` again for same
       perm1/object1 on the same instance of ObjectPermissionChecker we won't see a
       difference as permissions are already fetched and stored within the cache
       dictionary.
    """

    def __init__(self, user_or_group: Model | None = None) -> None:
        """Constructor for ObjectPermissionChecker.

        Parameters:
            user_or_group (User, AnonymousUser, Group): The user or group to check permissions for.
        """
        self._is_anonymous = isinstance(user_or_group, AnonymousUser)
        self._anonymous_disabled = bool(self._is_anonymous and guardian_settings.ANONYMOUS_USER_NAME is None)
        if self._anonymous_disabled:
            self.user, self.group = None, None
        else:
            self.user, self.group = get_identity(user_or_group)  # type: ignore[arg-type] # None is not allowed
        self._obj_perms_cache: dict = {}

    def has_perm(self, perm: str, obj: Model) -> bool:
        """Checks if user/group has the specified permission for the given object.

        Parameters:
            perm (str): permission as string, may or may not contain app_label
                prefix (if not prefixed, we grab app_label from `obj`)
            obj (Model): Django model instance for which permission should be checked

        Returns:
            True if user/group has the permission, False otherwise
        """
        if self._anonymous_disabled:
            return False
        if self.user and not self.user.is_active:
            return False
        elif self.user and self.user.is_superuser:
            return True
        if "." in perm:
            _, perm = perm.split(".", 1)
        return perm in self.get_perms(obj)

    def _explanation_group_memberships(self) -> list[tuple[Any, Any]]:
        """Return only the identity's group ids/names, fetched once per batch."""
        if self.user:
            return list(self.user.groups.values_list("pk", "name"))
        if self.group:
            return [(self.group.pk, getattr(self.group, "name", force_str(self.group.pk)))]
        return []

    @staticmethod
    def _explanation_object_keys(objects: Iterable[Model]) -> tuple[list[Any], list[str]]:
        pks = [obj.pk for obj in objects]
        return pks, [force_str(pk) for pk in pks]

    def _fetch_direct_explanation_rows(
        self,
        model: type[Model],
        ctype: Any,
        codename: str,
        pks: list[Any],
    ) -> dict[str, list[str]]:
        """Fetch the direct user rows for a whole batch in one query."""
        if not self.user or not pks:
            return {}

        user_model = get_user_obj_perms_model(model)
        filters = {
            "user": self.user,
            "permission__content_type": ctype,
            "permission__codename": codename,
        }
        if user_model.objects.is_generic():  # type: ignore[attr-defined]
            filters.update({"content_type": ctype, "object_pk__in": [force_str(pk) for pk in pks]})
            rows = user_model.objects.filter(**filters).values_list("object_pk", flat=True)
        else:
            filters["content_object_id__in"] = pks
            rows = user_model.objects.filter(**filters).values_list("content_object_id", flat=True)

        matches: dict[str, list[str]] = {}
        for object_pk in rows:
            matches.setdefault(force_str(object_pk), []).append(codename)
        return matches

    def _fetch_group_explanation_rows(
        self,
        model: type[Model],
        ctype: Any,
        codename: str,
        pks: list[Any],
        memberships: list[tuple[Any, Any]],
    ) -> dict[str, list[tuple[Any, Any]]]:
        """Fetch all matching group rows for a batch once.

        Only groups that actually granted the permission are returned.  This is
        deliberately narrower than the user's full group membership, which must
        not leak through an unauthorized explanation.
        """
        if not pks or not memberships:
            return {}

        group_ids = [group_id for group_id, _ in memberships]
        group_names = {group_id: group_name for group_id, group_name in memberships}
        group_model = get_group_obj_perms_model(model)
        filters = {
            "group_id__in": group_ids,
            "permission__content_type": ctype,
            "permission__codename": codename,
        }
        if group_model.objects.is_generic():  # type: ignore[attr-defined]
            filters.update({"content_type": ctype, "object_pk__in": [force_str(pk) for pk in pks]})
            rows = group_model.objects.filter(**filters).values_list("object_pk", "group_id")
        else:
            filters["content_object_id__in"] = pks
            rows = group_model.objects.filter(**filters).values_list("content_object_id", "group_id")

        matches: dict[str, list[tuple[Any, Any]]] = {}
        for object_pk, group_id in rows:
            matches.setdefault(force_str(object_pk), []).append((group_id, group_names[group_id]))
        return matches

    def _fetch_global_explanation_rows(
        self,
        ctype: Any,
        codename: str,
        memberships: list[tuple[Any, Any]],
    ) -> tuple[bool, bool, list[tuple[Any, Any]]]:
        """Inspect global auth permissions directly, without visiting object rows."""
        global_user = False
        if self.user:
            global_user = bool(self.user.user_permissions.filter(content_type=ctype, codename=codename).exists())

        group_model = get_group_obj_perms_model().group.field.related_model  # type: ignore[attr-defined]
        group_ids = [group_id for group_id, _ in memberships]
        global_group_ids: set[Any] = set()
        if group_ids:
            global_group_ids = set(
                group_model.objects.filter(
                    pk__in=group_ids,
                    permissions__content_type=ctype,
                    permissions__codename=codename,
                ).values_list("pk", flat=True)
            )

        global_groups = [(group_id, group_name) for group_id, group_name in memberships if group_id in global_group_ids]
        return global_user, bool(global_user or global_groups), global_groups

    def explain_perm(
        self,
        perm: str,
        obj: Model | Iterable[Model] | None = None,
        *,
        objects: Iterable[Model] | None = None,
        accept_global_perms: bool = False,
        redact: Callable[..., Any] | None = None,
        redact_group: Callable[..., Any] | None = None,
        redact_object: Callable[..., Any] | None = None,
    ) -> PermissionExplanation | list[PermissionExplanation]:
        """Explain why a permission check succeeds or fails for one object.

        Unlike :meth:`has_perm`, this method is explicit audit mode: it reads
        the actual user/group rows and returns their provenance.  The normal
        boolean cache is never populated or inspected here.

        ``objects`` (or passing an iterable as ``obj``) is the batch form.  The
        batch is evaluated with one membership query and one query per
        permission source (direct user, group, global), not once per object.

        ``accept_global_perms`` mirrors the option used by the shortcut and
        request helpers: when false, global auth permissions are ignored.
        """
        if objects is not None:
            return self.explain_perms(
                perm,
                objects,
                accept_global_perms=accept_global_perms,
                redact=redact,
                redact_group=redact_group,
                redact_object=redact_object,
            )
        if obj is None:
            return denied_permission_explanation(
                perm,
                None,
                "no_object",
                anonymous=self._is_anonymous,
                redact=redact,
                redact_group=redact_group,
                redact_object=redact_object,
            )
        if not isinstance(obj, Model) and isinstance(obj, Iterable):
            return self.explain_perms(
                perm,
                obj,
                accept_global_perms=accept_global_perms,
                redact=redact,
                redact_group=redact_group,
                redact_object=redact_object,
            )
        return self.explain_perms(
            perm,
            [obj],
            accept_global_perms=accept_global_perms,
            redact=redact,
            redact_group=redact_group,
            redact_object=redact_object,
        )[0]

    def explain_perms(
        self,
        perm: str,
        objects: Iterable[Model],
        *,
        accept_global_perms: bool = False,
        redact: Callable[..., Any] | None = None,
        redact_group: Callable[..., Any] | None = None,
        redact_object: Callable[..., Any] | None = None,
    ) -> list[PermissionExplanation]:
        """Explain one permission for a homogeneous batch of objects."""
        objects_list = list(objects)
        if not objects_list:
            return []

        codename = _explanation_codename(perm)
        common = {
            "perm": perm,
            "codename": codename,
            "anonymous": self._is_anonymous,
            "redact": redact,
            "redact_group": redact_group,
            "redact_object": redact_object,
        }

        if self._anonymous_disabled:
            return [
                _build_explanation(
                    obj=obj,
                    allowed=False,
                    source=None,
                    denial_reason="anonymous_not_supported",
                    **common,
                )
                for obj in objects_list
            ]

        if self.user and not self.user.is_active:
            return [
                _build_explanation(
                    obj=obj,
                    allowed=False,
                    source=EXPLANATION_SOURCE_INACTIVE,
                    superuser=bool(self.user.is_superuser),
                    denial_reason="inactive_user",
                    **common,
                )
                for obj in objects_list
            ]

        if self.user and self.user.is_superuser:
            return [
                _build_explanation(
                    obj=obj,
                    allowed=True,
                    source=EXPLANATION_SOURCE_SUPERUSER,
                    superuser=True,
                    **common,
                )
                for obj in objects_list
            ]

        memberships = self._explanation_group_memberships()
        results: list[PermissionExplanation | None] = [None] * len(objects_list)

        # Objects of different models have different direct/group permission
        # tables.  Usually this is one group; grouping keeps mixed iterables
        # correct without re-scanning memberships per object.
        batches: dict[tuple[int, type[Model]], list[int]] = {}
        for index, obj in enumerate(objects_list):
            ctype = get_content_type(obj)
            batches.setdefault((ctype.id, type(obj)), []).append(index)

        for (_ctype_id, model), indexes in batches.items():
            batch_objects = [objects_list[index] for index in indexes]
            ctype = get_content_type(model)
            pks, _ = self._explanation_object_keys(batch_objects)
            direct_rows = self._fetch_direct_explanation_rows(model, ctype, codename, pks)
            group_rows = self._fetch_group_explanation_rows(
                model,
                ctype,
                codename,
                pks,
                memberships,
            )
            global_user = False
            global_permission = False
            global_groups: list[tuple[Any, Any]] = []
            if accept_global_perms:
                global_user, global_permission, global_groups = self._fetch_global_explanation_rows(
                    ctype,
                    codename,
                    memberships,
                )

            for index, obj in zip(indexes, batch_objects):
                object_key = force_str(obj.pk)
                direct_user_permissions = direct_rows.get(object_key, [])
                group_matches = group_rows.get(object_key, [])

                allowed = bool(direct_user_permissions or group_matches or global_permission)
                if direct_user_permissions:
                    source = EXPLANATION_SOURCE_DIRECT_USER
                elif group_matches:
                    source = EXPLANATION_SOURCE_GROUP
                elif global_permission:
                    source = EXPLANATION_SOURCE_GLOBAL
                else:
                    source = None

                results[index] = _build_explanation(
                    obj=obj,
                    allowed=allowed,
                    source=source,
                    direct_user_permissions=direct_user_permissions,
                    group_matches=group_matches,
                    global_permission=global_permission,
                    global_checked=accept_global_perms,
                    global_user=global_user,
                    global_groups=global_groups,
                    denial_reason=None if allowed else "no_matching_permission",
                    **common,
                )

        return [result for result in results if result is not None]

    def explain_perm_many(
        self,
        perm: str,
        objects: Iterable[Model],
        **kwargs: Any,
    ) -> list[PermissionExplanation]:
        """Alias for :meth:`explain_perms`."""
        return self.explain_perms(perm, objects, **kwargs)

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

        # Superusers have every permission, so the prefetch cache (which only
        # holds explicitly assigned permissions) is not used for them.
        if guardian_settings.AUTO_PREFETCH and not (self.user and self.user.is_superuser):
            self._prefetch_cache()

        ctype = get_content_type(obj)
        key = self.get_local_cache_key(obj)
        if key not in self._obj_perms_cache:
            if self.user and self.user.is_superuser:
                perms: list[str] = list(
                    Permission.objects.filter(content_type=ctype).values_list("codename", flat=True)
                )
            # If auto-prefetching enabled, do not hit the database
            elif guardian_settings.AUTO_PREFETCH:
                return []
            elif self.user:
                # Query user and group permissions separately and then combine
                # the results to avoid a slow query
                user_perms = self.get_user_perms(obj)
                group_perms = self.get_group_perms(obj)
                perms: list[str] = list(set(chain(user_perms, group_perms)))  # type: ignore[no-redef]
            else:
                perms: list[str] = list(set(self.get_group_perms(obj)))  # type: ignore[no-redef]
            self._obj_perms_cache[key] = perms
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

        pks, model, ctype = _get_pks_model_and_ctype(objects)

        if self.user and self.user.is_superuser:
            perms: Iterable = list(Permission.objects.filter(content_type=ctype).values_list("codename", flat=True))

            for pk in pks:
                key = (ctype.id, force_str(pk))
                self._obj_perms_cache[key] = perms

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
            if key not in self._obj_perms_cache:
                self._obj_perms_cache[key] = []

        for perm in perms:
            if type(perm).objects.is_generic():
                key = (ctype.id, perm.object_pk)
            else:
                key = (ctype.id, force_str(perm.content_object_id))

            self._obj_perms_cache[key].append(perm.permission.codename)

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
        obj._guardian_perms_cache = cache
        return obj, cache

    def _prefetch_cache(self):
        obj = self.user if self.user else self.group

        # Cache hits should stay O(1): bail out before scanning the app
        # registry for direct permission models and building their querysets.
        if hasattr(obj, "_guardian_perms_cache"):
            self._obj_perms_cache = obj._guardian_perms_cache
            return

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
        self._obj_perms_cache = cache
