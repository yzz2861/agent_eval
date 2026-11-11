from typing import Any, TypeAlias
import warnings

import django
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import FieldDoesNotExist
from django.db import models, transaction
from django.db.models import Model, Q, QuerySet

from guardian.conf import settings as guardian_settings
from guardian.core import ObjectPermissionChecker
from guardian.ctypes import get_content_type, get_default_content_type
from guardian.exceptions import MixedContentTypeError, ObjectNotPersisted
from guardian.temporal import (
    UNSET,
    active_validity_q,
    bump_cache_generation,
    normalize_datetime,
    validate_validity_window,
)

_PermType: TypeAlias = Permission | str

_DEFAULT_CONTENT_TYPE_PATH = f"{get_default_content_type.__module__}.{get_default_content_type.__name__}"


def _is_using_default_content_type() -> bool:
    """Check if default content type function is being used.

    Returns True if GUARDIAN_GET_CONTENT_TYPE setting points to the default
    get_default_content_type function, False otherwise.

    The check is necessary to avoid a regression where setting content_object
    in get_or_create defaults causes Django's GenericForeignKey.__set__ to
    overwrite the content_type that was explicitly set by a custom
    GUARDIAN_GET_CONTENT_TYPE function.

    Note: This function is not cached to allow dynamic changes during testing
    (e.g., when using mock.patch).
    """
    return guardian_settings.GET_CONTENT_TYPE == _DEFAULT_CONTENT_TYPE_PATH


def _ensure_permission(perm: _PermType, ctype: ContentType) -> Permission:
    if isinstance(perm, str):
        perm = Permission.objects.get(content_type=ctype, codename=perm)

    return perm


def _get_perm_filter(perm: _PermType, model: Model | type[Model] | None = None, ctype: ContentType | None = None) -> Q:
    if isinstance(perm, Permission):
        return Q(permission=perm)

    assert ctype is not None or model is not None
    if ctype is None and model is not None:
        ctype = get_content_type(model)

    return Q(permission__codename=perm, permission__content_type=ctype)


def _ensure_permission_for_ctype(perm: _PermType, ctype: ContentType) -> Permission:
    """Resolve ``perm`` and make sure it belongs to ``ctype``."""
    permission = _ensure_permission(perm, ctype)
    if permission.content_type_id != ctype.id:
        raise MixedContentTypeError(
            f"Permission {permission!r} belongs to content type {permission.content_type!r}, not {ctype!r}"
        )
    return permission


def _group_objects_by_content_type(queryset: QuerySet | list) -> list[tuple[ContentType, list[Model]]]:
    """Return objects grouped by content type, validating list inputs.

    QuerySets have exactly one model.  Lists may mix models, in which case
    callers operate per content type instead of silently using the first
    object's content type.
    """
    if isinstance(queryset, QuerySet):
        objects = list(queryset)
        if not objects:
            return []
        return [(get_content_type(queryset.model), objects)]

    groups: dict[tuple[str, str], tuple[ContentType, list[Model]]] = {}
    for instance in queryset:
        if getattr(instance, "pk", None) is None:
            raise ObjectNotPersisted("Object %s needs to be persisted first" % instance)
        ctype = get_content_type(instance)
        key = (ctype.app_label, ctype.model)
        if key not in groups:
            groups[key] = (ctype, [])
        groups[key][1].append(instance)
    return list(groups.values())


def _dedupe_objects(objects: list[Model]) -> list[Model]:
    seen = set()
    unique = []
    for instance in objects:
        key = str(instance.pk)
        if key in seen:
            continue
        seen.add(key)
        unique.append(instance)
    return unique


def _normalize_window(valid_from, valid_until) -> tuple:
    valid_from = normalize_datetime(valid_from, "valid_from")
    valid_until = normalize_datetime(valid_until, "valid_until")
    validate_validity_window(valid_from, valid_until)
    return valid_from, valid_until


def _window_for_existing(existing, valid_from, valid_until) -> tuple:
    """Apply explicit validity arguments while preserving omitted bounds."""
    new_from = existing.valid_from if valid_from is UNSET else valid_from
    new_until = existing.valid_until if valid_until is UNSET else valid_until
    return _normalize_window(new_from, new_until)


class BaseObjectPermissionManager(models.Manager):
    def active(self, at=None) -> QuerySet:
        """Return grants active at ``at`` (defaults to now)."""
        return self.get_queryset().filter(active_validity_q(at=at))

    @property
    def user_or_group_field(self) -> str:
        try:
            self.model._meta.get_field("user")
            return "user"
        except FieldDoesNotExist:
            return "group"

    def is_generic(self) -> bool:
        try:
            self.model._meta.get_field("object_pk")
            return True
        except FieldDoesNotExist:
            return False

    def assign_perm(
        self,
        perm: _PermType,
        user_or_group: Any,
        obj: Model,
        valid_from=UNSET,
        valid_until=UNSET,
    ) -> Any:
        """Assign a permission, optionally within a time window.

        ``valid_from`` is inclusive and ``valid_until`` is exclusive.  Omitted
        arguments preserve an existing grant's bounds; explicitly passing
        ``None`` clears a bound and makes that side permanent.  Re-assigning a
        temporary grant with a later ``valid_until`` therefore renews it.
        """
        if getattr(obj, "pk", None) is None:
            raise ObjectNotPersisted("Object %s needs to be persisted first" % obj)
        ctype = get_content_type(obj)
        self._validate_ctype(ctype)
        permission = _ensure_permission_for_ctype(perm, ctype)

        window = _normalize_window(
            None if valid_from is UNSET else valid_from,
            None if valid_until is UNSET else valid_until,
        )
        kwargs = {"permission": permission, self.user_or_group_field: user_or_group}
        defaults = {"valid_from": window[0], "valid_until": window[1]}
        if self.is_generic():
            kwargs["content_type"] = ctype
            kwargs["object_pk"] = obj.pk
            if _is_using_default_content_type():
                defaults["content_object"] = obj
        else:
            kwargs["content_object"] = obj
        kwargs["defaults"] = defaults
        obj_perm, created = self.get_or_create(**kwargs)
        if created:
            bump_cache_generation()
        elif valid_from is not UNSET or valid_until is not UNSET:
            window = _window_for_existing(obj_perm, valid_from, valid_until)
            if (obj_perm.valid_from, obj_perm.valid_until) != window:
                obj_perm.valid_from, obj_perm.valid_until = window
                obj_perm.save(update_fields=["valid_from", "valid_until"])
                bump_cache_generation()
        return obj_perm

    def _object_lookup(self, ctype: ContentType) -> dict:
        if self.is_generic():
            return {"content_type": ctype}
        return {}

    def _validate_ctype(self, ctype: ContentType) -> None:
        if self.is_generic():
            return
        target_model = self.model._meta.get_field("content_object").remote_field.model
        if ctype != get_content_type(target_model):
            raise MixedContentTypeError(
                f"{self.model.__name__} can only store permissions for {target_model.__name__}, not {ctype!r}"
            )

    def _bulk_upsert(self, rows: list[Model], update_fields: list[str]) -> list[Model]:
        """Insert rows, updating only the requested fields on conflicts."""
        if not rows:
            return []
        field = self.user_or_group_field
        if self.is_generic():
            unique_fields = [field, "permission", "object_pk"]
        else:
            unique_fields = [field, "permission", "content_object"]

        if django.VERSION >= (4, 2):
            if not update_fields:
                # Conflict means the grant already exists; update the
                # permission FK to its incoming (identical) value as a no-op
                # so RETURNING still gives us primary keys on every backend.
                update_fields = ["permission"]
            return self.model.objects.bulk_create(
                rows,
                update_conflicts=True,
                unique_fields=unique_fields,
                update_fields=update_fields,
            )

        # Older Django versions fall back to per-row create/update.  The
        # public methods still wrap multi-statement batches in a transaction.
        result = []
        with transaction.atomic():
            for row in rows:
                lookup = {"permission": row.permission, field: getattr(row, field)}
                if self.is_generic():
                    lookup.update({"content_type": row.content_type, "object_pk": row.object_pk})
                else:
                    lookup["content_object"] = row.content_object
                existing = self.filter(**lookup).first()
                if existing is None:
                    row.save()
                    result.append(row)
                elif update_fields:
                    for name in update_fields:
                        setattr(existing, name, getattr(row, name))
                    existing.save(update_fields=update_fields)
                    result.append(existing)
                else:
                    result.append(existing)
        return result

    def _bulk_assign_for_ctype(
        self,
        permission: Permission,
        user_or_group: Any,
        ctype: ContentType,
        objects: list[Model],
        valid_from=UNSET,
        valid_until=UNSET,
    ) -> list:
        self._validate_ctype(ctype)
        objects = _dedupe_objects(objects)
        if not objects:
            return []

        explicit_window = valid_from is not UNSET or valid_until is not UNSET
        if not explicit_window:
            checker = ObjectPermissionChecker(user_or_group)
            checker.prefetch_perms(objects)
            objects = [instance for instance in objects if not checker.has_perm(permission.codename, instance)]
            if not objects:
                return []

        lookup = {"permission": permission, self.user_or_group_field: user_or_group, **self._object_lookup(ctype)}
        window = _normalize_window(
            None if valid_from is UNSET else valid_from,
            None if valid_until is UNSET else valid_until,
        )

        rows = []
        for instance in objects:
            row = self.model(**lookup)
            if self.is_generic():
                row.object_pk = instance.pk
            else:
                row.content_object = instance
            row.valid_from, row.valid_until = window
            rows.append(row)

        update_fields = ["valid_from", "valid_until"] if explicit_window else []
        result = self._bulk_upsert(rows, update_fields)
        bump_cache_generation()
        return result

    def bulk_assign_perm(
        self,
        perm: _PermType,
        user_or_group: Any,
        queryset: QuerySet | list,
        ignore_conflicts: bool = False,
        valid_from=UNSET,
        valid_until=UNSET,
    ) -> list:
        """Bulk assign a permission inside one transaction.

        Objects are de-duplicated and grouped by content type.  A failure while
        resolving any permission/object rolls back every row in the batch.
        ``ignore_conflicts`` is retained for API compatibility.  Duplicate
        objects are de-duplicated before writing; an existing grant is left
        unchanged unless an explicit validity window was supplied (in which
        case it is renewed).
        """
        groups = _group_objects_by_content_type(queryset)
        if not groups:
            return []
        assigned = []

        def assign_all():
            result = []
            for ctype, objects in groups:
                permission = _ensure_permission_for_ctype(perm, ctype)
                result.extend(
                    self._bulk_assign_for_ctype(permission, user_or_group, ctype, objects, valid_from, valid_until)
                )
            return result

        if len(groups) > 1:
            with transaction.atomic():
                assigned = assign_all()
        else:
            assigned = assign_all()
        return assigned

    def assign_perm_to_many(
        self,
        perm: _PermType,
        users_or_groups: Any,
        obj: Model,
        ignore_conflicts: bool = False,
        valid_from=UNSET,
        valid_until=UNSET,
    ) -> list:
        """Bulk assign a permission on one object to many users/groups."""
        if getattr(obj, "pk", None) is None:
            raise ObjectNotPersisted("Object %s needs to be persisted first" % obj)
        ctype = get_content_type(obj)
        self._validate_ctype(ctype)
        permission = _ensure_permission_for_ctype(perm, ctype)
        field = self.user_or_group_field

        if isinstance(users_or_groups, QuerySet):
            identities = list(users_or_groups)
        else:
            identities = list(users_or_groups)
        if any(getattr(item, "pk", None) is None for item in identities):
            raise ObjectNotPersisted("Users/groups need to be persisted first")
        identities = list({item.pk: item for item in identities}.values())
        if not identities:
            return []

        explicit_window = valid_from is not UNSET or valid_until is not UNSET
        lookup = {"permission": permission, **self._object_lookup(ctype)}
        if self.is_generic():
            lookup["object_pk"] = obj.pk
        else:
            lookup["content_object"] = obj

        window = _normalize_window(
            None if valid_from is UNSET else valid_from,
            None if valid_until is UNSET else valid_until,
        )
        rows = []
        for identity in identities:
            row = self.model(**lookup)
            setattr(row, field, identity)
            row.valid_from, row.valid_until = window
            rows.append(row)

        update_fields = ["valid_from", "valid_until"] if explicit_window else []
        result = self._bulk_upsert(rows, update_fields)
        bump_cache_generation()
        return result

    def assign(self, perm: _PermType, user_or_group: Any, obj: Model) -> Any:
        """Depreciated function name left in for compatibility"""
        warnings.warn(
            "UserObjectPermissionManager method 'assign' is being renamed to 'assign_perm'. Update your code accordingly as old name will be depreciated in 2.0 version.",
            DeprecationWarning,
        )
        return self.assign_perm(perm, user_or_group, obj)

    @transaction.atomic
    def remove_perm(self, perm: _PermType, user_or_group: Any, obj: Model) -> tuple[int, dict]:
        """
        Removes permission `perm` for an instance `obj` and given `user_or_group`.

        Uses `QuerySet.delete()`, which sends `pre_delete` and `post_delete`
        signals but does not call each object-permission instance's `delete()` method.
        """
        if getattr(obj, "pk", None) is None:
            raise ObjectNotPersisted("Object %s needs to be persisted first" % obj)

        ctype = get_content_type(obj)
        self._validate_ctype(ctype)
        _ensure_permission_for_ctype(perm, ctype)
        filters = Q(**{self.user_or_group_field: user_or_group})
        filters &= _get_perm_filter(perm, model=obj)
        if self.is_generic():
            filters &= Q(object_pk=obj.pk)
        else:
            filters &= Q(content_object__pk=obj.pk)
        result = self.filter(filters).delete()
        if result[0]:
            bump_cache_generation()
        return result

    @transaction.atomic
    def bulk_remove_perm(self, perm: _PermType, user_or_group: Any, queryset: QuerySet | list) -> tuple[int, dict]:
        """
        Removes permission `perm` for a `queryset` and given `user_or_group`.

        Uses `QuerySet.delete()`, which sends `pre_delete` and `post_delete`
        signals but does not call each object-permission instance's `delete()` method.
        """
        groups = _group_objects_by_content_type(queryset)
        if not groups:
            return (0, {})

        total = 0
        details: dict = {}
        for ctype, objects in groups:
            self._validate_ctype(ctype)
            _ensure_permission_for_ctype(perm, ctype)
            filters = Q(**{self.user_or_group_field: user_or_group})
            filters &= _get_perm_filter(perm, ctype=ctype)
            objects = _dedupe_objects(objects)
            if self.is_generic():
                filters &= Q(object_pk__in=[str(obj.pk) for obj in objects])
            else:
                filters &= Q(content_object__in=objects)
            deleted, per_model = self.filter(filters).delete()
            total += deleted
            details.update(per_model)
        if total:
            bump_cache_generation()
        return (total, details)

    @transaction.atomic
    def remove_perm_from_many(self, perm: _PermType, users_or_groups: Any, obj: Model) -> tuple[int, dict]:
        """
        Bulk removes given `perm` for the object `obj` from a set of users or a set of groups.
        """
        ctype = get_content_type(obj)
        self._validate_ctype(ctype)
        _ensure_permission_for_ctype(perm, ctype)
        filters = _get_perm_filter(perm, ctype=ctype)
        if self.is_generic():
            filters &= Q(object_pk=str(obj.pk))
        else:
            filters &= Q(content_object=obj)

        if isinstance(users_or_groups, list):
            to_remove = [item.pk for item in users_or_groups]
        else:
            to_remove = users_or_groups.values_list("pk", flat=True)

        filters &= Q(**{f"{self.user_or_group_field}_id__in": to_remove})

        result = self.filter(filters).delete()
        if result[0]:
            bump_cache_generation()
        return result


class UserObjectPermissionManager(BaseObjectPermissionManager):
    """
    See Also:
        `guardian.managers.UserObjectPermissionManager`
    """


class GroupObjectPermissionManager(BaseObjectPermissionManager):
    """
    See Also:
        `guardian.managers.UserObjectPermissionManager`
    """
