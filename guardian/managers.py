from typing import Any, TypeAlias
import warnings

from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import FieldDoesNotExist
from django.db import models
from django.db.models import Model, Q, QuerySet

from guardian.conf import settings as guardian_settings
from guardian.core import ObjectPermissionChecker
from guardian.ctypes import get_content_type, get_default_content_type, validate_object_identity, validate_tenant
from guardian.exceptions import MixedContentTypeError, ObjectIdentityError, ObjectNotPersisted

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
    elif isinstance(ctype, ContentType) and perm.content_type_id != ctype.pk:
        # A Permission instance whose content type differs from the object's
        # content type would persist a row whose identity (permission,
        # content type, object pk) is inconsistent; bulk writes bypass the
        # model-level save() validation, so reject it here.
        raise ObjectIdentityError(
            f"Permission {perm!r} (content type {perm.content_type_id}) does not belong "
            f"to the object's content type {ctype.pk} ({ctype})"
        )

    return perm


def _get_perm_filter(perm: _PermType, model: Model | type[Model] | None = None, ctype: ContentType | None = None) -> Q:
    if isinstance(perm, Permission):
        return Q(permission=perm)

    assert ctype is not None or model is not None
    if ctype is None and model is not None:
        ctype = get_content_type(model)

    return Q(permission__codename=perm, permission__content_type=ctype)


class BaseObjectPermissionManager(models.Manager):
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

    def assign_perm(self, perm: _PermType, user_or_group: Any, obj: Model) -> Any:
        """Assigns permission with given `perm` for an instance `obj` and `user`."""
        if getattr(obj, "pk", None) is None:
            raise ObjectNotPersisted("Object %s needs to be persisted first" % obj)
        ctype = get_content_type(obj)
        validate_object_identity(obj, ctype)
        validate_tenant(user_or_group, obj, operation="assign")
        permission = _ensure_permission(perm, ctype)

        kwargs = {"permission": permission, self.user_or_group_field: user_or_group}
        if self.is_generic():
            kwargs["content_type"] = ctype
            kwargs["object_pk"] = obj.pk
            if _is_using_default_content_type():
                kwargs["defaults"] = {"content_object": obj}
        else:
            kwargs["content_object"] = obj
        obj_perm, _ = self.get_or_create(**kwargs)
        return obj_perm

    def bulk_assign_perm(
        self, perm: _PermType, user_or_group: Any, queryset: QuerySet | list, ignore_conflicts: bool = False
    ) -> list:
        """
        Bulk assigns permissions with given `perm` for an objects in `queryset` and
        `user_or_group`.
        """
        if isinstance(queryset, list):
            if not queryset:
                return []
            ctype = get_content_type(queryset[0])
            for instance in queryset:
                self._validate_bulk_instance(instance, ctype, user_or_group)
        else:
            ctype = get_content_type(queryset.model)
            validate_object_identity(queryset.model, ctype)
            if guardian_settings.GET_TENANT:
                for instance in queryset:
                    validate_tenant(user_or_group, instance, operation="assign")

        permission = _ensure_permission(perm, ctype)
        checker = ObjectPermissionChecker(user_or_group)
        checker.prefetch_perms(queryset)

        assigned_perms = []
        for instance in queryset:
            if not checker.has_perm(permission.codename, instance):
                kwargs = {"permission": permission, self.user_or_group_field: user_or_group}
                if self.is_generic():
                    kwargs["content_type"] = ctype
                    kwargs["object_pk"] = instance.pk
                else:
                    kwargs["content_object"] = instance
                assigned_perms.append(self.model(**kwargs))
        self.model.objects.bulk_create(assigned_perms, ignore_conflicts=ignore_conflicts)

        return assigned_perms

    def _validate_bulk_instance(self, instance: Model, ctype: ContentType, user_or_group: Any) -> None:
        """Validate one object of a bulk input as a whole identity.

        Every element must be persisted, share the batch's content type and
        model identity, and belong to a tenant the identity may access;
        validation happens before any row is written so a rejected batch
        leaves no partial grants behind.
        """
        if getattr(instance, "pk", None) is None:
            raise ObjectNotPersisted("Object %s needs to be persisted first" % instance)
        instance_ctype = get_content_type(instance)
        if instance_ctype != ctype:
            raise MixedContentTypeError(
                "Bulk permission operations require objects sharing the same content type "
                f"(got {instance_ctype} where {ctype} was expected)"
            )
        validate_object_identity(instance, instance_ctype)
        validate_tenant(user_or_group, instance, operation="assign")

    def assign_perm_to_many(
        self, perm: _PermType, users_or_groups: Any, obj: Model, ignore_conflicts: bool = False
    ) -> list:
        """
        Bulk assigns given `perm` for the object `obj` to a set of users or a set of groups.
        """
        ctype = get_content_type(obj)
        if getattr(obj, "pk", None) is None:
            raise ObjectNotPersisted("Object %s needs to be persisted first" % obj)
        validate_object_identity(obj, ctype)
        permission = _ensure_permission(perm, ctype)

        kwargs = {"permission": permission}
        if self.is_generic():
            kwargs["content_type"] = ctype
            kwargs["object_pk"] = obj.pk
        else:
            kwargs["content_object"] = obj

        to_add = []
        field = self.user_or_group_field
        for user in users_or_groups:
            validate_tenant(user, obj, operation="assign")
            kwargs[field] = user
            to_add.append(self.model(**kwargs))

        return self.model.objects.bulk_create(to_add, ignore_conflicts=ignore_conflicts)

    def assign(self, perm: _PermType, user_or_group: Any, obj: Model) -> Any:
        """Depreciated function name left in for compatibility"""
        warnings.warn(
            "UserObjectPermissionManager method 'assign' is being renamed to 'assign_perm'. Update your code accordingly as old name will be depreciated in 2.0 version.",
            DeprecationWarning,
        )
        return self.assign_perm(perm, user_or_group, obj)

    def remove_perm(self, perm: _PermType, user_or_group: Any, obj: Model) -> tuple[int, dict]:
        """
        Removes permission `perm` for an instance `obj` and given `user_or_group`.

        Uses `QuerySet.delete()`, which sends `pre_delete` and `post_delete`
        signals but does not call each object-permission instance's `delete()` method.
        """
        if getattr(obj, "pk", None) is None:
            raise ObjectNotPersisted("Object %s needs to be persisted first" % obj)

        validate_tenant(user_or_group, obj, operation="remove")
        ctype = get_content_type(obj)
        filters = Q(**{self.user_or_group_field: user_or_group})
        filters &= _get_perm_filter(perm, model=obj)
        if self.is_generic():
            # Bind the row's own content type together with the object pk:
            # object_pk alone (or via the permission join) is not an identity.
            filters &= Q(content_type=ctype)
            filters &= Q(object_pk=obj.pk)
        else:
            filters &= Q(content_object__pk=obj.pk)
        return self.filter(filters).delete()

    def bulk_remove_perm(self, perm: _PermType, user_or_group: Any, queryset: QuerySet | list) -> tuple[int, dict]:
        """
        Removes permission `perm` for a `queryset` and given `user_or_group`.

        Uses `QuerySet.delete()`, which sends `pre_delete` and `post_delete`
        signals but does not call each object-permission instance's `delete()` method.
        """
        filters = Q(**{self.user_or_group_field: user_or_group})

        if isinstance(queryset, list):
            if not queryset:
                return (0, {})
            ctype = get_content_type(queryset[0])
        else:
            ctype = get_content_type(queryset.model)

        filters &= _get_perm_filter(perm, ctype=ctype)
        if self.is_generic():
            # Bind the row's own content type together with the object pks.
            filters &= Q(content_type=ctype)
            if isinstance(queryset, list):
                filters &= Q(object_pk__in=[obj.pk for obj in queryset])
            else:
                filters &= Q(object_pk__in=list(queryset.values_list("pk", flat=True)))
        else:
            filters &= Q(content_object__in=queryset)

        if guardian_settings.GET_TENANT:
            for instance in queryset:
                validate_tenant(user_or_group, instance, operation="remove")

        return self.filter(filters).delete()

    def remove_perm_from_many(self, perm: _PermType, users_or_groups: Any, obj: Model) -> tuple[int, dict]:
        """
        Bulk removes given `perm` for the object `obj` from a set of users or a set of groups.
        """
        ctype = get_content_type(obj)
        filters = _get_perm_filter(perm, ctype=ctype)
        if self.is_generic():
            filters &= Q(content_type=ctype)
            filters &= Q(object_pk=obj.pk)
        else:
            filters &= Q(content_object=obj)

        if isinstance(users_or_groups, list):
            to_remove = [item.pk for item in users_or_groups]
        else:
            to_remove = users_or_groups.values_list("pk", flat=True)

        if guardian_settings.GET_TENANT:
            for identity in users_or_groups:
                validate_tenant(identity, obj, operation="remove")

        filters &= Q(**{f"{self.user_or_group_field}_id__in": to_remove})

        return self.filter(filters).delete()


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
