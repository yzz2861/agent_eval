from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, TypeAlias
import warnings

from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import FieldDoesNotExist
from django.db import IntegrityError, models, transaction
from django.db.models import Model, Q, QuerySet

from guardian.conf import settings as guardian_settings
from guardian.ctypes import get_content_type, get_default_content_type
from guardian.exceptions import (
    BulkAssignmentError,
    DuplicateBulkAssignmentError,
    MixedContentTypeError,
    ObjectNotPersisted,
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


@dataclass(frozen=True)
class BulkAssignResult:
    """Auditable outcome of a bulk object-permission assignment.

    Attributes:
        created: object-permission rows that were actually inserted by this
            call. With ``ignore_existing=True`` the list only contains the
            brand-new rows; rows skipped because the permission already
            existed are reported separately in ``skipped``.
        skipped: target objects for which the permission was already present
            and therefore not written again. Always populated, even when no
            object was skipped (then it is an empty list).
    """

    created: list[Model] = field(default_factory=list)
    skipped: list[Model] = field(default_factory=list)


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

    def _validate_bulk_targets(self, objects: Iterable[Model]) -> tuple[list[Model], ContentType]:
        """Validates every target object before any row is written.

        The batch must be non-empty, every object must already be persisted
        and all objects must share the content type the permission was
        created for.
        """
        if isinstance(objects, QuerySet):
            targets = list(objects)
        else:
            targets = list(objects)
            if targets and not all(isinstance(obj, Model) for obj in targets):
                raise BulkAssignmentError("bulk_assign_perm() expects model instances or a QuerySet of model instances")

        if not targets:
            return [], self._empty_ctype()

        # Use the first instance (not the model class) so custom
        # GUARDIAN_GET_CONTENT_TYPE implementations, e.g. polymorphic setups
        # returning a base content type, are honoured for lists and QuerySets.
        ctype = get_content_type(targets[0])

        for instance in targets:
            if getattr(instance, "pk", None) is None:
                raise ObjectNotPersisted("Object %s needs to be persisted first" % instance)
            instance_ctype = get_content_type(instance)
            if instance_ctype != ctype:
                raise MixedContentTypeError(
                    "All objects passed to bulk_assign_perm() must share a single content type; "
                    "expected %s but got %s for object %r" % (ctype, instance_ctype, instance)
                )

        return targets, ctype

    @staticmethod
    def _empty_ctype() -> ContentType:
        # Empty batches are a stable no-op: nothing to validate against and
        # nothing to write. Returning an unsaved ContentType keeps the type
        # contract without hitting the database.
        return ContentType()

    def _validate_identity(self, user_or_group: Any) -> None:
        """Validates the user/group receiving the permissions.

        The identity must be a persisted model of the type referenced by this
        object-permission model (a user for user perms, a group for group
        perms). Inactive users are rejected so callers cannot silently grant
        permissions to a disabled account.
        """
        field_name = self.user_or_group_field
        try:
            field = self.model._meta.get_field(field_name)
        except FieldDoesNotExist:
            raise BulkAssignmentError(
                "Model %s has no %s field to assign permissions to" % (self.model.__name__, field_name)
            )

        if not isinstance(user_or_group, field.related_model):
            raise BulkAssignmentError(
                "%s.%s expects a %s instance, got %r"
                % (self.model.__name__, "bulk_assign_perm", field.related_model.__name__, user_or_group)
            )

        if getattr(user_or_group, "pk", None) is None:
            raise ObjectNotPersisted(
                "%s %r needs to be persisted first" % (field.related_model.__name__, user_or_group)
            )

        if field_name == "user" and getattr(user_or_group, "is_active", True) is False:
            raise BulkAssignmentError("Cannot assign object permissions to inactive user %r" % user_or_group)

    def _build_obj_perm(self, permission: Permission, user_or_group: Any, ctype: ContentType, instance: Model) -> Model:
        kwargs = {"permission": permission, self.user_or_group_field: user_or_group}
        if self.is_generic():
            kwargs["content_type"] = ctype
            kwargs["object_pk"] = instance.pk
            if _is_using_default_content_type():
                kwargs["content_object"] = instance
        else:
            kwargs["content_object"] = instance
        return self.model(**kwargs)

    def _existing_object_pks(self, permission: Permission, user_or_group: Any, ctype: ContentType, pks: list) -> set:
        """Returns the stringified pks that already carry the permission."""
        filters = Q(**{self.user_or_group_field: user_or_group, "permission": permission})
        if self.is_generic():
            filters &= Q(content_type=ctype, object_pk__in=[str(pk) for pk in pks])
            values = self.filter(filters).values_list("object_pk", flat=True)
        else:
            filters &= Q(content_object_id__in=pks)
            values = self.filter(filters).values_list("content_object_id", flat=True)
        return {str(pk) for pk in values}

    def bulk_assign_perm(
        self,
        perm: _PermType,
        user_or_group: Any,
        queryset: QuerySet | list,
        ignore_existing: bool = False,
        ignore_conflicts: bool | None = None,
    ) -> BulkAssignResult:
        """Bulk assigns ``perm`` for every object in ``queryset`` to one user/group.

        All validation (content type homogeneity, persisted objects, the
        permission codename, identity state and duplicate detection) happens
        inside a single transaction before any row is inserted, so any failure
        rolls the whole batch back: a failed call never leaves a partial set
        of permissions behind.

        Args:
            perm: ``Permission`` instance or codename valid for the objects'
                content type.
            user_or_group: persisted, active user (or persisted group).
            queryset: non-empty homogeneous list/QuerySet of persisted model
                instances.
            ignore_existing: when ``True`` objects that already have the
                permission are reported in ``BulkAssignResult.skipped`` and
                only missing rows are inserted; when ``False`` (default) any
                duplicate raises :class:`DuplicateBulkAssignmentError` and
                nothing is written.
            ignore_conflicts: deprecated alias for ``ignore_existing`` kept
                for backwards compatibility. Must not be combined with an
                explicit ``ignore_existing`` value.

        Returns:
            BulkAssignResult: split of created rows vs. skipped objects, so
            callers can audit what actually happened.
        """
        if ignore_conflicts is not None and ignore_existing:
            raise BulkAssignmentError("Pass either 'ignore_existing' or the deprecated 'ignore_conflicts', not both")
        if ignore_conflicts is not None:
            warnings.warn(
                "'ignore_conflicts' is deprecated, use 'ignore_existing' instead",
                DeprecationWarning,
                stacklevel=2,
            )
            ignore_existing = ignore_conflicts

        # Empty batches are a stable no-op: short-circuit before opening a
        # transaction/savepoint so no query is emitted and nothing can fail.
        if not isinstance(queryset, QuerySet) and not queryset:
            return BulkAssignResult()

        with transaction.atomic():
            return self._bulk_assign_perm(perm, user_or_group, queryset, ignore_existing=ignore_existing)

    def _bulk_assign_perm(self, perm, user_or_group, queryset, ignore_existing: bool) -> BulkAssignResult:
        # 1. Identity: correct model, persisted, active user.
        self._validate_identity(user_or_group)

        # 2. Objects: non-empty, persisted, single content type.
        targets, ctype = self._validate_bulk_targets(queryset)
        if not targets:
            return BulkAssignResult()

        # 3. Permission codename/content type must resolve and match.
        try:
            permission = _ensure_permission(perm, ctype)
        except Permission.DoesNotExist as exc:
            raise BulkAssignmentError(
                "Permission %r does not exist for content type %s" % (perm, ctype), original_error=exc
            ) from exc
        if permission.content_type_id != ctype.id:
            raise MixedContentTypeError(
                "Permission %s belongs to content type %s but objects use %s"
                % (permission, permission.content_type, ctype)
            )

        # 4. In-batch duplicates: the same object appearing twice would try to
        # insert the same unique row twice.
        seen_pks: set = set()
        duplicate_in_batch: list = []
        for instance in targets:
            key = str(instance.pk)
            if key in seen_pks:
                duplicate_in_batch.append(instance)
            seen_pks.add(key)
        if duplicate_in_batch and not ignore_existing:
            raise DuplicateBulkAssignmentError(
                "Duplicate objects in batch (e.g. %r); pass ignore_existing=True to skip duplicates"
                % duplicate_in_batch[0]
            )

        # 5. Already-persisted permissions for the same unique triples.
        existing_pks = self._existing_object_pks(permission, user_or_group, ctype, list(seen_pks))
        if existing_pks and not ignore_existing:
            raise DuplicateBulkAssignmentError(
                "Permission %s is already assigned to %d of the target objects; pass "
                "ignore_existing=True to skip them" % (permission.codename, len(existing_pks))
            )

        # Deduplicate the input while preserving order so a repeated object in
        # ignore_existing mode produces a single row and a single skip entry.
        unique_targets: list[Model] = []
        unique_seen: set = set()
        for instance in targets:
            key = str(instance.pk)
            if key not in unique_seen:
                unique_seen.add(key)
                unique_targets.append(instance)

        skipped = [instance for instance in unique_targets if str(instance.pk) in existing_pks]
        to_create = [
            self._build_obj_perm(permission, user_or_group, ctype, instance)
            for instance in unique_targets
            if str(instance.pk) not in existing_pks
        ]

        if not to_create:
            return BulkAssignResult(created=[], skipped=skipped)

        try:
            created = self.model.objects.bulk_create(to_create, ignore_conflicts=ignore_existing)
        except IntegrityError as exc:
            # A concurrent transaction may have inserted the same unique row
            # after the pre-check. In fail mode the outer atomic() rolls the
            # whole batch back with the original error attached as cause. In
            # ignore mode the database already swallowed the conflict, so this
            # only triggers on backends without conflict support.
            if not ignore_existing:
                raise DuplicateBulkAssignmentError(
                    "Concurrent duplicate permission assignment detected; rolled back", original_error=exc
                ) from exc
            raise

        if ignore_existing:
            # ignore_conflicts does not guarantee pks are populated and a
            # concurrent transaction may have won some races, so derive the
            # final created/skipped split from the actual database state.
            final_rows = list(
                self.filter(**{self.user_or_group_field: user_or_group, "permission": permission}).filter(
                    self._object_pk_filter(ctype, list(unique_seen))
                )
            )
            row_by_object_pk = {self._row_object_pk(row): row for row in final_rows}
            # Rows that existed before our call were skipped; anything else
            # present now was created by us or by a racing transaction and is
            # reported as created so the audit matches the database exactly.
            skipped = [instance for instance in unique_targets if str(instance.pk) in existing_pks]
            created = [
                row_by_object_pk[str(instance.pk)]
                for instance in unique_targets
                if str(instance.pk) in row_by_object_pk and str(instance.pk) not in existing_pks
            ]

        return BulkAssignResult(created=created, skipped=skipped)

    def _row_object_pk(self, row: Model) -> str:
        if self.is_generic():
            return str(row.object_pk)
        return str(row.content_object_id)

    def _object_pk_filter(self, ctype: ContentType, pks: list) -> Q:
        if self.is_generic():
            return Q(content_type=ctype, object_pk__in=[str(pk) for pk in pks])
        return Q(content_object_id__in=pks)

    def assign_perm_to_many(
        self, perm: _PermType, users_or_groups: Any, obj: Model, ignore_conflicts: bool = False
    ) -> list:
        """
        Bulk assigns given `perm` for the object `obj` to a set of users or a set of groups.
        """
        ctype = get_content_type(obj)
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

        filters = Q(**{self.user_or_group_field: user_or_group})
        filters &= _get_perm_filter(perm, model=obj)
        if self.is_generic():
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
            if isinstance(queryset, list):
                filters &= Q(object_pk__in=[str(obj.pk) for obj in queryset])
            else:
                filters &= Q(object_pk__in=[str(pk) for pk in queryset.values_list("pk", flat=True)])
        else:
            filters &= Q(content_object__in=queryset)

        return self.filter(filters).delete()

    def remove_perm_from_many(self, perm: _PermType, users_or_groups: Any, obj: Model) -> tuple[int, dict]:
        """
        Bulk removes given `perm` for the object `obj` from a set of users or a set of groups.
        """
        ctype = get_content_type(obj)
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
