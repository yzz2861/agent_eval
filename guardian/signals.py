"""Signal wiring for process-local permission-cache invalidation."""

from django.apps import apps
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.db.models.signals import m2m_changed, post_delete, post_save

from guardian.core import invalidate_permission_cache
from guardian.models import GroupObjectPermissionBase, UserObjectPermissionBase


def _invalidate_permission_cache(**kwargs) -> None:
    invalidate_permission_cache()


def _invalidate_content_type_cache(**kwargs) -> None:
    from guardian.shortcuts import clear_ct_cache

    clear_ct_cache()
    invalidate_permission_cache()


def _invalidate_group_membership(sender, action, **kwargs) -> None:
    if action in {"post_add", "post_remove", "post_clear"}:
        invalidate_permission_cache()


def _connect_many_to_many(owner, field_name: str, dispatch_uid: str) -> None:
    field = getattr(owner, field_name, None)
    if field is None:
        return
    m2m_changed.connect(
        _invalidate_group_membership,
        sender=field.through,
        dispatch_uid=dispatch_uid,
    )


def _connect_object_permission_models() -> None:
    for model in apps.get_models():
        if model._meta.abstract or model._meta.proxy:
            continue
        if not issubclass(model, (UserObjectPermissionBase, GroupObjectPermissionBase)):
            continue
        post_save.connect(
            _invalidate_permission_cache,
            sender=model,
            dispatch_uid=f"guardian.invalidate-obj-perm-save-{model._meta.label_lower}",
        )
        post_delete.connect(
            _invalidate_permission_cache,
            sender=model,
            dispatch_uid=f"guardian.invalidate-obj-perm-delete-{model._meta.label_lower}",
        )


def connect_permission_cache_signals() -> None:
    """Connect invalidation receivers once, during app startup."""
    User = get_user_model()

    post_delete.connect(
        _invalidate_permission_cache,
        sender=User,
        dispatch_uid="guardian.invalidate-user-delete",
    )
    post_delete.connect(
        _invalidate_permission_cache,
        sender=Group,
        dispatch_uid="guardian.invalidate-group-delete",
    )

    for sender in (ContentType, Permission):
        post_save.connect(
            _invalidate_content_type_cache,
            sender=sender,
            dispatch_uid=f"guardian.invalidate-ctype-save-{sender._meta.label_lower}",
        )
        post_delete.connect(
            _invalidate_content_type_cache,
            sender=sender,
            dispatch_uid=f"guardian.invalidate-ctype-delete-{sender._meta.label_lower}",
        )

    _connect_many_to_many(User, "groups", "guardian.invalidate-user-groups")
    _connect_many_to_many(User, "user_permissions", "guardian.invalidate-user-permissions")
    _connect_many_to_many(Group, "permissions", "guardian.invalidate-group-permissions")

    _connect_object_permission_models()
