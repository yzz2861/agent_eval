from collections.abc import Iterable
from typing import Any

from django.db import models
from django.db.models import Model
from django.http import HttpRequest

from guardian.conf import settings
from guardian.core import (
    ObjectPermissionChecker,
    PermissionExplanation,
    denied_permission_explanation,
)
from guardian.ctypes import get_content_type
from guardian.exceptions import WrongAppError
from guardian.utils import get_anonymous_user


def check_object_support(obj: Model) -> bool:
    """Checks if given `obj` is supported

    Returns:
         `True` if given `obj` is supported
    """
    # Backend checks only object permissions (isinstance implies that obj
    # is not None)
    # Backend checks only permissions for Django models
    return isinstance(obj, models.Model)


def check_user_support(user_obj: Any) -> tuple[bool, Any]:
    """Checks if given user is supported.

    Checks if the given user is supported. Anonymous users need explicit
    activation via ANONYMOUS_USER_NAME

    Returns:
        A tuple of checkresult and `user_obj` which should be used for permission checks
    """
    # This is how we support anonymous users - simply try to retrieve User
    # instance and perform checks for that predefined user
    if not user_obj.is_authenticated:
        # If anonymous user permission is disabled, then they are always unauthorized
        if settings.ANONYMOUS_USER_NAME is None:
            return False, user_obj
        # get_anonymous_user() honours GUARDIAN_ANONYMOUS_USER_CACHE_TTL
        user_obj = get_anonymous_user()

    return True, user_obj


def check_support(user_obj: Any, obj: Model) -> Any:
    """Checks if given user and object are supported.

    Combination of `check_object_support` and `check_user_support`
    """
    obj_support = check_object_support(obj)
    user_support, user_obj = check_user_support(user_obj)
    return obj_support and user_support, user_obj


class ObjectPermissionBackend:
    """Django backend for checking object-level permissions."""

    supports_object_permissions = True
    supports_anonymous_user = True
    supports_inactive_user = True

    def authenticate(self, request: HttpRequest, username: str | None = None, password: str | None = None) -> Any:
        return None

    def has_perm(self, user_obj: Any, perm: str, obj: Model | None = None) -> bool:
        """Check if a user has the permission for a given object.

        Returns `True` if given `user_obj` has `perm` for `obj`.
        If no `obj` is given, `False` is returned.
        The main difference between Django's `ModelBackend` is that we can pass
        `obj` instance here and `perm` doesn't have to contain
        `app_label` as it can be retrieved from given `obj`.

        **Inactive user support**

        If `user` is authenticated but inactive at the same time, all checks
        always return `False`.

        Note:
           Remember, that if user is not *active*, all checks would return `False`.

        Parameters:
            user_obj (User): User instance.
            perm (str): Permission string.
            obj (Model): Model instance.

        Returns:
            `True` if `user_obj` has permission, `False` otherwise.
        """

        # check if user_obj and object are supported
        support, user_obj = check_support(user_obj, obj)
        if not support:
            return False

        if "." in perm:
            app_label, _ = perm.split(".", 1)
            # TODO (David Graham): Check if obj is None or change the method signature
            if app_label != obj._meta.app_label:  # type: ignore[union-attr]
                # Check the content_type app_label when permission
                # and obj app labels don't match.
                ctype = get_content_type(obj)
                if app_label != ctype.app_label:
                    raise WrongAppError(
                        f"Passed perm has app label of '{app_label}' while "
                        f"given obj has app label '{obj._meta.app_label}' and given obj"  # type: ignore[union-attr]
                        f"content_type has app label '{ctype.app_label}'"
                    )

        check = ObjectPermissionChecker(user_obj)
        return check.has_perm(perm, obj)

    @staticmethod
    def _validate_app_label(user_obj: Any, perm: str, obj: Model) -> None:
        """Apply the same app-label validation used by ``has_perm``."""
        if "." not in perm:
            return
        app_label, _ = perm.split(".", 1)
        if app_label != obj._meta.app_label:
            ctype = get_content_type(obj)
            if app_label != ctype.app_label:
                raise WrongAppError(
                    f"Passed perm has app label of '{app_label}' while "
                    f"given obj has app label '{obj._meta.app_label}' and given obj"
                    f"content_type has app label '{ctype.app_label}'"
                )

    @staticmethod
    def _is_anonymous(user_obj: Any) -> bool:
        return not getattr(user_obj, "is_authenticated", False)

    def explain_perm(
        self,
        user_obj: Any,
        perm: str,
        obj: Model | Iterable[Model] | None = None,
        *,
        objects: Iterable[Model] | None = None,
        accept_global_perms: bool = False,
        redact: Any = None,
        redact_group: Any = None,
        redact_object: Any = None,
    ) -> PermissionExplanation | list[PermissionExplanation]:
        """Explain a backend object-permission decision.

        This follows the same support, app-label and identity rules as
        :meth:`has_perm`, and delegates the actual row inspection to
        :class:`~guardian.core.ObjectPermissionChecker`.  The boolean result is
        therefore guaranteed to agree with the checker path for the same input.
        """
        if objects is not None:
            return self.explain_perms(
                user_obj,
                perm,
                objects,
                accept_global_perms=accept_global_perms,
                redact=redact,
                redact_group=redact_group,
                redact_object=redact_object,
            )

        anonymous = self._is_anonymous(user_obj)
        if obj is None:
            return denied_permission_explanation(
                perm,
                None,
                "no_object",
                anonymous=anonymous,
                redact=redact,
                redact_group=redact_group,
                redact_object=redact_object,
            )
        if isinstance(obj, (list, tuple, Iterable)):
            return self.explain_perms(
                user_obj,
                perm,
                obj,
                accept_global_perms=accept_global_perms,
                redact=redact,
                redact_group=redact_group,
                redact_object=redact_object,
            )

        if not check_object_support(obj):
            return denied_permission_explanation(
                perm,
                obj,
                "unsupported_object",
                anonymous=anonymous,
                redact=redact,
                redact_group=redact_group,
                redact_object=redact_object,
            )

        support, resolved_user = check_support(user_obj, obj)
        if not support:
            reason = "anonymous_not_supported" if anonymous else "unsupported_user"
            return denied_permission_explanation(
                perm,
                obj,
                reason,
                anonymous=anonymous,
                redact=redact,
                redact_group=redact_group,
                redact_object=redact_object,
            )

        self._validate_app_label(resolved_user, perm, obj)
        checker = ObjectPermissionChecker(resolved_user)
        if anonymous:
            checker._is_anonymous = True
        return checker.explain_perm(
            perm,
            obj,
            accept_global_perms=accept_global_perms,
            redact=redact,
            redact_group=redact_group,
            redact_object=redact_object,
        )

    def explain_perms(
        self,
        user_obj: Any,
        perm: str,
        objects: Iterable[Model],
        *,
        accept_global_perms: bool = False,
        redact: Any = None,
        redact_group: Any = None,
        redact_object: Any = None,
    ) -> list[PermissionExplanation]:
        """Explain one permission for a batch of objects through the backend."""
        objects_list = list(objects)
        if not objects_list:
            return []

        anonymous = self._is_anonymous(user_obj)
        if not all(check_object_support(obj) for obj in objects_list):
            return [
                denied_permission_explanation(
                    perm,
                    obj if isinstance(obj, models.Model) else None,
                    "unsupported_object",
                    anonymous=anonymous,
                    redact=redact,
                    redact_group=redact_group,
                    redact_object=redact_object,
                )
                for obj in objects_list
            ]

        # check_support only depends on the user and object support, both of
        # which were just validated for the whole batch.
        support, resolved_user = check_support(user_obj, objects_list[0])
        if not support:
            reason = "anonymous_not_supported" if anonymous else "unsupported_user"
            return [
                denied_permission_explanation(
                    perm,
                    obj,
                    reason,
                    anonymous=anonymous,
                    redact=redact,
                    redact_group=redact_group,
                    redact_object=redact_object,
                )
                for obj in objects_list
            ]

        for obj in objects_list:
            self._validate_app_label(resolved_user, perm, obj)

        checker = ObjectPermissionChecker(resolved_user)
        if anonymous:
            checker._is_anonymous = True
        return checker.explain_perms(
            perm,
            objects_list,
            accept_global_perms=accept_global_perms,
            redact=redact,
            redact_group=redact_group,
            redact_object=redact_object,
        )

    def explain_perm_many(
        self,
        user_obj: Any,
        perm: str,
        objects: Iterable[Model],
        **kwargs: Any,
    ) -> list[PermissionExplanation]:
        """Alias for :meth:`explain_perms`."""
        return self.explain_perms(user_obj, perm, objects, **kwargs)

    def get_group_permissions(self, user_obj: Any, obj: Model | None = None) -> Iterable[str]:
        """Returns group permissions for a given object.

        Parameters:
            user_obj (User): User instance.
            obj (Model): Django Model instance. If None, returns empty set
                        since this backend only handles object-level permissions.

        Returns:
             a set of permission strings that the given `user_obj` has for `obj`
             through their group memberships.
        """
        # This backend only handles object-level permissions
        if obj is None:
            return set()

        # check if user_obj and object are supported
        support, user_obj = check_support(user_obj, obj)
        if not support:
            return set()

        check = ObjectPermissionChecker(user_obj)
        return set(check.get_group_perms(obj))

    def get_all_permissions(self, user_obj: Any, obj: Model | None = None) -> Iterable[str]:
        """Returns all permissions for a given object.

        Parameters:
            user_obj (User): User instance.
            obj (Model): Django Model instance.

        Returns:
             a set of permission strings that the given `user_obj` has for `obj`.
        """
        # check if user_obj and object are supported
        support, user_obj = check_support(user_obj, obj)
        if not support:
            return set()

        check = ObjectPermissionChecker(user_obj)
        return set(check.get_perms(obj))
