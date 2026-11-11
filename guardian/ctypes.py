import logging
from typing import Any

from django.contrib.contenttypes.models import ContentType
from django.db.models import Model
from django.utils.module_loading import import_string

from guardian.conf import settings as guardian_settings
from guardian.exceptions import ObjectIdentityError, TenantMismatchError

logger = logging.getLogger(__name__)


def get_content_type(obj: Model | type[Model]) -> Any:
    get_content_type_function = import_string(guardian_settings.GET_CONTENT_TYPE)
    return get_content_type_function(obj)


def get_default_content_type(obj: Model | type[Model]) -> ContentType:
    """Get content type for a given object using Django's content type framework.

    Parameters:
        obj (Model | type[Model]): Object for which content type is to be fetched.

    Returns:
        Content type for the given object.

    See Also:
        https://docs.djangoproject.com/en/5.1/ref/contrib/contenttypes/

    """
    return ContentType.objects.get_for_model(obj)


def validate_object_identity(obj: Model | type[Model], ctype: Any = None) -> Any:
    """Ensure the resolved content type still identifies the object's model.

    Object identity is the combination of primary key, actual model and
    content type; it must never be split apart. A custom
    GUARDIAN_GET_CONTENT_TYPE may legitimately map proxy or inherited
    models to their concrete/parent content type (same table, same primary
    key namespace). Mapping an object to the content type of an *unrelated*
    model would merge distinct primary key namespaces and let same-pk
    objects of different models inherit each other's permissions, so such a
    mapping is refused with an auditable ObjectIdentityError instead of
    being persisted.

    Parameters:
        obj (Model | type[Model]): Object (or model class) being validated.
        ctype: Content type resolved for obj; computed when omitted.

    Returns:
        The (possibly computed) content type, for caller convenience.
    """
    if ctype is None:
        ctype = get_content_type(obj)
    model_class = ctype.model_class() if isinstance(ctype, ContentType) else None
    if model_class is None:
        # Non-ContentType or unresolvable custom return values cannot be
        # validated; leave them to the caller's configuration.
        return ctype
    model = obj if isinstance(obj, type) else type(obj)
    if issubclass(model, model_class):
        return ctype
    if model._meta.concrete_model._meta.db_table == model_class._meta.concrete_model._meta.db_table:
        return ctype
    logger.warning(
        "Refusing ambiguous object identity for model %s mapped to content type of %s (reason_code=%s)",
        model._meta.label_lower,
        model_class._meta.label_lower,
        ObjectIdentityError.code,
    )
    raise ObjectIdentityError(
        "GUARDIAN_GET_CONTENT_TYPE maps "
        f"{model._meta.label_lower} to the content type of {model_class._meta.label_lower}; "
        "object identity (primary key, model, content type) would be ambiguous"
    )


def get_tenant(obj: Any) -> Any:
    """Resolve the tenant of obj via the configured tenant resolver.

    Returns None when no GUARDIAN_GET_TENANT resolver is configured
    (single-tenant compatibility) or when the resolver does not associate
    obj with any tenant (historical, tenant-less data stays accessible).
    """
    resolver_path = guardian_settings.GET_TENANT
    if not resolver_path or obj is None:
        return None
    return import_string(resolver_path)(obj)


def tenant_allows(identity: Any, obj: Model, operation: str = "check") -> bool:
    """Check whether identity may access obj across tenant boundaries.

    Returns True when no tenant resolver is configured, when either side has
    no tenant (tenant-less historical data stays compatible), or when both
    tenants match. Otherwise logs an auditable, aggregate-friendly denial and
    returns False. The denial deliberately carries no object identifiers so
    callers cannot probe for the existence of another tenant's objects.
    """
    identity_tenant = get_tenant(identity)
    obj_tenant = get_tenant(obj)
    if identity_tenant is None or obj_tenant is None or identity_tenant == obj_tenant:
        return True
    logger.warning(
        "Denied cross-tenant object permission %s (reason_code=%s)",
        operation,
        TenantMismatchError.code,
    )
    return False


def validate_tenant(identity: Any, obj: Model, operation: str = "assign") -> None:
    """Raise TenantMismatchError for cross-tenant operations.

    No-op when no tenant resolver is configured or when either side is
    tenant-less, preserving single-tenant and historical-data behaviour.
    """
    if not tenant_allows(identity, obj, operation=operation):
        raise TenantMismatchError(f"Cross-tenant object permission {operation} is denied")
