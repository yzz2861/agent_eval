from django.apps import AppConfig
from django.conf import settings
from django.db.models.signals import post_delete, post_migrate, post_save

from . import monkey_patch_group, monkey_patch_user


class GuardianConfig(AppConfig):
    name = "guardian"
    default_auto_field = "django.db.models.AutoField"

    def ready(self):
        from .shortcuts import clear_ct_cache

        post_migrate.connect(clear_ct_cache)
        self._connect_cache_invalidation_signals()
        if settings.GUARDIAN_MONKEY_PATCH_GROUP:
            monkey_patch_group()
        if settings.GUARDIAN_MONKEY_PATCH_USER:
            monkey_patch_user()

    @staticmethod
    def _connect_cache_invalidation_signals():
        """Invalidate in-process checker caches when grants change directly."""
        from .models import BaseObjectPermission
        from .temporal import bump_cache_generation

        def invalidate(sender, instance, **kwargs):
            if isinstance(instance, BaseObjectPermission):
                bump_cache_generation()

        post_save.connect(invalidate, dispatch_uid="guardian.temporal.post_save", weak=False)
        post_delete.connect(invalidate, dispatch_uid="guardian.temporal.post_delete", weak=False)
