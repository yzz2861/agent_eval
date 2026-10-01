from django.core.exceptions import ValidationError
from django.test import TestCase

from .models import Tenant, User


class CompositePKBulkValidateTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.tenant = Tenant.objects.create(id=1)
        cls.user = User.objects.create(
            tenant=cls.tenant, id=1, email="user1@example.com"
        )

    def test_batch_conflict_on_unique_field(self):
        instances = [
            User(tenant=self.tenant, id=2, email="dup@example.com"),
            User(tenant=self.tenant, id=3, email="dup@example.com"),
        ]
        result = User.bulk_validate(instances)
        self.assertIsNotNone(result[0])
        self.assertIsNotNone(result[1])

    def test_database_conflict_excludes_edited_self(self):
        instance = User(
            pk=self.user.pk,
            tenant_id=self.tenant.id,
            id=1,
            email="user1@example.com",
        )
        instance._state.adding = False
        result = User.bulk_validate([instance])
        self.assertTrue(result.valid, result.errors)

    def test_database_conflict_on_other_row(self):
        instance = User(
            tenant_id=self.tenant.id, id=2, email="user1@example.com"
        )
        result = User.bulk_validate([instance])
        self.assertIsInstance(result[0], ValidationError)

    def test_new_instance_with_existing_composite_pk_conflicts(self):
        instance = User(
            tenant_id=self.tenant.id, id=1, email="other@example.com"
        )
        result = User.bulk_validate([instance])
        self.assertIsNotNone(result[0])
