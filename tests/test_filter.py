# Copyright 2021 The casbin Authors. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import tempfile
from concurrent.futures import ThreadPoolExecutor
from unittest import TestCase
import casbin
from casbin.core_enforcer import CoreEnforcer
from tests.test_enforcer import get_examples, get_examples_copy
from casbin.persist.adapters import FileAdapter, FilteredFileAdapter
from casbin.persist.adapters.filtered_file_adapter import filter_line, filter_words


class Filter:
    # P,G are strings
    P = []
    G = []


DOMAIN_MODEL = """
[request_definition]
r = sub, dom, obj, act

[policy_definition]
p = sub, dom, obj, act

[role_definition]
g = _, _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub, r.dom) && r.dom == p.dom && r.obj == p.obj && r.act == p.act
"""

DOMAIN_PATTERN_MODEL = """
[request_definition]
r = sub, dom, obj, act

[policy_definition]
p = sub, dom, obj, act

[role_definition]
g = _, _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub, r.dom) && keyMatch(r.dom, p.dom) && r.obj == p.obj && r.act == p.act
"""


def write_policy(text):
    file = tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False)
    file.write(text)
    file.flush()
    file.close()
    return file.name


class TestFilteredFileAdapter(TestCase):
    def test_init_filtered_adapter(self):
        adapter = FilteredFileAdapter(get_examples("rbac_with_domains_policy.csv"))
        e = casbin.Enforcer(get_examples("rbac_with_domains_model.conf"), adapter)
        self.assertFalse(e.has_policy(["admin", "domain1", "data1", "read"]))

    def test_load_filtered_policy(self):
        adapter = FilteredFileAdapter(get_examples("rbac_with_domains_policy.csv"))
        e = casbin.Enforcer(get_examples("rbac_with_domains_model.conf"), adapter)
        filter = Filter()
        filter.P = ["", "domain1"]
        filter.G = ["", "", "domain1"]
        try:
            e.load_policy()
        except:
            raise RuntimeError("unexpected error in LoadFilteredPolicy")
        self.assertTrue(e.has_policy(["admin", "domain1", "data1", "read"]))
        self.assertTrue(e.has_policy(["admin", "domain2", "data2", "read"]))
        try:
            e.load_filtered_policy(filter)
        except:
            raise RuntimeError("unexpected error in LoadFilteredPolicy")

        if not e.is_filtered:
            raise RuntimeError("adapter did not set the filtered flag correctly")

        self.assertTrue(e.has_policy(["admin", "domain1", "data1", "read"]))
        self.assertFalse(e.has_policy(["admin", "domain2", "data2", "read"]))

        with self.assertRaises(RuntimeError):
            e.save_policy()

        with self.assertRaises(RuntimeError):
            e.get_adapter().save_policy(e.get_model())

    def test_append_filtered_policy(self):
        adapter = FilteredFileAdapter(get_examples("rbac_with_domains_policy.csv"))
        e = casbin.Enforcer(get_examples("rbac_with_domains_model.conf"), adapter)
        filter = Filter()
        filter.P = ["", "domain1"]
        filter.G = ["", "", "domain1"]
        try:
            e.load_policy()
        except:
            raise RuntimeError("unexpected error in LoadFilteredPolicy")
        self.assertTrue(e.has_policy(["admin", "domain1", "data1", "read"]))
        self.assertTrue(e.has_policy(["admin", "domain2", "data2", "read"]))
        try:
            e.load_filtered_policy(filter)
        except:
            raise RuntimeError("unexpected error in LoadFilteredPolicy")

        if not e.is_filtered:
            raise RuntimeError("adapter did not set the filtered flag correctly")

        self.assertTrue(e.has_policy(["admin", "domain1", "data1", "read"]))
        self.assertFalse(e.has_policy(["admin", "domain2", "data2", "read"]))

        filter.P = ["", "domain2"]
        filter.G = ["", "", "domain2"]
        try:
            e.load_increment_filtered_policy(filter)
        except:
            raise RuntimeError("unexpected error in LoadFilteredPolicy")

        self.assertTrue(e.has_policy(["admin", "domain1", "data1", "read"]))
        self.assertTrue(e.has_policy(["admin", "domain2", "data2", "read"]))

    def test_filtered_policy_invalid_filter(self):
        adapter = FilteredFileAdapter(get_examples("rbac_with_domains_policy.csv"))
        e = casbin.Enforcer(get_examples("rbac_with_domains_model.conf"), adapter)
        filter = ["", "domain1"]

        with self.assertRaises(RuntimeError):
            e.load_filtered_policy(filter)

    def test_filtered_policy_empty_filter(self):
        adapter = FilteredFileAdapter(get_examples_copy("rbac_with_domains_policy.csv"))
        e = casbin.Enforcer(get_examples("rbac_with_domains_model.conf"), adapter)

        try:
            e.load_filtered_policy(None)
        except:
            raise RuntimeError("unexpected error in LoadFilteredPolicy")

        if e.is_filtered():
            raise RuntimeError("adapter did not reset the filtered flag correctly")

        try:
            e.save_policy()
        except:
            raise RuntimeError("unexpected error in SavePolicy")

    def test_unsupported_filtered_policy(self):
        e = casbin.Enforcer(
            get_examples("rbac_with_domains_model.conf"),
            get_examples("rbac_with_domains_policy.csv"),
        )
        filter = Filter()
        filter.P = ["", "domain1"]
        filter.G = ["", "", "domain1"]
        with self.assertRaises(ValueError):
            e.load_filtered_policy(filter)

    def test_filtered_adapter_empty_filepath(self):
        adapter = FilteredFileAdapter("")
        e = casbin.Enforcer(get_examples("rbac_with_domains_model.conf"), adapter)

        with self.assertRaises(RuntimeError):
            e.load_filtered_policy(None)

    def test_filtered_adapter_invalid_filepath(self):
        adapter = FilteredFileAdapter(get_examples("does_not_exist_policy.csv"))
        e = casbin.Enforcer(get_examples("rbac_with_domains_model.conf"), adapter)

        with self.assertRaises(RuntimeError):
            e.load_filtered_policy(None)

    def test_empty_filter_array(self):
        """Test filter for empty array."""
        adapter = FilteredFileAdapter(get_examples("rbac_with_domains_policy.csv"))
        e = casbin.Enforcer(get_examples("rbac_with_domains_model.conf"), adapter)
        filter = Filter()
        filter.P = []
        filter.G = []

        e.load_filtered_policy(filter)
        self.assertTrue(e.has_policy(["admin", "domain1", "data1", "read"]))
        self.assertTrue(e.has_policy(["admin", "domain2", "data2", "read"]))

    def test_empty_string_filter(self):
        """Test the filter for all empty strings."""
        adapter = FilteredFileAdapter(get_examples("rbac_with_domains_policy.csv"))
        e = casbin.Enforcer(get_examples("rbac_with_domains_model.conf"), adapter)
        filter = Filter()
        filter.P = ["", "", ""]
        filter.G = ["", "", ""]

        e.load_filtered_policy(filter)
        self.assertTrue(e.has_policy(["admin", "domain1", "data1", "read"]))
        self.assertTrue(e.has_policy(["admin", "domain2", "data2", "read"]))

    def test_mixed_empty_filter(self):
        """Test the filter for mixed empty and non-empty strings."""
        adapter = FilteredFileAdapter(get_examples("rbac_with_domains_policy.csv"))
        e = casbin.Enforcer(get_examples("rbac_with_domains_model.conf"), adapter)
        filter = Filter()
        filter.P = ["", "domain1", ""]
        filter.G = ["", "", "domain1"]

        e.load_filtered_policy(filter)
        self.assertTrue(e.has_policy(["admin", "domain1", "data1", "read"]))
        self.assertFalse(e.has_policy(["admin", "domain2", "data2", "read"]))

    def test_nonexistent_domain_filter(self):
        """Testing the filter for a non-existent domain."""
        adapter = FilteredFileAdapter(get_examples("rbac_with_domains_policy.csv"))
        e = casbin.Enforcer(get_examples("rbac_with_domains_model.conf"), adapter)
        filter = Filter()
        filter.P = ["", "domain3"]
        filter.G = ["", "", "domain3"]

        e.load_filtered_policy(filter)
        self.assertFalse(e.has_policy(["admin", "domain3", "data3", "read"]))

    def test_empty_filter_array(self):
        """Test filter for empty array."""
        adapter = FilteredFileAdapter(get_examples("rbac_with_domains_policy.csv"))
        e = casbin.Enforcer(get_examples("rbac_with_domains_model.conf"), adapter)
        filter = Filter()
        filter.P = []
        filter.G = []

        try:
            e.load_filtered_policy(filter)
        except:
            raise RuntimeError("unexpected error with empty filter arrays")

        self.assertFalse(e.is_filtered(), "Adapter should not be marked as filtered with empty filters")

        self.assertTrue(e.has_policy(["admin", "domain1", "data1", "read"]))
        self.assertTrue(e.has_policy(["admin", "domain2", "data2", "read"]))

    def test_empty_string_filter(self):
        """Test the filter for all empty strings."""
        adapter = FilteredFileAdapter(get_examples_copy("rbac_with_domains_policy.csv"))
        e = casbin.Enforcer(get_examples("rbac_with_domains_model.conf"), adapter)
        filter = Filter()
        filter.P = ["", "", ""]
        filter.G = ["", "", ""]

        try:
            e.load_filtered_policy(filter)
        except:
            raise RuntimeError("unexpected error with empty string filters")

        self.assertFalse(e.is_filtered(), "Adapter should not be marked as filtered with empty string filters")

        try:
            e.save_policy()
        except:
            raise RuntimeError("unexpected error in SavePolicy with empty string filters")

        self.assertTrue(e.has_policy(["admin", "domain1", "data1", "read"]))
        self.assertTrue(e.has_policy(["admin", "domain2", "data2", "read"]))

    def test_mixed_empty_filter(self):
        """Test the filter for mixed empty and non-empty strings."""
        adapter = FilteredFileAdapter(get_examples("rbac_with_domains_policy.csv"))
        e = casbin.Enforcer(get_examples("rbac_with_domains_model.conf"), adapter)
        filter = Filter()
        filter.P = ["", "domain1", ""]
        filter.G = ["", "", "domain1"]

        try:
            e.load_filtered_policy(filter)
        except:
            raise RuntimeError("unexpected error with mixed empty filters")

        self.assertTrue(e.is_filtered(), "Adapter should be marked as filtered")

        with self.assertRaises(RuntimeError):
            e.save_policy()

        self.assertTrue(e.has_policy(["admin", "domain1", "data1", "read"]))
        self.assertFalse(e.has_policy(["admin", "domain2", "data2", "read"]))

    def test_whitespace_filter(self):
        """Test the filter for all blank characters."""
        adapter = FilteredFileAdapter(get_examples("rbac_with_domains_policy.csv"))
        e = casbin.Enforcer(get_examples("rbac_with_domains_model.conf"), adapter)
        filter = Filter()
        filter.P = [" ", "  ", "\t"]
        filter.G = ["\n", " ", "  "]

        e.load_filtered_policy(filter)

        self.assertFalse(e.is_filtered())
        self.assertTrue(e.has_policy(["admin", "domain1", "data1", "read"]))
        self.assertTrue(e.has_policy(["admin", "domain2", "data2", "read"]))

    def test_filter_line_edge_cases(self):
        """Test the boundary cases of the filter_line function."""
        adapter = FilteredFileAdapter(get_examples("rbac_with_domains_policy.csv"))

        self.assertFalse(filter_line("", [[""], [""]]))

        self.assertFalse(filter_line("invalid_line", [[""], [""]]))

        self.assertFalse(filter_line("p, admin, domain1, data1, read", None))

    def test_filter_words_edge_cases(self):
        """Test the boundary cases of the filter_words function."""
        self.assertTrue(filter_words(["p"], ["filter1", "filter2"]))

        self.assertFalse(filter_words(["p", "admin", "domain1"], []))

        line = ["admin", "domain1", "data*", "read"]
        filter = ["", "", "data1", ""]
        self.assertTrue(filter_words(line, filter))

    def test_load_filtered_policy_with_comments(self):
        """Test loading filtering policies with comments."""
        import tempfile
        import shutil

        with tempfile.NamedTemporaryFile(mode="w+", delete=False) as temp_file:
            with open(get_examples("rbac_with_domains_policy.csv"), "r") as source:
                shutil.copyfileobj(source, temp_file)

            temp_file.write("\n# This is a comment\np, admin, domain1, data3, read")
            temp_file.flush()

            temp_path = temp_file.name

        try:
            adapter = FilteredFileAdapter(temp_path)
            e = casbin.Enforcer(get_examples("rbac_with_domains_model.conf"), adapter)
            filter = Filter()
            filter.P = ["", "domain1"]
            filter.G = ["", "", "domain1"]

            e.load_filtered_policy(filter)
            self.assertTrue(e.has_policy(["admin", "domain1", "data3", "read"]))
        finally:
            try:
                os.unlink(temp_path)
            except OSError:
                pass


class TestDomainIsolation(TestCase):
    def tearDown(self):
        adapter = getattr(self, "adapter", None)
        if adapter is not None:
            try:
                os.unlink(adapter._file_path)
            except OSError:
                pass

    def load(self, model_text, policy_text, filtered=True):
        self.adapter = (
            FilteredFileAdapter(write_policy(policy_text)) if filtered else FileAdapter(write_policy(policy_text))
        )
        self.enforcer = casbin.Enforcer(CoreEnforcer.new_model(text=model_text), self.adapter)
        return self.enforcer

    def test_same_role_name_is_isolated_when_filter_switches(self):
        policy = """p, admin, domain1, data1, read
p, admin, domain2, data2, read
g, alice, admin, domain1
g, bob, admin, domain2
"""
        e = self.load(DOMAIN_MODEL, policy)

        filter = Filter()
        filter.P = ["", "domain1"]
        filter.G = ["", "", "domain1"]
        e.load_filtered_policy(filter)

        self.assertEqual(e.get_roles_for_user_in_domain("alice", "domain1"), ["admin"])
        self.assertEqual(e.get_roles_for_user_in_domain("bob", "domain2"), [])
        self.assertFalse(e.enforce("alice", "domain2", "data2", "read"))
        self.assertFalse(e.enforce("bob", "domain2", "data2", "read"))

        filter.P = ["", "domain2"]
        filter.G = ["", "", "domain2"]
        e.load_filtered_policy(filter)

        self.assertEqual(e.get_roles_for_user_in_domain("alice", "domain1"), [])
        self.assertEqual(e.get_roles_for_user_in_domain("bob", "domain2"), ["admin"])
        self.assertFalse(e.enforce("alice", "domain1", "data1", "read"))
        self.assertFalse(e.enforce("alice", "domain2", "data2", "read"))
        self.assertTrue(e.enforce("bob", "domain2", "data2", "read"))

    def test_clearing_filter_removes_old_domain_links(self):
        policy = """p, admin, domain1, data1, read
p, admin, domain2, data2, read
g, alice, admin, domain1
g, bob, admin, domain2
"""
        e = self.load(DOMAIN_MODEL, policy)

        filter = Filter()
        filter.P = ["", "domain1"]
        filter.G = ["", "", "domain1"]
        e.load_filtered_policy(filter)
        self.assertTrue(e.enforce("alice", "domain1", "data1", "read"))

        e.load_filtered_policy(None)
        self.assertFalse(e.is_filtered())
        self.assertEqual(e.get_roles_for_user_in_domain("alice", "domain1"), ["admin"])
        self.assertEqual(e.get_roles_for_user_in_domain("bob", "domain2"), ["admin"])
        self.assertTrue(e.enforce("alice", "domain1", "data1", "read"))
        self.assertTrue(e.enforce("bob", "domain2", "data2", "read"))
        self.assertFalse(e.enforce("alice", "domain2", "data2", "read"))
        self.assertFalse(e.enforce("bob", "domain1", "data1", "read"))

    def test_explicit_global_role_survives_domain_filter(self):
        policy = """p, admin, domain1, data1, read
p, admin, domain2, data2, read
p, admin, *, global_data, read
g, alice, admin, *
g, bob, admin, domain2
"""
        e = self.load(DOMAIN_PATTERN_MODEL, policy)

        filter = Filter()
        filter.P = ["", "domain1"]
        filter.G = ["", "", "domain1"]
        e.load_filtered_policy(filter)

        self.assertIn(["alice", "admin", "*"], e.get_grouping_policy())
        self.assertIn(["admin", "*", "global_data", "read"], e.get_policy())
        self.assertNotIn(["bob", "admin", "domain2"], e.get_grouping_policy())
        self.assertTrue(e.enforce("alice", "domain1", "data1", "read"))
        self.assertTrue(e.enforce("alice", "domain1", "global_data", "read"))
        self.assertEqual(e.get_roles_for_user_in_domain("alice", "domain1"), ["admin"])

    def test_empty_domain_is_not_a_wildcard(self):
        policy = """p, admin, domain1, data1, read
p, admin, domain2, data2, read
g, alice, admin, domain1
g, carol, admin,
"""
        e = self.load(DOMAIN_MODEL, policy, filtered=False)

        self.assertEqual(e.get_roles_for_user_in_domain("carol", ""), ["admin"])
        self.assertEqual(e.get_roles_for_user_in_domain("carol", "domain1"), [])
        self.assertEqual(e.get_roles_for_user("carol"), [])
        self.assertFalse(e.enforce("carol", "domain1", "data1", "read"))
        self.assertFalse(e.enforce("carol", "domain2", "data2", "read"))

    def test_missing_domain_field_is_ignored(self):
        policy = """p, admin, domain1, data1, read
g, alice, admin
"""
        e = self.load(DOMAIN_MODEL, policy, filtered=False)

        self.assertEqual(e.get_roles_for_user("alice"), [])
        self.assertEqual(e.get_roles_for_user_in_domain("alice", "domain1"), [])
        self.assertFalse(e.enforce("alice", "domain1", "data1", "read"))

    def test_cross_domain_delete_keeps_other_domain(self):
        policy = """p, admin, domain1, data1, read
p, admin, domain2, data2, read
g, alice, admin, domain1
g, bob, admin, domain2
"""
        e = self.load(DOMAIN_MODEL, policy, filtered=False)

        self.assertTrue(e.delete_roles_for_user_in_domain("alice", "admin", "domain1"))
        self.assertEqual(e.get_roles_for_user_in_domain("alice", "domain1"), [])
        self.assertEqual(e.get_roles_for_user_in_domain("bob", "domain2"), ["admin"])
        self.assertTrue(e.enforce("bob", "domain2", "data2", "read"))

    def test_concurrent_enforce_does_not_cross_domains(self):
        policy = """p, admin, domain1, data1, read
p, admin, domain2, data2, read
g, alice, admin, domain1
g, bob, admin, domain2
"""
        e = self.load(DOMAIN_MODEL, policy, filtered=False)

        def check(index):
            if index % 2:
                return e.enforce("alice", "domain1", "data1", "read") and not e.enforce(
                    "alice", "domain2", "data2", "read"
                )
            return e.enforce("bob", "domain2", "data2", "read") and not e.enforce("bob", "domain1", "data1", "read")

        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(check, range(400)))
        self.assertTrue(all(results))
