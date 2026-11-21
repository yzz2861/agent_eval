# SPDX-License-Identifier: Apache-2.0
import ast
from types import SimpleNamespace

import testtools

from bandit.plugins import resource_ownership


RESOURCE_CONFIG = {
    "resources": [
        {
            "factory": "issue_temporary_credential",
            "release": "return_temporary_credential",
            "managed_calls": ["use_temporary_credential"],
        }
    ]
}


class ResourceOwnershipTests(testtools.TestCase):
    def _run(self, source, config=RESOURCE_CONFIG, aliases=None):
        tree = ast.parse(source)
        function = next(
            node
            for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        )
        context = SimpleNamespace(
            node=function,
            import_aliases=aliases or {},
        )
        return resource_ownership.resource_ownership(context, config)

    def test_early_return_reports_source_and_exit_path(self):
        source = (
            "def early(flag):\n"
            "    credential = issue_temporary_credential()\n"
            "    if flag:\n"
            "        return None\n"
            "    return_temporary_credential(credential)\n"
        )

        result = self._run(source)

        self.assertIsNotNone(result)
        self.assertEqual(2, result.lineno)
        self.assertIn("line 2", result.text)
        self.assertIn("2 -> 3 -> 4", result.text)
        self.assertIn("return at line 4", result.text)

    def test_normal_release_does_not_report(self):
        source = (
            "def normal():\n"
            "    credential = issue_temporary_credential()\n"
            "    return_temporary_credential(credential)\n"
        )

        self.assertIsNone(self._run(source))

    def test_explicit_handoff_does_not_report(self):
        source = (
            "def handoff():\n"
            "    credential = issue_temporary_credential()\n"
            "    use_temporary_credential(credential)\n"
        )

        self.assertIsNone(self._run(source))

    def test_alias_does_not_transfer_ownership(self):
        source = (
            "def alias():\n"
            "    credential = issue_temporary_credential()\n"
            "    another_name = credential\n"
            "    return None\n"
        )

        result = self._run(source)

        self.assertIsNotNone(result)
        self.assertEqual(2, result.lineno)

    def test_alias_can_be_used_to_release(self):
        source = (
            "def alias_release():\n"
            "    credential = issue_temporary_credential()\n"
            "    another_name = credential\n"
            "    return_temporary_credential(another_name)\n"
        )

        self.assertIsNone(self._run(source))

    def test_context_managers_manage_the_factory_lifetime(self):
        source = (
            "def managed():\n"
            "    with issue_temporary_credential() as credential:\n"
            "        use_temporary_credential(credential)\n"
        )

        self.assertIsNone(self._run(source))

    def test_async_finally_covers_cancellation(self):
        source = (
            "async def managed():\n"
            "    credential = issue_temporary_credential()\n"
            "    try:\n"
            "        await tick()\n"
            "    finally:\n"
            "        await return_temporary_credential(credential)\n"
        )

        self.assertIsNone(self._run(source))

    def test_unknown_handoff_is_left_unknown(self):
        source = (
            "def dynamic():\n"
            "    credential = issue_temporary_credential()\n"
            "    mystery(credential)\n"
        )

        self.assertIsNone(self._run(source))

    def test_direct_factory_mapping_is_supported(self):
        source = (
            "def mapping():\n"
            "    credential = issue_temporary_credential()\n"
            "    return None\n"
        )

        result = self._run(
            source,
            config={
                "issue_temporary_credential": "return_temporary_credential"
            },
        )

        self.assertIsNotNone(result)
