import threading
import time
import warnings

import pytest

from RestrictedPython import compile_restricted
from RestrictedPython import safe_builtins
from RestrictedPython.transactions import Binding
from RestrictedPython.transactions import CommitError
from RestrictedPython.transactions import Transaction
from RestrictedPython.transactions import TransactionStateError
from RestrictedPython.transactions import UnsupportedWritable
from RestrictedPython.transactions import VersionConflict
from RestrictedPython.transactions import WritePermissionDenied
from RestrictedPython.transactions import transactional_exec


class Account:
    def __init__(self):
        self.balance = 100
        self.tags = ["a"]
        self.history = [{"event": "open"}]


class SlottedAccount:
    __slots__ = ("balance", "frozen")

    def __init__(self):
        self.balance = 5
        self.frozen = False


class ExplodingAttr:
    def __init__(self):
        self.value = 1

    def __setattr__(self, name, value):
        if name == "value" and value == "boom":
            raise RuntimeError("storage unavailable")
        object.__setattr__(self, name, value)


def test_isolation_keeps_host_untouched_until_commit():
    items = [1, 2, {"k": 3}]
    meta = {"nested": [10, 20]}
    account = Account()
    tx = Transaction()
    tx.allow_object(items, name="items")
    tx.allow_object(meta, name="meta")
    tx.allow_object(
        account, name="account",
        writable_attrs=("balance", "tags", "history"))

    tx.execute(
        """
items.append(3)
items[2]["k"] = 99
meta["nested"][0] = 77
account.balance = 250
account.tags = ["b", "c"]
""")

    assert items == [1, 2, {"k": 3}]
    assert meta == {"nested": [10, 20]}
    assert account.balance == 100
    assert account.tags == ["a"]
    assert len(tx.writes()) == 5

    tx.commit()
    assert items == [1, 2, {"k": 99}, 3]
    assert meta == {"nested": [77, 20]}
    assert account.balance == 250
    assert account.tags == ["b", "c"]
    assert tx.committed is True


def test_writes_are_collected_per_host():
    data = {"a": [1], "b": 2}
    tx = Transaction()
    tx.allow_object(data, name="data")
    tx.execute(
        """
data["b"] = 20
data["a"].append(2)
""")
    sets = dict((id(host), records)
                for host, records in tx.write_sets())
    assert id(data) in sets
    assert id(data["a"]) in sets
    kinds = {(record.kind, record.operation)
             for record in tx.writes()}
    assert ("item", "set") in kinds
    assert ("item", "append") in kinds
    assert tx.changed_objects() == (data, data["a"])


def test_alias_through_two_names_stays_one_object():
    shared = {"v": 1}
    root = {"a": shared, "b": shared}
    tx = Transaction()
    tx.allow_object(root, name="root")
    namespace = tx.execute(
        """
root["a"]["v"] = 42
seen = root["a"]["v"] + root["b"]["v"]
root["b"]["v"] = 7
""")
    assert namespace["seen"] == 84
    # The real shared object is untouched before commit.
    assert shared == {"v": 1}
    tx.commit()
    assert root["a"] is root["b"] is shared
    assert shared == {"v": 7}


def test_list_alias_and_nested_identity_preserved():
    child = [1, 2]
    root = {"first": child, "second": child}
    tx = Transaction()
    tx.allow_object(root, name="root")
    tx.execute(
        """
root["first"].append(3)
root["second"][0] = 99
""")
    tx.commit()
    assert root["first"] is root["second"] is child
    assert child == [99, 2, 3]


def test_new_objects_keep_natural_identity_inside_transaction():
    root = {"items": []}
    tx = Transaction()
    tx.allow_object(root, name="root")
    namespace = tx.execute(
        """
created = {"mark": True}
root["items"].append(created)
root["items"].append(created)
same = root["items"][0] is root["items"][1]
""")
    assert namespace["same"] is True
    tx.commit()
    assert root["items"][0] is root["items"][1]
    assert root["items"][0] == {"mark": True}


def test_dict_self_reference_is_preserved():
    data = {"name": "root", "children": []}
    data["self"] = data
    data["children"].append(data)
    tx = Transaction()
    tx.allow_object(data, name="data")
    tx.execute(
        """
data["name"] = "changed"
data["children"].append({"ok": True})
""")
    tx.commit()
    assert data["self"] is data
    assert data["children"][0] is data
    assert data["name"] == "changed"
    assert data["children"][1] == {"ok": True}


def test_list_self_reference_is_preserved():
    values = [1, 2]
    values.append(values)
    tx = Transaction()
    tx.allow_object(values, name="values")
    tx.execute("values[0] = 99")
    tx.commit()
    assert values[2] is values
    assert values[:2] == [99, 2]


def test_cross_container_cycle_preserved():
    left = {"side": "left", "peer": None}
    right = {"side": "right", "peer": left}
    left["peer"] = right
    tx = Transaction()
    tx.allow_object(left, name="left")
    tx.execute(
        """
left["side"] = "L"
""")
    tx.commit()
    assert left["peer"] is right
    assert right["peer"] is left
    assert left["side"] == "L"


def test_undocumented_attribute_write_is_denied():
    account = Account()
    tx = Transaction()
    tx.allow_object(
        account, name="account", writable_attrs=("balance",))
    with pytest.raises(WritePermissionDenied):
        tx.execute(
            """
account.tags = ["x"]
""")
    tx.abort()
    assert account.tags == ["a"]
    assert account.balance == 100


def test_attribute_write_on_container_is_denied():
    data = [1, 2]
    tx = Transaction()
    tx.allow_object(data, name="data")
    with pytest.raises(WritePermissionDenied):
        tx.execute(
            """
data.surprise = 1
""")
    tx.abort()
    assert data == [1, 2]


def test_undocumented_root_object_write_is_denied():
    tx = Transaction()
    stranger = [1]
    with pytest.raises(WritePermissionDenied):
        tx.guard_write(stranger)


def test_unsupported_type_rejected_at_documentation_time():
    tx = Transaction()
    with pytest.raises(UnsupportedWritable):
        tx.allow_object({1, 2, 3}, name="values")
    assert tx.finished is False


def test_unsupported_nested_type_rejected_on_first_read():
    class Bean:
        def __init__(self):
            self.payload = {1, 2}

    bean = Bean()
    tx = Transaction()
    tx.allow_object(
        bean, name="bean", writable_attrs=("payload",))
    with pytest.raises(UnsupportedWritable):
        tx.execute(
            """
value = bean.payload
""")
    assert bean.payload == {1, 2}


def test_callable_host_attributes_are_refused_before_use():
    class Service:
        def __init__(self):
            self.name = "svc"

        def mutate(self):
            raise AssertionError("host side effect must not run")

    service = Service()
    tx = Transaction()
    tx.allow_object(
        service, name="service", writable_attrs=("name",))
    with pytest.raises(UnsupportedWritable):
        tx.execute(
            """
service.mutate()
""")
    assert service.name == "svc"


def test_exception_during_execution_leaks_no_write():
    data = {"items": [1, 2, 3]}
    tx = Transaction()
    tx.allow_object(data, name="data")
    with pytest.raises(RuntimeError):
        tx.execute(
            """
data["items"].append(9)
raise RuntimeError("boom")
""")
    tx.abort()
    assert data == {"items": [1, 2, 3]}
    with pytest.raises(TransactionStateError):
        tx.commit()


def test_concurrent_host_update_causes_version_conflict():
    versions = {"v": 1}
    data = {"items": [1, 2, 3]}

    def get_version(host):
        return versions["v"]

    tx = Transaction()
    tx.allow_object(data, name="data", version_getter=get_version)
    tx.execute(
        """
data["items"].append(4)
""")
    # Another writer changes the host and bumps its version.
    versions["v"] = 2
    with pytest.raises(VersionConflict):
        tx.commit()
    assert data == {"items": [1, 2, 3]}
    assert tx.committed is False


def test_failing_validator_aborts_before_touching_hosts():
    data = {"items": [1]}
    tx = Transaction()
    tx.allow_object(data, name="data")
    tx.execute(
        """
data["items"].append(2)
""")

    def reject(transaction):
        raise ValueError("business rule rejected")

    with pytest.raises(CommitError) as exc:
        tx.commit(validators=[reject])
    assert isinstance(exc.value.__cause__, ValueError)
    assert data == {"items": [1]}


def test_mid_commit_failure_rolls_back_every_host():
    root = {"boom": ExplodingAttr(), "safe": [1, 2]}
    tx = Transaction()
    tx.allow_object(root, name="root")
    tx.allow_object(
        root["boom"], writable_attrs=("value",))
    tx.execute(
        """
root["boom"].value = "boom"
root["safe"].append(3)
""")
    with pytest.raises(CommitError) as exc:
        tx.commit()
    assert isinstance(exc.value.__cause__, RuntimeError)
    assert root["boom"].value == 1
    assert root["safe"] == [1, 2]


def test_concurrent_observer_sees_only_old_or_complete_state():
    data = {
        "phase": "old",
        "nested": {"v": 1},
        "items": [0],
    }
    tx = Transaction()
    tx.allow_object(data, name="data")
    tx.execute(
        """
data["phase"] = "new"
data["nested"]["v"] = 2
data["items"].append(1)
""")
    allowed = {
        ("old", 1, (0,)),
        ("new", 2, (0, 1)),
    }
    seen = []
    stop = threading.Event()

    def observe():
        while not stop.is_set():
            with tx.lock:
                seen.append((
                    data["phase"],
                    data["nested"]["v"],
                    tuple(data["items"]),
                ))

    thread = threading.Thread(target=observe)
    thread.start()
    time.sleep(0.02)
    with tx.lock:
        tx.commit()
    time.sleep(0.02)
    stop.set()
    thread.join()
    assert seen, "observer should collect samples"
    assert set(seen).issubset(allowed)
    assert allowed.issubset(set(seen))


def test_default_restricted_execution_is_unchanged():
    code = compile_restricted("y = x + 1", "<default>", "exec")
    namespace = dict(safe_builtins)
    namespace["x"] = 5
    exec(code, namespace)
    assert namespace["y"] == 6


def test_transactional_exec_helper_commits_documentation_only():
    data = {"n": 0}
    binding = Binding(data, "data")
    tx, namespace = transactional_exec(
        """
data["n"] = data["n"] + 10
""",
        bindings=[binding])
    assert data == {"n": 10}
    assert tx.committed is True
    with pytest.raises(TransactionStateError):
        namespace["data"]["n"]


def test_slotted_attribute_host_is_supported_and_restored():
    account = SlottedAccount()
    tx = Transaction()
    tx.allow_object(
        account, name="account",
        writable_attrs=("balance", "frozen"))
    tx.execute(
        """
account.balance = 42
account.frozen = True
""")
    assert account.balance == 5
    tx.commit()
    assert account.balance == 42
    assert account.frozen is True


def test_context_manager_commits_on_success_and_aborts_on_error():
    data = {"v": 1}
    with Transaction() as tx:
        tx.allow_object(data, name="data")
        tx.execute(
            """
data["v"] = 2
""")
    assert data == {"v": 2}

    other = {"v": 1}
    tx = Transaction()
    tx.allow_object(other, name="data")
    with pytest.raises(ValueError):
        with tx:
            tx.execute(
                """
data["v"] = 3
raise ValueError("stop")
""")
    assert other == {"v": 1}
    assert tx.finished is True
    assert tx.committed is False


def test_iteration_and_dict_views_go_through_guards():
    data = {"nums": [1, 2, 3], "name": "x"}
    tx = Transaction()
    tx.allow_object(data, name="data")
    namespace = tx.execute(
        """
total = 0
for number in data["nums"]:
    total = total + number
keys = []
for key in data.keys():
    keys.append(key)
pairs = data.items()
""")
    assert namespace["total"] == 6
    assert sorted(namespace["keys"]) == ["name", "nums"]
    assert ("nums", namespace["data"]["nums"]) in namespace["pairs"]
    tx.abort()


def test_guarded_setattr_and_delattr_builtins_respect_policy():
    account = Account()
    tx = Transaction()
    tx.allow_object(
        account, name="account", writable_attrs=("balance",))
    tx.execute(
        """
setattr(account, "balance", 333)
""")
    assert account.balance == 100
    with pytest.raises(WritePermissionDenied):
        tx.execute(
            """
setattr(account, "tags", ["nope"])
""")
    tx.commit()
    assert account.balance == 333


def test_for_loop_tuple_unpacking_uses_guarded_iteration():
    data = {"pairs": [("a", 1), ("b", 2)]}
    tx = Transaction()
    tx.allow_object(data, name="data")
    namespace = tx.execute(
        """
total = 0
letters = []
for letter, number in data["pairs"]:
    letters.append(letter)
    total = total + number
""")
    assert namespace["letters"] == ["a", "b"]
    assert namespace["total"] == 3
    tx.abort()


def test_print_collector_captures_restricted_output():
    data = {"items": [1, 2]}
    tx = Transaction()
    tx.allow_object(data, name="data")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        namespace = tx.execute(
            """
print("hello", data["items"])
""")
    assert namespace["_print"]() == "hello [1, 2]\n"
    tx.abort()


def test_commit_and_abort_lifecycle_is_strict():
    data = {"a": 1}
    tx = Transaction()
    tx.allow_object(data, name="data")
    assert tx.commit() is True
    assert tx.finished is True
    assert tx.committed is True
    with pytest.raises(TransactionStateError):
        tx.commit()
    with pytest.raises(TransactionStateError):
        tx.execute(
            """
data["a"] = 2
""")
    assert data == {"a": 1}

    other = Transaction()
    other.allow_object(data, name="data")
    assert other.abort() is True
    assert other.abort() is False
    assert other.committed is False
    with pytest.raises(TransactionStateError):
        other.execute(
            """
data["a"] = 3
""")
    assert data == {"a": 1}


def test_commit_without_writes_is_a_noop_success():
    data = {"a": 1}
    tx = Transaction()
    tx.allow_object(data, name="data")
    tx.execute(
        """
value = data["a"]
""")
    assert tx.commit() is True
    assert data == {"a": 1}
    assert tx.writes() == ()
