import pickle

from jinja2 import Environment
from jinja2.loaders import DictLoader


def test_environment(env):
    env = pickle.loads(pickle.dumps(env))
    assert env.from_string("x={{ x }}").render(x=42) == "x=42"


def test_environment_cache_locks_rebuild():
    env = Environment(
        loader=DictLoader({"same.html": "same"}),
        cache_namespace="tenant",
    )
    env.get_template("same.html")

    restored = pickle.loads(pickle.dumps(env))

    assert restored.get_template("same.html").render() == "same"
