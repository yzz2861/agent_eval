"""Fixed-seed generator of small programs with explicit contracts.

Everything is derived from a single ``random.Random`` stream owned by
the caller, so a suite is reproducible offline run after run.
"""

import itertools

from tests.functional.gencontracts import model

SEED = 20261122

_COMMANDS = (
    "ls -l tmp",
    "echo hello",
    "cat logfile",
    "grep root logfile",
    "wc -l notes",
    "tail -n 5 logfile",
)
_SECRETS = ("hunter2", "s3cr3t", "t0ken123", "pa55word", "letmein99")
_PLAIN = ("alpha", "beta", "gamma", "delta", "epsilon")


def _gen_expr(rng, bound, lit_pool):
    choices = ["lit", "move_lit"]
    if bound:
        choices += ["var", "move_var"]
    kind = rng.choice(choices)
    if kind == "lit":
        return model.Lit(rng.choice(lit_pool))
    if kind == "var":
        return model.Var(rng.choice(bound))
    if kind == "move_var":
        return model.Move(
            rng.choice(model.MOVE_OPS), model.Var(rng.choice(bound))
        )
    return model.Move(
        rng.choice(model.MOVE_OPS), model.Lit(rng.choice(lit_pool))
    )


def _gen_scope(rng, name, cids, names, min_stmts, max_stmts):
    bound = []
    body = []
    for _ in range(rng.randint(min_stmts, max_stmts)):
        kind = rng.choice(("bind", "bind", "shell", "connect"))
        if kind == "bind":
            var = "v%d" % next(names)
            body.append(
                model.Bind(next(cids), var, _gen_expr(rng, bound, _PLAIN))
            )
            bound.append(var)
        elif kind == "shell":
            body.append(
                model.ShellSink(
                    next(cids),
                    _gen_expr(rng, bound, _COMMANDS),
                    shell=rng.random() < 0.7,
                )
            )
        else:
            keyword = rng.choice(
                model.PASSWORD_LIKE_KEYWORDS + model.NEUTRAL_KEYWORDS
            )
            body.append(
                model.ConnectSink(
                    next(cids), keyword, _gen_expr(rng, bound, _SECRETS)
                )
            )
    return model.Scope(name, tuple(body))


def generate_case(rng, case_index):
    """Generate one program; ``rng`` is owned and seeded by the caller."""
    prefix = "c%03d" % case_index
    cids = ("%s-s%d" % (prefix, n) for n in itertools.count())
    names = itertools.count()

    scopes = [_gen_scope(rng, "", cids, names, 2, 6)]
    for fn_index in range(rng.randint(0, 2)):
        scopes.append(
            _gen_scope(rng, "helper_%d" % fn_index, cids, names, 1, 5)
        )

    program = model.Program(prefix, tuple(scopes))
    if not any(
        isinstance(stmt, (model.ShellSink, model.ConnectSink))
        for _, stmt in model.iter_statements(program)
    ):
        # guarantee at least one sink per program
        sink = model.ShellSink(next(cids), model.Lit("echo hello"), True)
        module = program.scopes[0]
        program = model.Program(
            prefix,
            (model.Scope("", module.body + (sink,)),) + program.scopes[1:],
        )
    return program
