"""File containing both exec() and the newly covered eval() case."""


def run_loaders(payload, expression):
    exec(payload)
    return eval(expression)
