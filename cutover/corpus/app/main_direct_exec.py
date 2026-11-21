"""Bare exec() call in the actively maintained application tree."""


def run_loader(payload):
    exec(payload)
