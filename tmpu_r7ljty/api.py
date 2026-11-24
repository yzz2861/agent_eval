
from sanitizer import clean


def lookup(value):
    return raw_query(clean(value))
