"""
Structure-aware mutators for the RTF fuzzing backend.

Each mutator works on the parsed syntax tree (see :mod:`oletools.rtf_fuzz.model`)
rather than on raw bytes, and records itself in the transformation chain as a
(category, name, detail) tuple.  Mutators are split into two pools:

* :data:`VALID_MUTATORS` only produce legal re-encodings that must keep the
  extracted object byte-identical (used by the equivalence oracle);
* :data:`INVALID_MUTATORS` deliberately create contradictory or illegal
  states whose diagnostics the invalid-sample oracle compares (used to detect
  silent truncation, crashes or unexpected full-object recovery).

Every mutator returns a *new* tree; the input is never modified in place.
"""

import copy
import random

from . import model


class Mutation(object):
    """A transformed tree plus the transformation chain entry that produced it."""

    def __init__(self, tree, category, name, detail=None):
        self.tree = tree
        self.category = category
        self.name = name
        self.detail = detail

    def as_record(self):
        record = {"category": self.category, "name": self.name}
        if self.detail is not None:
            record["detail"] = self.detail
        return record


def _clone(tree):
    return copy.deepcopy(tree)


def _objdata_groups(tree):
    return model.find_objdata_groups(tree)


def _first_objdata(tree):
    groups = _objdata_groups(tree)
    return groups[0] if groups else None


VALID_MUTATORS = []
INVALID_MUTATORS = []


def _register(pool):
    def decorator(function):
        pool.append(function)
        return function
    return decorator


valid = _register(VALID_MUTATORS)
invalid = _register(INVALID_MUTATORS)


# ---------------------------------------------------------------------------
# Valid mutators: legal re-encodings, extracted object must stay identical.
# ---------------------------------------------------------------------------

@valid
def insert_blank_hex_fragment(tree, rng):
    """Insert harmless whitespace inside a hex fragment (ignored by parser)."""
    tree = _clone(tree)
    fragments = model.find_hex_fragments(tree)
    if not fragments:
        return None
    target = rng.choice(fragments)
    if len(target.data) < 4:
        return None
    pos = rng.randrange(2, len(target.data) - 1)
    target.data = target.data[:pos] + b" " + target.data[pos:]
    return Mutation(tree, "valid", "insert_blank_hex_fragment",
                    {"position": pos})


@valid
def insert_newline_fragment(tree, rng):
    """Split a hex fragment with a CRLF run (a legal, ignored separator)."""
    tree = _clone(tree)
    fragments = model.find_hex_fragments(tree)
    candidates = [node for node in fragments if len(node.data) >= 6]
    if not candidates:
        return None
    target = rng.choice(candidates)
    pos = (len(target.data) // 2) * 1
    target.data = target.data[:pos] + b"\r\n" + target.data[pos:]
    return Mutation(tree, "valid", "insert_newline_fragment",
                    {"position": pos})


@valid
def insert_ignored_group(tree, rng):
    """Insert an ignored nested group using non-hex filler text."""
    tree = _clone(tree)
    fragments = model.find_hex_fragments(tree)
    candidates = [node for node in fragments if len(node.data) >= 4]
    if not candidates:
        return None
    target = rng.choice(candidates)
    pos = (len(target.data) // 2) * 2 - 2
    pos = max(2, pos)
    group = b"{\\*\\zzz qqq}"
    target.data = target.data[:pos] + group + target.data[pos:]
    return Mutation(tree, "valid", "insert_ignored_group",
                    {"position": pos})


@valid
def split_hex_fragment(tree, rng):
    """Split one hex text node into two adjacent text nodes (no byte change)."""
    tree = _clone(tree)
    for parent, node in model.walk_with_parent(tree):
        if isinstance(node, model.TextNode) and len(node.data) >= 8:
            pos = (len(node.data) // 2)
            if parent is None:
                return None
            index = parent.children.index(node)
            parent.children[index:index + 1] = [
                model.TextNode(node.data[:pos]),
                model.TextNode(node.data[pos:])]
            return Mutation(tree, "valid", "split_hex_fragment",
                            {"position": pos})
    return None


@valid
def merge_adjacent_hex(tree, rng):
    """Merge two sibling hex text nodes (inverse of a legal split)."""
    tree = _clone(tree)
    for node in model.walk(tree):
        children = getattr(node, "children", None)
        if not children:
            continue
        for index in range(len(children) - 1):
            left, right = children[index], children[index + 1]
            if (isinstance(left, model.TextNode)
                    and isinstance(right, model.TextNode)):
                children[index:index + 2] = [
                    model.TextNode(left.data + right.data)]
                return Mutation(tree, "valid", "merge_adjacent_hex")
    return None



def _hex_prefix_is_even(tree, target):
    """Count hex digits preceding target within its destination group."""
    owner = None
    for parent, node in model.walk_with_parent(tree):
        if node is target:
            owner = parent
            break
    if owner is None:
        return False
    seen = 0
    for node in model.walk(owner):
        if node is target:
            break
        if isinstance(node, model.TextNode):
            seen += sum(1 for c in node.data
                        if chr(c) in "0123456789abcdefABCDEF")
    return (seen % 2) == 0



def _preceded_by_apostrophe(tree, target):
    """Return True when the node immediately follows an apostrophe symbol."""
    for parent, node in model.walk_with_parent(tree):
        if node is target and parent is not None and target in parent.children:
            index = parent.children.index(target)
            if index == 0:
                return False
            previous = parent.children[index - 1]
            if not isinstance(previous, model.ControlSymbolNode):
                return False
            return previous.raw.endswith(b"\'")
    return False


@valid
def convert_hex_range_to_bin(tree, rng):
    """Replace an even-length hex run with an equivalent backslash-bin entry."""
    tree = _clone(tree)
    for node in model.find_hex_fragments(tree):
        digits = node.data
        # The apostrophe control symbol contributes zero bytes and trims an
        # odd leading digit, so only convert when the hex stream preceding the
        # node inside its destination holds an even number of digits.
        if not _hex_prefix_is_even(tree, node):
            continue
        if _preceded_by_apostrophe(tree, node):
            # backslash-apostrophe consumes the next two characters, so it
            # cannot be followed directly by a backslash-bin control word.
            continue
        # keep only runs made purely of hex digits for a clean conversion
        if len(digits) < 8 or len(digits) % 2 != 0:
            continue
        if not all(chr(c) in "0123456789abcdefABCDEF" for c in digits):
            continue
        parent = None
        for candidate_parent, candidate in model.walk_with_parent(tree):
            if candidate is node:
                parent = candidate_parent
                break
        if parent is None:
            continue
        raw = bytes(bytearray(int(digits[i:i + 2], 16)
                              for i in range(0, len(digits), 2)))
        index = parent.children.index(node)
        parent.children[index:index + 1] = [
            model.BinNode(str(len(raw)).encode("ascii"), raw,
                          leading_space=True)]
        return Mutation(tree, "valid", "convert_hex_range_to_bin",
                        {"bytes": len(raw)})
    return None


@valid
def split_bin_entry(tree, rng):
    """Split one backslash-bin payload into two shorter, equivalent entries."""
    tree = _clone(tree)
    bins = [node for node in model.find_bin_nodes(tree)
            if not node.truncated and len(node.payload) >= 4]
    if not bins:
        return None
    target = rng.choice(bins)
    cut = len(target.payload) // 2
    first = model.BinNode(str(cut).encode("ascii"),
                          target.payload[:cut], target.leading_space)
    second = model.BinNode(str(len(target.payload) - cut).encode("ascii"),
                           target.payload[cut:], True)
    parent = None
    for candidate_parent, candidate in model.walk_with_parent(tree):
        if candidate is target:
            parent = candidate_parent
            break
    index = parent.children.index(target)
    parent.children[index:index + 1] = [first, second]
    return Mutation(tree, "valid", "split_bin_entry", {"cut": cut})


@valid
def wrap_extra_group(tree, rng):
    """Wrap objdata contents in an extra nested non-destination group.

    The nested group is transparent to the destination stack, so extraction
    must be unchanged.
    """
    tree = _clone(tree)
    group = _first_objdata(tree)
    if group is None or len(group.children) < 2:
        return None
    inner = model.GroupNode(group.children[1:])
    del group.children[1:]
    group.children.append(inner)
    return Mutation(tree, "valid", "wrap_extra_group")


# ---------------------------------------------------------------------------
# Invalid mutators: deliberately contradictory or illegal states.
# ---------------------------------------------------------------------------

@invalid
def rename_destination(tree, rng):
    """Rename backslash-objdata to a non-destination word so it is ignored."""
    tree = _clone(tree)
    group = _first_objdata(tree)
    if group is None:
        return None
    for child in group.children:
        if (isinstance(child, model.ControlWordNode)
                and child.name == b"objdata"):
            child.name = b"zzdata"
            return Mutation(tree, "invalid", "rename_destination")
    return None


@invalid
def drop_opening_brace(tree, rng):
    """Replace an objdata group with an explicitly malformed, brace-less body."""
    tree = _clone(tree)
    group = _first_objdata(tree)
    if group is None:
        return None
    parent = None
    for candidate_parent, candidate in model.walk_with_parent(tree):
        if candidate is group:
            parent = candidate_parent
            break
    if parent is None:
        return None
    # Collapse the group into its children plus a stray closing brace so the
    # document is unbalanced but still serialisable byte-for-byte.
    index = parent.children.index(group)
    replacement = list(group.children) + [model.TextNode(b"}")]
    parent.children[index:index + 1] = replacement
    return Mutation(tree, "invalid", "drop_opening_brace")


@invalid
def bin_length_too_large(tree, rng):
    """Inflate a backslash-bin length past the available payload."""
    tree = _clone(tree)
    bins = model.find_bin_nodes(tree)
    candidates = [node for node in bins if not node.truncated
                  and node.length_token.lstrip(b"-").isdigit()]
    if not candidates:
        return None
    target = rng.choice(bins)
    inflated = len(target.payload) + rng.randrange(1, 17)
    target.length_token = str(inflated).encode("ascii")
    target.truncated = True
    return Mutation(tree, "invalid", "bin_length_too_large",
                    {"declared": inflated, "actual": len(target.payload)})


@invalid
def bin_length_too_small(tree, rng):
    """Shrink a backslash-bin length so part of the payload leaks as text."""
    tree = _clone(tree)
    bins = [node for node in model.find_bin_nodes(tree)
            if not node.truncated and len(node.payload) >= 4]
    if not bins:
        return None
    target = rng.choice(bins)
    shrunk = max(0, len(target.payload) // 2)
    leaked = target.payload[shrunk:]
    target.length_token = str(shrunk).encode("ascii")
    target.payload = target.payload[:shrunk]
    parent = None
    for candidate_parent, candidate in model.walk_with_parent(tree):
        if candidate is target:
            parent = candidate_parent
            break
    index = parent.children.index(target)
    parent.children.insert(index + 1, model.TextNode(leaked))
    return Mutation(tree, "invalid", "bin_length_too_small",
                    {"declared": shrunk, "leaked": len(leaked)})


@invalid
def bin_negative_length(tree, rng):
    """Force a negative backslash-bin length (rtfobj normalises it to zero)."""
    tree = _clone(tree)
    bins = [node for node in model.find_bin_nodes(tree)
            if node.length_token.lstrip(b"-").isdigit()]
    if not bins:
        return None
    target = rng.choice(bins)
    actual = len(target.payload)
    target.length_token = (b"-" + str(max(1, actual)).encode("ascii"))
    target.truncated = True
    return Mutation(tree, "invalid", "bin_negative_length",
                    {"actual": actual})


@invalid
def bin_missing_length(tree, rng):
    """Remove the backslash-bin argument entirely (zero-length read)."""
    tree = _clone(tree)
    bins = model.find_bin_nodes(tree)
    if not bins:
        return None
    target = rng.choice(bins)
    actual = len(target.payload)
    target.length_token = b"0"
    target.truncated = actual > 0
    return Mutation(tree, "invalid", "bin_missing_length",
                    {"actual": actual})


@invalid
def corrupt_hex_digit(tree, rng):
    """Rewrite one hexadecimal digit so the decoded object changes/breaks."""
    tree = _clone(tree)
    fragments = [node for node in model.find_hex_fragments(tree)
                 if any(chr(c) in "0123456789abcdefABCDEF" for c in node.data)]
    if not fragments:
        return None
    target = rng.choice(fragments)
    positions = [i for i, c in enumerate(target.data)
                 if chr(c) in "0123456789abcdefABCDEF"]
    pos = rng.choice(positions)
    original = chr(target.data[pos])
    replacement = rng.choice([c for c in "0123456789abcdef" if c != original.lower()])
    data = bytearray(target.data)
    data[pos] = ord(replacement)
    target.data = bytes(data)
    return Mutation(tree, "invalid", "corrupt_hex_digit",
                    {"position": pos, "from": original, "to": replacement})


@invalid
def insert_odd_hex_digit(tree, rng):
    """Insert a single extra hex digit to force odd-length trimming."""
    tree = _clone(tree)
    fragments = model.find_hex_fragments(tree)
    candidates = [node for node in fragments if len(node.data) >= 2]
    if not candidates:
        return None
    target = rng.choice(candidates)
    pos = rng.randrange(0, len(target.data) + 1)
    target.data = target.data[:pos] + b"a" + target.data[pos:]
    return Mutation(tree, "invalid", "insert_odd_hex_digit",
                    {"position": pos})


@valid
def insert_nonhex_in_hex(tree, rng):
    """Insert non-hex characters that rtfobj filters out (equivalent)."""
    tree = _clone(tree)
    fragments = model.find_hex_fragments(tree)
    if not fragments:
        return None
    target = rng.choice(fragments)
    pos = rng.randrange(0, len(target.data))
    target.data = target.data[:pos] + b"zz" + target.data[pos:]
    return Mutation(tree, "valid", "insert_nonhex_in_hex",
                    {"position": pos})


@invalid
def truncate_objdata_body(tree, rng):
    """Cut the objdata body short to simulate a truncated embedded object."""
    tree = _clone(tree)
    group = _first_objdata(tree)
    if group is None or len(group.children) < 2:
        return None
    for index in range(len(group.children) - 1, 0, -1):
        child = group.children[index]
        if isinstance(child, (model.TextNode, model.BinNode)):
            del group.children[index]
            return Mutation(tree, "invalid", "truncate_objdata_body",
                            {"removed_index": index})
    return None


def apply_one(tree, rng, pool):
    """Apply one randomly chosen mutator from pool, retrying on no-op."""
    order = list(pool)
    rng.shuffle(order)
    for mutator in order:
        mutation = mutator(tree, rng)
        if mutation is not None:
            return mutation
    return None


def valid_mutation(tree, rng):
    """Apply one valid (equivalence-preserving) mutator."""
    return apply_one(tree, rng, VALID_MUTATORS)


def invalid_mutation(tree, rng):
    """Apply one deliberately invalid mutator."""
    return apply_one(tree, rng, INVALID_MUTATORS)
