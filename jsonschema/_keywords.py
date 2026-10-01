from fractions import Fraction
import re

from jsonschema._utils import (
    ensure_list,
    equal,
    extras_msg,
    find_additional_properties,
    find_evaluated_item_indexes_by_schema,
    find_evaluated_property_keys_by_schema,
    uniq,
)
from jsonschema.exceptions import FormatError, ValidationError


def _explanation_source_pointer(base, keyword, index=None):
    from jsonschema._explanation import json_pointer

    segments = (*base, keyword)
    if index is not None:
        segments = (*segments, index)
    return json_pointer(segments)


def patternProperties(validator, patternProperties, instance, schema):
    if not validator.is_type(instance, "object"):
        return

    collector = getattr(validator, "_explanation_collector", None)
    for pattern, subschema in patternProperties.items():
        for k, v in instance.items():
            if re.search(pattern, k):
                if collector is not None:
                    collector.annotate_property(k)
                yield from validator.descend(
                    v,
                    subschema,
                    path=k,
                    schema_path=pattern,
                    explanation_commit_on_success=True,
                )


def propertyNames(validator, propertyNames, instance, schema):
    if not validator.is_type(instance, "object"):
        return

    for property in instance:
        yield from validator.descend(instance=property, schema=propertyNames)


def additionalProperties(validator, aP, instance, schema):
    if not validator.is_type(instance, "object"):
        return

    extras = set(find_additional_properties(instance, schema))
    collector = getattr(validator, "_explanation_collector", None)

    if validator.is_type(aP, "object"):
        for extra in extras:
            if collector is not None:
                before = set(collector.stack[-1].properties)
            yield from validator.descend(
                instance[extra],
                aP,
                path=extra,
                explanation_commit_on_success=True,
            )
            if collector is not None and extra not in before:
                collector.annotate_property(extra)
    elif not aP and extras:
        if collector is not None:
            for extra in extras:
                collector.annotate_property(extra)
        if "patternProperties" in schema:
            verb = "does" if len(extras) == 1 else "do"
            joined = ", ".join(repr(each) for each in sorted(extras))
            patterns = ", ".join(
                repr(each) for each in sorted(schema["patternProperties"])
            )
            error = f"{joined} {verb} not match any of the regexes: {patterns}"
            yield ValidationError(error)
        else:
            error = "Additional properties are not allowed (%s %s unexpected)"
            yield ValidationError(error % extras_msg(sorted(extras, key=str)))


def items(validator, items, instance, schema):
    if not validator.is_type(instance, "array"):
        return

    prefix = len(schema.get("prefixItems", []))
    total = len(instance)
    extra = total - prefix
    if extra <= 0:
        return

    collector = getattr(validator, "_explanation_collector", None)
    if collector is not None:
        for index in range(prefix, total):
            collector.annotate_item(index)
    if items is False:
        rest = instance[prefix:] if extra != 1 else instance[prefix]
        item = "items" if prefix != 1 else "item"
        yield ValidationError(
            f"Expected at most {prefix} {item} but found {extra} "
            f"extra: {rest!r}",
        )
    else:
        for index in range(prefix, total):
            yield from validator.descend(
                instance=instance[index],
                schema=items,
                path=index,
                explanation_commit_on_success=True,
            )


def const(validator, const, instance, schema):
    if not equal(instance, const):
        yield ValidationError(f"{const!r} was expected")


def contains(validator, contains, instance, schema):
    if not validator.is_type(instance, "array"):
        return

    matches = 0
    min_contains = schema.get("minContains", 1)
    max_contains = schema.get("maxContains", len(instance))

    contains_validator = validator.evolve(schema=contains)
    collector = getattr(validator, "_explanation_collector", None)

    for index, each in enumerate(instance):
        if collector is not None:
            errors = list(
                validator.descend(
                    each,
                    contains,
                    explanation_commit_on_success=True,
                ),
            )
            matched = not errors
        else:
            matched = contains_validator.is_valid(each)

        if matched:
            matches += 1
            if collector is not None:
                collector.annotate_item(index)
            if matches > max_contains:
                yield ValidationError(
                    "Too many items match the given schema "
                    f"(expected at most {max_contains})",
                    validator="maxContains",
                    validator_value=max_contains,
                )
                return

    if matches < min_contains:
        if not matches:
            yield ValidationError(
                f"{instance!r} does not contain items "
                "matching the given schema",
            )
        else:
            yield ValidationError(
                "Too few items match the given schema (expected at least "
                f"{min_contains} but only {matches} matched)",
                validator="minContains",
                validator_value=min_contains,
            )


def exclusiveMinimum(validator, minimum, instance, schema):
    if not validator.is_type(instance, "number"):
        return

    if instance <= minimum:
        yield ValidationError(
            f"{instance!r} is less than or equal to "
            f"the minimum of {minimum!r}",
        )


def exclusiveMaximum(validator, maximum, instance, schema):
    if not validator.is_type(instance, "number"):
        return

    if instance >= maximum:
        yield ValidationError(
            f"{instance!r} is greater than or equal "
            f"to the maximum of {maximum!r}",
        )


def minimum(validator, minimum, instance, schema):
    if not validator.is_type(instance, "number"):
        return

    if instance < minimum:
        message = f"{instance!r} is less than the minimum of {minimum!r}"
        yield ValidationError(message)


def maximum(validator, maximum, instance, schema):
    if not validator.is_type(instance, "number"):
        return

    if instance > maximum:
        message = f"{instance!r} is greater than the maximum of {maximum!r}"
        yield ValidationError(message)


def multipleOf(validator, dB, instance, schema):
    if not validator.is_type(instance, "number"):
        return

    if isinstance(dB, float):
        quotient = instance / dB
        try:
            failed = int(quotient) != quotient
        except OverflowError:
            # When `instance` is large and `dB` is less than one,
            # quotient can overflow to infinity; and then casting to int
            # raises an error.
            #
            # In this case we fall back to Fraction logic, which is
            # exact and cannot overflow.  The performance is also
            # acceptable: we try the fast all-float option first, and
            # we know that fraction(dB) can have at most a few hundred
            # digits in each part.  The worst-case slowdown is therefore
            # for already-slow enormous integers or Decimals.
            failed = (Fraction(instance) / Fraction(dB)).denominator != 1
    else:
        failed = instance % dB

    if failed:
        yield ValidationError(f"{instance!r} is not a multiple of {dB}")


def minItems(validator, mI, instance, schema):
    if validator.is_type(instance, "array") and len(instance) < mI:
        message = "should be non-empty" if mI == 1 else "is too short"
        yield ValidationError(f"{instance!r} {message}")


def maxItems(validator, mI, instance, schema):
    if validator.is_type(instance, "array") and len(instance) > mI:
        message = "is expected to be empty" if mI == 0 else "is too long"
        yield ValidationError(f"{instance!r} {message}")


def uniqueItems(validator, uI, instance, schema):
    if (
        uI
        and validator.is_type(instance, "array")
        and not uniq(instance)
    ):
        yield ValidationError(f"{instance!r} has non-unique elements")


def pattern(validator, patrn, instance, schema):
    if (
        validator.is_type(instance, "string")
        and not re.search(patrn, instance)
    ):
        yield ValidationError(f"{instance!r} does not match {patrn!r}")


def format(validator, format, instance, schema):
    if validator.format_checker is not None:
        try:
            validator.format_checker.check(instance, format)
        except FormatError as error:
            yield ValidationError(error.message, cause=error.cause)


def minLength(validator, mL, instance, schema):
    if validator.is_type(instance, "string") and len(instance) < mL:
        message = "should be non-empty" if mL == 1 else "is too short"
        yield ValidationError(f"{instance!r} {message}")


def maxLength(validator, mL, instance, schema):
    if validator.is_type(instance, "string") and len(instance) > mL:
        message = "is expected to be empty" if mL == 0 else "is too long"
        yield ValidationError(f"{instance!r} {message}")


def dependentRequired(validator, dependentRequired, instance, schema):
    if not validator.is_type(instance, "object"):
        return

    for property, dependency in dependentRequired.items():
        if property not in instance:
            continue

        for each in dependency:
            if each not in instance:
                message = f"{each!r} is a dependency of {property!r}"
                yield ValidationError(message)


def dependentSchemas(validator, dependentSchemas, instance, schema):
    if not validator.is_type(instance, "object"):
        return

    for property, dependency in dependentSchemas.items():
        if property not in instance:
            continue
        yield from validator.descend(
            instance,
            dependency,
            schema_path=property,
            explanation_source=(
                "dependentSchemas",
                property,
                None,
                f"/dependentSchemas/{property}",
            ),
        )


def enum(validator, enums, instance, schema):
    if all(not equal(each, instance) for each in enums):
        yield ValidationError(f"{instance!r} is not one of {enums!r}")


def ref(validator, ref, instance, schema):
    yield from validator._validate_reference(ref=ref, instance=instance)


def dynamicRef(validator, dynamicRef, instance, schema):
    yield from validator._validate_reference(
        ref=dynamicRef,
        instance=instance,
        keyword="$dynamicRef",
    )


def type(validator, types, instance, schema):
    types = ensure_list(types)

    if not any(validator.is_type(instance, type) for type in types):
        reprs = ", ".join(repr(type) for type in types)
        yield ValidationError(f"{instance!r} is not of type {reprs}")


def properties(validator, properties, instance, schema):
    if not validator.is_type(instance, "object"):
        return

    collector = getattr(validator, "_explanation_collector", None)
    for property, subschema in properties.items():
        if property in instance:
            if collector is not None:
                collector.annotate_property(property)
            yield from validator.descend(
                instance[property],
                subschema,
                path=property,
                schema_path=property,
                explanation_commit_on_success=True,
            )


def required(validator, required, instance, schema):
    if not validator.is_type(instance, "object"):
        return
    for property in required:
        if property not in instance:
            yield ValidationError(f"{property!r} is a required property")


def minProperties(validator, mP, instance, schema):
    if validator.is_type(instance, "object") and len(instance) < mP:
        message = (
            "should be non-empty" if mP == 1
            else "does not have enough properties"
        )
        yield ValidationError(f"{instance!r} {message}")


def maxProperties(validator, mP, instance, schema):
    if not validator.is_type(instance, "object"):
        return
    if validator.is_type(instance, "object") and len(instance) > mP:
        message = (
            "is expected to be empty" if mP == 0
            else "has too many properties"
        )
        yield ValidationError(f"{instance!r} {message}")


def allOf(validator, allOf, instance, schema):
    collector = getattr(validator, "_explanation_collector", None)
    for index, subschema in enumerate(allOf):
        source = None
        if collector is not None:
            source = (
                "allOf",
                index,
                None,
                _explanation_source_pointer(
                    validator._explanation_schema_path,
                    "allOf",
                    index,
                ),
            )
        yield from validator.descend(
            instance,
            subschema,
            schema_path=index,
            explanation_source=source,
            explanation_commit_on_success=True,
        )


def anyOf(validator, anyOf, instance, schema):
    all_errors = []
    collector = getattr(validator, "_explanation_collector", None)
    for index, subschema in enumerate(anyOf):
        source = None
        if collector is not None:
            source = (
                "anyOf",
                index,
                None,
                _explanation_source_pointer(
                    validator._explanation_schema_path,
                    "anyOf",
                    index,
                ),
            )
        errs = list(validator.descend(
            instance,
            subschema,
            schema_path=index,
            explanation_source=source,
            explanation_commit_on_success=True,
        ))
        if not errs:
            break
        all_errors.extend(errs)
    else:
        yield ValidationError(
            f"{instance!r} is not valid under any of the given schemas",
            context=all_errors,
        )


def oneOf(validator, oneOf, instance, schema):
    all_errors = []
    valid_subschemas = []
    collector = getattr(validator, "_explanation_collector", None)
    for index, subschema in enumerate(oneOf):
        source = None
        if collector is not None:
            source = (
                "oneOf",
                index,
                None,
                _explanation_source_pointer(
                    validator._explanation_schema_path,
                    "oneOf",
                    index,
                ),
            )
        errs = list(validator.descend(
            instance,
            subschema,
            schema_path=index,
            explanation_source=source,
            explanation_commit_on_success=True,
        ))
        if not errs:
            valid_subschemas.append(subschema)
        else:
            all_errors.extend(errs)

    if not valid_subschemas:
        yield ValidationError(
            f"{instance!r} is not valid under any of the given schemas",
            context=all_errors,
        )
    elif len(valid_subschemas) > 1:
        reprs = ", ".join(repr(schema) for schema in valid_subschemas)
        yield ValidationError(f"{instance!r} is valid under each of {reprs}")


def not_(validator, not_schema, instance, schema):
    if validator.evolve(schema=not_schema).is_valid(instance):
        message = f"{instance!r} should not be valid under {not_schema!r}"
        yield ValidationError(message)


def if_(validator, if_schema, instance, schema):
    collector = getattr(validator, "_explanation_collector", None)
    if collector is not None:
        if_errors = list(validator.descend(
            instance,
            if_schema,
            schema_path="if",
            explanation_source=(
                "if",
                "if",
                None,
                _explanation_source_pointer(
                    validator._explanation_schema_path,
                    "if",
                ),
            ),
        ))
        condition_valid = not if_errors
    else:
        condition_valid = validator.evolve(schema=if_schema).is_valid(instance)

    if condition_valid:
        if "then" in schema:
            then = schema["then"]
            source = None
            if collector is not None:
                source = (
                    "if",
                    "then",
                    None,
                    _explanation_source_pointer(
                        validator._explanation_schema_path,
                        "then",
                    ),
                )
            yield from validator.descend(
                instance,
                then,
                schema_path="then",
                explanation_source=source,
                explanation_commit_on_success=True,
            )
    elif "else" in schema:
        else_ = schema["else"]
        source = None
        if collector is not None:
            source = (
                "if",
                "else",
                None,
                _explanation_source_pointer(
                    validator._explanation_schema_path,
                    "else",
                ),
            )
        yield from validator.descend(
            instance,
            else_,
            schema_path="else",
            explanation_source=source,
            explanation_commit_on_success=True,
        )


def unevaluatedItems(validator, unevaluatedItems, instance, schema):
    if not validator.is_type(instance, "array"):
        return
    collector = getattr(validator, "_explanation_collector", None)
    if collector is not None:
        evaluated_item_indexes = set(collector.stack[-1].items)
    else:
        evaluated_item_indexes = find_evaluated_item_indexes_by_schema(
            validator, instance, schema,
        )
    unevaluated_items = [
        item for index, item in enumerate(instance)
        if index not in evaluated_item_indexes
    ]
    if unevaluated_items:
        error = "Unevaluated items are not allowed (%s %s unexpected)"
        yield ValidationError(error % extras_msg(unevaluated_items))


def unevaluatedProperties(validator, unevaluatedProperties, instance, schema):
    if not validator.is_type(instance, "object"):
        return
    collector = getattr(validator, "_explanation_collector", None)
    if collector is not None:
        evaluated_keys = set(collector.stack[-1].properties)
    else:
        evaluated_keys = find_evaluated_property_keys_by_schema(
            validator, instance, schema,
        )
    unevaluated_keys = []
    for property in instance:
        if property not in evaluated_keys:
            before = len(unevaluated_keys)
            for _ in validator.descend(
                instance[property],
                unevaluatedProperties,
                path=property,
                schema_path=property,
                explanation_commit_on_success=True,
            ):
                # FIXME: Include context for each unevaluated property
                #        indicating why it's invalid under the subschema.
                unevaluated_keys.append(property)  # noqa: PERF401
            if collector is not None and len(unevaluated_keys) == before:
                collector.annotate_property(property)

    if unevaluated_keys:
        if unevaluatedProperties is False:
            error = "Unevaluated properties are not allowed (%s %s unexpected)"
            extras = sorted(unevaluated_keys, key=str)
            yield ValidationError(error % extras_msg(extras))
        else:
            error = (
                "Unevaluated properties are not valid under "
                "the given schema (%s %s unevaluated and invalid)"
            )
            yield ValidationError(error % extras_msg(unevaluated_keys))


def prefixItems(validator, prefixItems, instance, schema):
    if not validator.is_type(instance, "array"):
        return

    collector = getattr(validator, "_explanation_collector", None)
    for (index, item), subschema in zip(enumerate(instance), prefixItems):
        if collector is not None:
            collector.annotate_item(index)
        yield from validator.descend(
            instance=item,
            schema=subschema,
            schema_path=index,
            path=index,
            explanation_commit_on_success=True,
        )
