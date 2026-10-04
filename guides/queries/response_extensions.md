---
title: Response Extensions
layout: guide
doc_stub: false
search: true
section: Queries
desc: Adding "extensions" to the response hash
index: 12
---

During query execution, you can add to the response's `"extensions" => { ... }` Hash. By default, no `"extensions"` key is present in the result, but if you call the method below, it will be present with the given values.

To add to `"extensions"`, call `context.response_extensions[key] = value` during execution. For example:

```ruby
field :to_dos, [ToDo]

def to_dos
  warnings = context.response_extensions["warnings"] ||= []
  warnings << "To-Dos will be disabled on Jan. 31, 2022."
  context[:current_user].deprecated_to_dos
end
```


That would add to the final query response:

```ruby
{
  "data" => { ... },
  "extensions" => {
    "warnings" => ["To-Dos will be disabled on Jan. 31, 2022"],
  },
}
```

Values written to `context.response_extensions` are added to the GraphQL response verbatim.

## Null propagation diagnostics

When a non-null field returns `nil`, GraphQL null propagation may replace an object or the entire `data` value with `nil`. To help identify the cause, pass `null_propagation_extensions: true` in query context:

```ruby
MySchema.execute(query, context: { null_propagation_extensions: true })
```

Failures are reported under `extensions.nullPropagation.traces`. Each trace contains the original response path, the non-null `FIELD`, `LIST`, or `LIST_ELEMENT` wrappers through which `nil` propagated, and the response path where propagation stopped. Response keys use the aliases selected by the client. Diagnostics include type names and paths only; resolver return values are not collected.
