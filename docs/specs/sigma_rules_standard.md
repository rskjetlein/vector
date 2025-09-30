# Sigma Rule Handling Standard

This document summarizes the rule structure that Sigma defines in the public
standard at <https://sigmahq.io/docs/basics/rules.html>. Vector does not yet
implement every rule construct that Sigma describes, but all of the elements
listed below must be taken into account when evaluating the feasibility of
adding or extending Sigma support.  Individual sections cross-reference the
terminology used in the Sigma specification so that omissions in Vector's
current implementation can be spotted quickly.

## Overall rule layout

A Sigma rule is a YAML document that contains mandatory metadata along with a
`logsource` block and a `detection` block.  The top-level keys that appear in
the examples published by the Sigma project include the following:

* `title` *(required)* – a short, human readable description of the behaviour
  that the rule is detecting.  Rules often add `id` (a UUID) and
  `description` for longer narrative context.
* `status` – indicates rule maturity (`stable`, `testing`, `deprecated`, etc.).
* `logsource` *(required)* – describes the telemetry family that the rule
  targets.  It normally provides a `category`, a platform-specific `product`,
  and may include a `service`, `definition`, or `source` field.
* `detection` *(required)* – the heart of the rule.  The Sigma specification
  requires at least one selection definition and a `condition`.  Optional
  helpers such as `timeframe`, `fields`, `falsepositives`, `level`, `author`,
  `references`, and `tags` round out the metadata.

Vector currently parses `title` and `id` to build a display name, and it loads
all of the YAML documents embedded inside the configured rule files.  The
transform does **not** use `logsource` or the metadata properties beyond the
rule name, so any future work that introduces source scoping or severity-based
routing should read this section of the Sigma spec carefully.

## Detection block anatomy

The detection block follows a well-defined structure:

```yaml
selection1:
  FieldA: value
  FieldB|contains: admin
selection2:
  CommandLine|re: "(?i)\\bnet(\.exe)?\\s+user"
filter:
  UserName:
    - SYSTEM
    - LOCAL SERVICE
condition: selection1 and selection2 and not filter
```

The Sigma rules specification allows multiple **selection blocks** along with
optional **filters** and helper keywords such as `keywords` or `all`.  Each
selection gives Sigma the raw tests that need to match fields in the incoming
log events.  The `condition` string supplies the boolean logic that combines
these selections, filters, and keywords together.

Vector's transform loads each top-level entry in the detection block that is
not named `condition` or `timeframe` and treats it as a selection.  The
implementation currently accepts only mapping-based selections that hold field
comparisons.  List-based helpers such as `keywords`, the `condition` helpers
(`1 of`, `all of`, `near`, etc.), and match modifiers like `|contains` or
`|re` are explicitly rejected and surface an error message referencing the
unsupported construct.

### Selection entries

Sigma allows the value portion of a selection to express the test in a variety
of forms:

* **Scalar equality** – the example above matches whenever `FieldA` equals the
  string `value`.
* **Multiple alternatives** – when a selection value is a sequence, Sigma
  interprets it as a logical OR between the listed scalars.
* **Match modifiers** – appending a pipe-delimited modifier to the field name
  changes the matching semantics.  For example, `FieldB|contains` converts the
  equality test into a substring check, `Image|startswith` constrains the
  prefix, `CommandLine|re` injects a regular expression, and `SourceIp|cidr`
  tests whether an IP address belongs to a network.  Modifiers also exist for
  special encodings (`|base64`, `|wide`), tokenized containment
  (`|contains|all`, `|contains|any`), and type-specific comparisons (`|lt`,
  `|gt`, etc.).
* **Nested matches** – selectors can traverse object-valued fields by using
  dotted paths (`event_data.CommandLine`) or array indices
  (`event_data.PipeList[1]`).

Vector currently supports scalar equality and lists of scalar equality tests.
It raises a configuration error when a selection refers to a modifier, when
nested structures appear, or when the selection references non-scalar content.

### Condition grammar

Sigma's `condition` clause is a compact boolean expression language with the
following features:

* Basic logic: `and`, `or`, and `not` keywords control how the selections are
  combined.  Parentheses determine precedence.
* References: bare identifiers such as `selection1` or `filter` reference the
  selections defined earlier in the detection block.
* Quantifiers: patterns such as `1 of selection*` or `all of them` allow rules
  to apply to groups of selections chosen by wildcard matching.  Wildcard
  patterns use an asterisk (`*`) as a greedy placeholder.
* `near` relationships: `selection1 near selection2` requires that two
  selections match within a configurable timeframe.
* Aggregation helpers: the syntax `count(selection1) by Target` or
  `sum(bytes) by user` enables post-processing conditions such as cardinality
  or threshold checks.

Vector's transform only understands conjunction (`and`), disjunction (`or`),
parentheses, and positive references to named selections.  It fails fast when
encountering negation, quantifiers, aggregations, or the `near` syntax so that
rule authors receive explicit feedback about unsupported constructs instead of
silently producing incorrect matches.

### Timeframe

Sigma permits an optional `timeframe` property in the detection block so that
backends can constrain how far apart sub-matches may occur before they are
considered unrelated.  Vector currently parses the property to ensure that it
is a string, but it does not perform any temporal correlation.

## Practical implications for Vector

1. **Strict validation is critical.**  The Sigma spec contains many more
   features than Vector currently implements.  The transform therefore rejects
   modifiers, negations, quantifiers, and aggregation syntax so that operators
   do not assume that the rules are enforced when they are not.
2. **Roadmap for full support.**  Bringing the transform in line with the
   Sigma standard would require:
   * Implementing the extensive library of match modifiers, including
     substring tests, regular expressions, CIDR matching, and encoded
     comparisons.
   * Parsing the boolean expression language into an abstract syntax tree that
     can model `not`, `1 of`, `all of`, `near`, and the aggregation functions.
   * Tracking selection hits over time to respect the `timeframe` semantics
     and `near` conditions.
   * Extending the event model so list containment and structured sub-fields
     are treated according to Sigma's expectations.
3. **Documentation alignment.**  All user-facing documentation should make it
   clear that the current transform only supports straightforward equality
   matches and list-based alternation.  The checks added alongside this
   document ensure that unsupported constructs fail during configuration, but
   the long-term goal should be parity with the official Sigma specification.

The Sigma community maintains additional resources—including rule style
guides, tests, and backend adapters—that describe how different engines map
these constructs to their query languages.  Engineers implementing advanced
support in Vector should consult those references to ensure that
configuration-time validation, error messages, and runtime semantics stay in
lock-step with the public standard.
