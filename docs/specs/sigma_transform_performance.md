# Sigma Transform Performance Considerations

This document outlines design considerations for implementing a Sigma-based transform
in Vector, with a focus on running large rule sets (for example, 5,000 rules) in
real-time pipelines.

## Baseline Expectations

Evaluating thousands of Sigma rules over high-volume telemetry requires careful
attention to CPU, memory, and allocation patterns. A straightforward implementation
that deserializes each rule for every event would quickly become a bottleneck.
Instead, the transform should parse and normalize rule definitions once at build
(or reload) time, producing efficient, in-memory data structures for evaluation.

## Parsing and Compilation Pipeline

1. **Bulk loading:** Read and validate rule files only when the transform is
   instantiated or when a configuration reload occurs. This avoids repeated I/O
   or YAML parsing on the hot path.
2. **Normalization:** Convert Sigma rules into a canonical representation (AST or
   bytecode) that strips comments and unused metadata.
3. **Static checks:** Pre-compute field access paths, typed comparisons, and
   aggregation windows so that evaluation reduces to fast predicate checks.
4. **Rule grouping:** Partition rules by log source, product, or category so the
   transform can quickly skip entire groups when an event clearly cannot match.

## Execution Optimizations

- **Indexing:** Build inverted indices (e.g., field name → candidate rule IDs) to
  limit the number of predicates visited per event. For example, use a hash map
  keyed by normalized field names to fetch only the relevant rules.
- **Short-circuiting:** Order predicates within each rule from most selective to
  least selective and exit early on failure. This can reduce average comparisons
  dramatically when many rules share common filters.
- **Vectorization:** Batch events and evaluate rules across the batch when inputs
  originate from the same schema. SIMD-friendly comparisons (e.g., evaluating the
  same string equality against multiple records) help amortize costs.
- **Concurrency:** Use the transform’s existing parallelism hooks to spread rules
  across worker threads. Assign independent rule partitions to separate tasks,
  ensuring that shared data (indices, compiled predicates) is read-only.

## Memory Management

- **Arena allocation:** Allocate compiled rule structures in arenas or bump
  allocators to reduce fragmentation and improve cache locality.
- **Deduplication:** Share immutable strings (field names, constant values)
  across rules via interning. This saves RAM when thousands of rules repeat the
  same identifiers.
- **Lazy materialization:** Only instantiate expensive structures (e.g., regex
  automata) for rules that actually use them.

## Hot Reloading Strategy

To support rule updates without downtime:

1. Compile the new rule set in the background.
2. Swap the active pointer to the new structures atomically once compilation
   succeeds.
3. Keep the old structures alive until all in-flight events have drained.

This double-buffering approach avoids blocking the pipeline during reloads while
ensuring correctness.

## Observability

- Emit metrics for rule evaluation latency, matches per rule, and per-batch CPU
  time.
- Surface cache hit rates for any indices or regex caches to help operators tune
  rule ordering and batching.
- Provide debug logging for the slowest rules to identify optimization targets.

## Summary

A performant Sigma transform hinges on compiling rules into efficient data
structures, indexing them for selective evaluation, and leveraging Vector’s
concurrency model. With these techniques, handling rule sets on the order of
thousands is feasible while maintaining throughput.
