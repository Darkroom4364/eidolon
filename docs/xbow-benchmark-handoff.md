# XBow Benchmark Handoff

This handoff is for the pwnkit benchmark lane only.

Do not treat XBow-style benchmark results as evidence of Eidolon defensive
value. Benchmark outputs stay inside the scanner-qualification boundary.

## Purpose

The goal of this handoff is to provide an external benchmark task export that
the repo can:

1. validate,
2. preflight,
3. import into a benchmark-only manifest,
4. execute through the pwnkit benchmark lane,
5. package into a reviewable bundle.

## Accepted Input Shapes

The repo accepts either:

1. a JSON array of task objects
2. a JSONL stream with one task object per line

## Required Task Fields

Each task must provide enough identity to survive import without ambiguity.

Minimum required fields:

```json
{
  "benchmark_family": "xbow_public",
  "benchmark_task_id": "task-alpha",
  "benchmark_snapshot_id": "snap-001",
  "benchmark_validation_rule": "validated_exploit_required"
}
```

Accepted aliases:

- `benchmark_family | family`
- `benchmark_task_id | task_id | id`
- `benchmark_snapshot_id | snapshot_id`
- `benchmark_validation_rule | validation_rule`

## Strongly Preferred Fields

These improve rerun comparability and benchmark interpretation:

- `benchmark_model_id`
- `benchmark_prompt_bundle_hash`
- `benchmark_action_budget`
- `benchmark_token_budget`
- `benchmark_wall_clock_budget_seconds`
- `substrate`
- `defense_mode`
- `run_count`
- `notes`
- `env`

## Contract Rules

The export must satisfy these rules:

- `benchmark_task_id` must be unique across the export.
- Normalized variant IDs must remain unique after import.
  Example: `task alpha` and `task-alpha` will collide.
- Any provided budget must be a positive integer.
- `run_count`, if present, must be a positive integer.
- `enabled`, if present, must be boolean.
- `env`, if present, must be a flat object of string/number/boolean values.

## What The Repo Will Preserve

During import, the benchmark lane preserves:

- task-export sha256
- task-export format
- imported-task count

Those fields are carried into:

- imported manifest
- benchmark matrix summary
- benchmark report
- packaged benchmark bundle
- benchmark comparison output

## Provider Checklist

Before handing off an export, provide:

1. export file path or filename
2. export date
3. benchmark family name
4. snapshot versioning policy
5. validation rule semantics
6. prompt bundle hash provenance
7. whether the task set is fixed or expected to churn between drops

## Preflight Command

Use this before import:

```sh
examples/qualification/report-pwnkit-benchmark-task-export.sh \
  /path/to/xbow-tasks.jsonl
```

If preflight fails, fix the export contract first. Do not bypass the checker.

## Import Command

```sh
examples/qualification/import-pwnkit-benchmark-tasks.sh \
  /path/to/xbow-tasks.jsonl \
  /tmp/eidolon-pwnkit-benchmark-variants.json
```

## Full Workflow Command

```sh
examples/qualification/run-pwnkit-benchmark-imported-matrix.sh \
  /path/to/xbow-tasks.jsonl \
  /tmp/eidolon-pwnkit-benchmark-imported
```

This writes:

- task-export report
- imported manifest
- benchmark matrix directory
- benchmark report
- packaged benchmark bundle

## Claim Boundary

Keep these statements separate:

- Benchmark success says something about pwnkit benchmark-lane performance.
- Benchmark success does not prove Eidolon defensive differentiation.
- Benchmark regression comparisons are only meaningful when the comparer marks
  them comparable.
