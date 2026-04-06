---
name: agent-harness-construction
description: Design and optimize AI agent action spaces, tool definitions, and observation formatting for higher completion rates.
origin: ECC
---

# Agent Harness Construction

Use this skill when you are improving how an agent plans, calls tools, recovers from errors, and converges on completion.

## Core Model

Agent output quality is constrained by:
1. Action space quality
2. Observation quality
3. Recovery quality
4. Context budget quality

## Action Space Design

1. Use stable, explicit tool names.
2. Keep inputs schema-first and narrow.
3. Return deterministic output shapes.
4. Avoid catch-all tools unless isolation is impossible.

## Granularity Rules

- Use micro-tools for high-risk operations (deploy, migration, permissions).
- Use medium tools for common edit/read/search loops.
- Use macro-tools only when round-trip overhead is the dominant cost.

## Observation Design

Every tool response should include:
- `status`: success|warning|error
- `summary`: one-line result
- `next_actions`: actionable follow-ups
- `artifacts`: file paths / IDs

## Error Recovery Contract

For every error path, include:
- root cause hint
- safe retry instruction
- explicit stop condition

## Context Budgeting

1. Keep system prompt minimal and invariant.
2. Move large guidance into skills loaded on demand.
3. Prefer references to files over inlining long documents.
4. Compact at phase boundaries, not arbitrary token thresholds.

## Architecture Pattern Guidance

- ReAct: best for exploratory tasks with uncertain path.
- Function-calling: best for structured deterministic flows.
- Hybrid (recommended): ReAct planning + typed tool execution.

## Benchmarking

Track:
- completion rate
- retries per task
- pass@1 and pass@3
- cost per successful task

## Concrete Example: Well-designed vs. Poorly-designed Tool

### Poorly-designed (too broad, opaque output)
```json
// Tool definition — catch-all, no schema constraints
{
  "name": "do_database_thing",
  "description": "Does stuff with the database",
  "parameters": { "input": { "type": "string" } }
}

// Tool output — raw, no recovery hints
"Error: connection refused at 10.0.0.1:5432"
```

### Well-designed (narrow schema, structured observation)
```json
// Tool definition — explicit, scoped
{
  "name": "query_users",
  "description": "Run a read-only SELECT query on the users table",
  "parameters": {
    "where_clause": { "type": "string", "description": "SQL WHERE clause, e.g. \"status = 'active'\"" },
    "limit": { "type": "integer", "default": 50, "maximum": 500 }
  }
}

// Tool output — structured observation
{
  "status": "error",
  "summary": "Database connection refused",
  "root_cause": "PostgreSQL not reachable at DB_HOST=10.0.0.1:5432",
  "next_actions": ["Check DB_HOST env var", "Verify database service is running: `systemctl status postgresql`"],
  "artifacts": [],
  "stop_condition": "Do not retry more than 2 times; escalate if still failing"
}
```

## Anti-Patterns

- Too many tools with overlapping semantics.
- Opaque tool output with no recovery hints.
- Error-only output without next steps.
- Context overloading with irrelevant references.
