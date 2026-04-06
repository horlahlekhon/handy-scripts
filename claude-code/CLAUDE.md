# Claude Code Global Config

## About Me

Staff/Principal Engineer. Python, Java, Go, TypeScript, Scala.
Skip basics — I know my tools. Short answers. No preamble or trailing summaries.
Complete working code with imports when writing code, not partial snippets.

### Stack
- **Python**: FastAPI, Django, SQLAlchemy, Tortoise ORM, FastStream, asyncio
- **Java**: Spring Boot, Quarkus (CDI preferred over Spring annotations)
- **Go / TypeScript**: standard patterns
- **Scala**: functional style
- **Databases**: PostgreSQL, MySQL, MongoDB, Redis
- **Architecture**: CQRS, DDD, event-driven
- **Cloud**: AWS (expert) — ECS, Lambda, S3, SQS/SNS, RDS, DynamoDB, etc.

## Cost & Token Discipline

- Prefer direct tool calls (Read, Grep, Glob) over spawning agents for simple lookups
- Spawn agents only for multi-step research or parallel independent tasks
- Keep context lean: avoid reading files you don't need, avoid re-reading what you've already seen
- Use `haiku` model for simple edits, summaries, and classification tasks when model choice is available

## Standards

Full rules live in `rules/` — load them only when relevant:
- `rules/common/` — applies to all projects
- `rules/python/`, `rules/java/`, `rules/golang/` — load for language-specific work

Core non-negotiables (always active, no need to check the rule file):
1. **Immutability** — never mutate; create new objects
2. **TDD** — write tests first; 80% line coverage minimum
3. **No hardcoded secrets** — env vars or secret manager only
4. **No silent errors** — never swallow exceptions without logging

## Skills (load on demand, not upfront)

| Trigger | Skill |
|---------|-------|
| New feature or bug fix | `tdd-workflow` |
| Python code | `python-patterns` + `python-testing` |
| Java/Spring Boot | `springboot-patterns` + `springboot-tdd` |
| API endpoint design | `api-design` |
| Node.js backend | `backend-patterns` |
| Deployment / CI | `deployment-patterns` |
| Logging, metrics, tracing | `monitoring-patterns` |
| Async / concurrency | `async-patterns` |
| Git branches / PRs | `git-branching` |
| PostgreSQL | `postgres-patterns` |
| Library/framework docs needed | `documentation-lookup` (Context7) |
| Frontend / UI | `frontend-design` |
| Multi-PR feature planning | `blueprint` |
| Unfamiliar codebase | `codebase-onboarding` |

## MCP Usage

- Enable ≤ 10 MCPs to protect context window
- **Always available**: `context7` (docs), `sequential-thinking` (complex reasoning)
- **On demand**: `github` for repo ops, `exa-web-search` for research, `playwright` for browser automation
- See `mcp/mcp-servers.json` for full server list and setup guide

## Default Workflow

1. Read existing code before writing — reuse before creating
2. Search GitHub / docs before implementing from scratch
3. Write tests first (RED), then implementation (GREEN), then refactor
4. Run security checklist before committing (`rules/common/security.md`)
5. Keep PRs under ~400 lines; one logical unit per PR
