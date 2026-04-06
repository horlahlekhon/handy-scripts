# Security Guidelines

## Mandatory Security Checks

Before ANY commit:
- [ ] No hardcoded secrets (API keys, passwords, tokens)
- [ ] All user inputs validated
- [ ] SQL injection prevention (parameterized queries)
- [ ] XSS prevention (sanitized HTML)
- [ ] CSRF protection enabled
- [ ] Authentication/authorization verified
- [ ] Rate limiting on all endpoints
- [ ] Error messages don't leak sensitive data

## Secret Management

- NEVER hardcode secrets in source code
- ALWAYS use environment variables or a secret manager
- Validate that required secrets are present at startup
- Rotate any secrets that may have been exposed

## Dependency Scanning

Scan for vulnerable dependencies before shipping:
- **Python**: `pip-audit` or `pip install safety && safety check`
- **Go**: `govulncheck ./...` (install: `go install golang.org/x/vuln/cmd/govulncheck@latest`)
- **Java (Maven)**: `mvn dependency-check:check` (OWASP plugin)
- **Java (Gradle)**: `gradle dependencyCheckAnalyze`

## Error Message Policy

- Error messages returned to clients must NOT reveal internal stack traces, file paths, or system details
- Log full error details server-side; return only a generic message or error code to the client
- Example: return `{"error": "Order not found"}`, not `{"error": "NullPointerException at OrderService.java:42"}`

## Security Response Protocol

If security issue found:
1. STOP immediately
2. Use **security-reviewer** agent
3. Fix CRITICAL issues before continuing
4. Rotate any exposed secrets
5. Review entire codebase for similar issues
