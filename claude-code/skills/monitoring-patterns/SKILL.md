---
name: monitoring-patterns
description: Structured logging, metrics (Prometheus), distributed tracing (OpenTelemetry), health check endpoints, and alerting principles for production services.
origin: ECC
---

# Monitoring & Observability Patterns

Production observability through structured logging, metrics, tracing, and health checks.

## When to Activate

- Adding logging to a service
- Setting up Prometheus metrics or Micrometer
- Implementing health check endpoints
- Adding distributed tracing (OpenTelemetry, Jaeger, Zipkin)
- Designing alerting rules or SLOs
- Debugging production issues using observability data

## When NOT to Use This Skill

- Application-level testing — use `tdd-workflow` or language-specific testing skills
- Deployment pipelines — use `deployment-patterns`

---

## 1. Structured Logging

Log in JSON so entries are machine-parseable and searchable.

### Required Fields

Every log entry must include:

| Field | Description |
|-------|-------------|
| `timestamp` | ISO 8601, e.g. `2026-04-06T10:00:00Z` |
| `level` | `DEBUG`, `INFO`, `WARN`, `ERROR` |
| `service` | Service/app name |
| `trace_id` | Distributed trace ID (if tracing enabled) |
| `message` | Human-readable description |

### Log Levels

| Level | When to use |
|-------|-------------|
| `DEBUG` | Detailed diagnostic info; disabled in production |
| `INFO` | Normal operations: request received, job started/finished |
| `WARN` | Unexpected but recoverable: retry triggered, cache miss, config fallback |
| `ERROR` | Unrecoverable within request: exception thrown, external call failed |

**Never log sensitive data** (passwords, tokens, PII) at any level.

### Examples

**Python (structlog)**
```python
import structlog

log = structlog.get_logger()

log.info("order.placed", order_id=order.id, user_id=user.id, total=str(order.total))
log.error("payment.failed", order_id=order.id, reason=str(e), exc_info=True)
```

**Java (SLF4J + Logback JSON encoder)**
```java
// logback-spring.xml: use logstash-logback-encoder for JSON output
log.info("order.placed orderId={} userId={} total={}", order.getId(), userId, order.getTotal());
log.error("payment.failed orderId={}", order.getId(), e);
```

**Go (slog, stdlib since 1.21)**
```go
slog.Info("order placed", "order_id", order.ID, "user_id", userID, "total", order.Total)
slog.Error("payment failed", "order_id", order.ID, "error", err)
```

**Node.js (pino)**
```typescript
const log = pino({ level: 'info' })
log.info({ orderId: order.id, userId }, 'order.placed')
log.error({ orderId: order.id, err }, 'payment.failed')
```

---

## 2. Metrics

Use **Prometheus** conventions (or an adapter like Micrometer for JVM).

### Metric Types

| Type | Use for |
|------|---------|
| Counter | Monotonically increasing events: requests, errors, retries |
| Gauge | Current value: queue depth, active connections, cache size |
| Histogram | Distribution of values: request latency, payload size |

### Naming Conventions

```
# Pattern: namespace_subsystem_unit
http_requests_total              # counter
http_request_duration_seconds    # histogram
db_connections_active            # gauge
```

### Key Metrics to Track

- `http_requests_total{method, path, status}` — request count by outcome
- `http_request_duration_seconds{method, path}` — latency histogram
- `db_query_duration_seconds{query_name}` — database latency
- `cache_hits_total` / `cache_misses_total` — cache effectiveness
- `queue_depth` — pending work

---

## 3. Health Check Endpoints

Expose two endpoints for orchestrators (Kubernetes, load balancers):

| Endpoint | Purpose | Returns 200 when... |
|----------|---------|---------------------|
| `GET /health` | Liveness | Process is running (not deadlocked) |
| `GET /ready` | Readiness | Service can accept traffic (DB connected, cache warm) |

```python
# FastAPI example
@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/ready")
def ready():
    try:
        db.execute("SELECT 1")
        return {"status": "ready"}
    except Exception as e:
        raise HTTPException(status_code=503, detail=str(e))
```

---

## 4. Distributed Tracing (OpenTelemetry)

Use OpenTelemetry (OTel) for cross-service request tracing.

### Auto-instrumentation (preferred)

Most frameworks support zero-code instrumentation:
```bash
# Python
opentelemetry-instrument --traces_exporter otlp python app.py

# Java
java -javaagent:opentelemetry-javaagent.jar -jar app.jar

# Node.js
node --require @opentelemetry/auto-instrumentations-node/register app.js
```

### Manual Spans (for business-critical paths)

```python
from opentelemetry import trace

tracer = trace.get_tracer("order-service")

with tracer.start_as_current_span("process-payment") as span:
    span.set_attribute("order.id", order_id)
    span.set_attribute("payment.amount", amount)
    result = payment_gateway.charge(order_id, amount)
    span.set_attribute("payment.status", result.status)
```

### Propagate Trace Context

Always forward trace headers (`traceparent`, `X-B3-TraceId`) in outgoing HTTP calls.

---

## 5. Alerting Principles

- **Alert on symptoms, not causes**: alert on `error_rate > 5%`, not `cpu > 80%`
- **SLO-based alerts**: define error budgets; alert when burn rate is high
- **Avoid alert fatigue**: every alert must be actionable; silence noisy alerts
- **Two-window burn rate**: fast burn (short window, high severity) + slow burn (long window, warning)

### Common SLOs

| Signal | Target |
|--------|--------|
| HTTP success rate | ≥ 99.9% |
| P99 latency | ≤ 500ms |
| Availability | ≥ 99.5% |

---

## Done When

- All log statements use a structured logger (not `print` or unformatted strings)
- Required log fields (`timestamp`, `level`, `service`, `message`) are present
- Key metrics (request count, latency, error rate) are instrumented
- `/health` and `/ready` endpoints respond correctly
- No sensitive data (tokens, passwords, PII) appears in logs
- Tracing is enabled and `trace_id` propagates across service calls
