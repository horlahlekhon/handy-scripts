---
name: async-patterns
description: Async and concurrency patterns for Python (asyncio), Java (virtual threads, CompletableFuture), Go (goroutines, channels), and Node.js (event loop, async/await). Use when writing concurrent or non-blocking code.
origin: ECC
---

# Async & Concurrency Patterns

Language-specific patterns for writing correct, efficient asynchronous and concurrent code.

## When to Activate

- Writing async functions or coroutines
- Making parallel HTTP/database calls
- Using goroutines, channels, CompletableFuture, or asyncio
- Handling concurrent access to shared state
- Avoiding deadlocks, race conditions, or callback hell

## When NOT to Use This Skill

- General performance optimization — use `performance.md` rules
- Deployment-level scaling (load balancing, horizontal scaling) — use `deployment-patterns`

---

## Python — asyncio

### Core Pattern

```python
import asyncio

async def fetch_user(user_id: int) -> dict:
    async with httpx.AsyncClient() as client:
        response = await client.get(f"/users/{user_id}")
        return response.json()

# Run multiple coroutines concurrently
async def fetch_all(user_ids: list[int]) -> list[dict]:
    return await asyncio.gather(*[fetch_user(uid) for uid in user_ids])
```

### Common Pitfalls

| Pitfall | Fix |
|---------|-----|
| Calling blocking I/O inside `async def` | Use `await asyncio.to_thread(blocking_fn)` |
| Forgetting `await` | `asyncio.run()` will raise `RuntimeWarning: coroutine was never awaited` |
| Running `asyncio.run()` inside an existing event loop | Use `await` directly instead |
| Shared mutable state between coroutines | Use `asyncio.Lock()` to protect access |

### Gathering with Error Handling

```python
results = await asyncio.gather(*tasks, return_exceptions=True)
for result in results:
    if isinstance(result, Exception):
        logger.error("Task failed", exc_info=result)
    else:
        process(result)
```

### CPU-bound Work

`asyncio` is for I/O-bound work only. For CPU-bound tasks:
```python
import concurrent.futures

async def run_cpu_bound(data):
    loop = asyncio.get_event_loop()
    with concurrent.futures.ProcessPoolExecutor() as pool:
        return await loop.run_in_executor(pool, compute, data)
```

---

## Java — Virtual Threads & CompletableFuture

### Virtual Threads (Java 21+, preferred for I/O-bound work)

```java
// Virtual threads are cheap — create one per request/task
try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
    var future1 = executor.submit(() -> fetchUser(userId));
    var future2 = executor.submit(() -> fetchOrders(userId));
    User user = future1.get();
    List<Order> orders = future2.get();
}
```

Use virtual threads for: HTTP calls, database queries, file I/O — any blocking I/O.
Avoid for: CPU-intensive computation (use platform threads or `ForkJoinPool`).

### CompletableFuture (Java 8+, for complex async pipelines)

```java
CompletableFuture<UserProfile> profile = CompletableFuture
    .supplyAsync(() -> userService.find(userId))
    .thenApplyAsync(user -> enrichWithOrders(user))
    .thenApplyAsync(user -> enrichWithPreferences(user))
    .exceptionally(ex -> {
        log.error("Profile load failed for {}", userId, ex);
        return UserProfile.empty(userId);
    });

// Combine two independent futures
CompletableFuture<Void> both = CompletableFuture.allOf(future1, future2);
both.join(); // blocks until both complete
```

### Spring WebFlux (reactive, for high-throughput non-blocking)

Use Spring WebFlux (Mono/Flux) when:
- You need back-pressure (streaming data)
- Building a reactive pipeline that doesn't block threads

Avoid WebFlux when:
- Your team is unfamiliar with reactive programming
- The rest of the stack is blocking (JDBC, etc.)
- Virtual threads (Java 21) can achieve the same throughput more simply

---

## Go — Goroutines & Channels

### Basic Goroutine

```go
go func() {
    result, err := fetchUser(ctx, userID)
    if err != nil {
        log.Error("fetch failed", "user_id", userID, "error", err)
        return
    }
    process(result)
}()
```

### WaitGroup for Fan-Out

```go
var wg sync.WaitGroup
results := make([]User, len(userIDs))

for i, id := range userIDs {
    wg.Add(1)
    go func(idx int, userID string) {
        defer wg.Done()
        results[idx], _ = fetchUser(ctx, userID)
    }(i, id)
}
wg.Wait()
```

### Channels for Communication

```go
jobs := make(chan Job, 100)      // buffered channel
results := make(chan Result, 100)

// Worker pool
for w := 0; w < 5; w++ {
    go worker(ctx, jobs, results)
}

// Always close channels when done sending
close(jobs)
```

### Context Cancellation

```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel() // always defer cancel to avoid resource leaks

resp, err := http.NewRequestWithContext(ctx, "GET", url, nil)
```

### Common Mistakes

| Mistake | Fix |
|---------|-----|
| Goroutine leak (no cancel/done) | Always pass `ctx` and respect `ctx.Done()` |
| Race condition on shared map | Use `sync.Mutex` or `sync.Map` |
| Closing a nil channel | Initialize channels before use |
| Ignoring `select` default case | Use `default` to make `select` non-blocking |

---

## Node.js — Event Loop & async/await

### async/await (preferred over raw Promises)

```typescript
async function getOrderWithUser(orderId: string) {
    const [order, user] = await Promise.all([
        fetchOrder(orderId),
        fetchUser(orderId)  // if user ID is known independently
    ])
    return { order, user }
}
```

### Parallel vs. Sequential

```typescript
// SEQUENTIAL (slow — waits for each before starting next)
const user = await fetchUser(id)
const orders = await fetchOrders(id)

// PARALLEL (fast — both start at the same time)
const [user, orders] = await Promise.all([fetchUser(id), fetchOrders(id)])
```

### Error Handling

```typescript
// Wrap at the boundary, not inside each async call
async function handler(req: Request, res: Response) {
    try {
        const result = await processOrder(req.body)
        res.json(result)
    } catch (err) {
        logger.error('Order processing failed', { err, body: req.body })
        res.status(500).json({ error: 'Processing failed' })
    }
}
```

### Avoiding Callback Hell

```typescript
// BAD — nested callbacks
fetchUser(id, (user) => {
    fetchOrders(user.id, (orders) => {
        calculateTotal(orders, (total) => { ... })
    })
})

// GOOD — async/await
const user = await fetchUser(id)
const orders = await fetchOrders(user.id)
const total = await calculateTotal(orders)
```

### CPU-bound Work

Node.js is single-threaded. For CPU-intensive tasks, use `worker_threads`:
```typescript
import { Worker } from 'worker_threads'

const result = await new Promise((resolve, reject) => {
    const worker = new Worker('./compute-worker.js', { workerData: payload })
    worker.on('message', resolve)
    worker.on('error', reject)
})
```

---

## Done When

- No blocking I/O runs on the main thread (Node.js) or inside async coroutines (Python) without offloading
- Concurrent operations that can run in parallel use `gather`, `Promise.all`, `allOf`, or goroutines — not sequential `await`
- All goroutines/tasks have cancellation paths via context or cancellation tokens
- Shared mutable state is protected by a lock, mutex, or actor model
- Async code is tested with the async test helpers for the language (pytest-asyncio, JUnit async, etc.)
