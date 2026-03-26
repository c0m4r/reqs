# reqs

blazing-fast HTTP/HTTPS benchmarking tool

```js
reqs -c 100 -t 5 http://localhost/status
No -d or -n specified; defaulting to 10s
Running for 10.0s with 100 connections (5 thread(s), pipeline=1)
Target: http://localhost/status

────────────────────────────────────────────────────                    
  reqs results
────────────────────────────────────────────────────
  Target:     http://localhost/status
  Duration:   10.019s
  Threads:    5  |  Connections: 100  |  Pipeline: 1
────────────────────────────────────────────────────
  Requests:   3623017
  Completed:  3623017
  Failed:     0 (0.00%)
  Req/s:      361618.97
  Data recv:  400.70 MB
  Throughput: 39.99 MB/s
────────────────────────────────────────────────────
  Latency:
    Min    14µs
    Avg    274µs
    Max    11.347ms
    Stdev  49µs

  Percentiles:
    p50       270µs
    p75       273µs
    p90       277µs
    p95       287µs
    p99       395µs
    p99.9     616µs
────────────────────────────────────────────────────
```

## Build from source

```bash
git clone https://github.com/c0m4r/reqs.git
cd reqs
cargo build --release
./target/release/reqs --help
```

## Examples

Run test for x seconds to check how muh req/s your server can handle

```bash
./target/release/reqs -c 2 -d 5s -t 2 http://localhost/status
```

Run test until you reach given number of requests:

```bash
./target/release/reqs -n 100 http://localhost/status
```
