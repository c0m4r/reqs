<div align="center">

# reqs

![Linux](https://img.shields.io/badge/made%20for-linux-yellow?logo=linux&logoColor=ffffff) 
[![Rust](https://img.shields.io/badge/made%20with-Rust-orange?logo=rust&amp;logoColor=ffffff)](https://rust-lang.org/) 
[![License: GPL v3](https://img.shields.io/badge/License-AGPLv3-red.svg)](https://www.gnu.org/licenses/agpl-3.0)

Blazing-fast HTTP/HTTPS benchmarking tool

</div>

```js
reqs -c 500 -d 25s http://localhost/status
Running for 25.0s with 500 connections (32 thread(s), pipeline=1)
Target: http://localhost/status

────────────────────────────────────────────────────                    
  reqs results
────────────────────────────────────────────────────
  Target:     http://localhost/status
  Duration:   25.091s
  Threads:    32  |  Connections: 500  |  Pipeline: 1
────────────────────────────────────────────────────
  Requests:   8879817
  Completed:  8879817
  Failed:     0 (0.00%)
  Req/s:      353901.99
  Data recv:  982.34 MB
  Throughput: 39.15 MB/s
────────────────────────────────────────────────────
  Latency:
    Min    7µs
    Avg    1.405ms
    Max    325.471ms
    Stdev  1.381ms

  Percentiles:
    p50       1.379ms
    p75       1.400ms
    p90       1.432ms
    p95       1.566ms
    p99       2.041ms
    p99.9     2.901ms
────────────────────────────────────────────────────
```

<img width="730" height="248" alt="image" src="https://github.com/user-attachments/assets/0f5b3712-aefb-4325-8543-bdc0951b2ed9" />

## Install

https://github.com/c0m4r/reqs/releases

Available packages: x86_64, DEB, RPM

### Build from source

```bash
git clone https://github.com/c0m4r/reqs.git
cd reqs
cargo build --release
./target/release/reqs --help
```

## How to use

Run test for x seconds to check how muh req/s your server can handle

```bash
reqs -c 2 -d 5s -t 2 http://localhost/status
```

Run test until you reach given number of requests:

```bash
reqs -n 100 http://localhost/status
```

Usage:

```bash
reqs --help
```
