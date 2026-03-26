# reqs

blazing-fast HTTP/HTTPS benchmarking tool

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
