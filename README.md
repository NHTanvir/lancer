# Lancer

A Rust-native web-application security testing suite. Goal: match every feature of
Burp Suite (Community + Professional) and surpass on speed.

> **Status:** Early development. See `plan.md` for the complete feature roadmap.

## Architecture

Lancer is a Cargo workspace:

| Crate              | Responsibility                                                    |
|--------------------|-------------------------------------------------------------------|
| `lancer-core`      | Shared HTTP types, scope rules, project metadata, error types     |
| `lancer-storage`   | SQLite-backed history, project files, configuration library      |
| `lancer-proxy`     | TLS MITM proxy, CA management, interception, match-and-replace    |
| `lancer-tools`     | Repeater, Decoder, Comparer, Sequencer, Intruder                  |
| `lancer-scanner`   | Passive + active scanner, Collaborator client                     |
| `lancer-script`    | Bambda-equivalent scripting (Rhai-based)                          |
| `lancer-cli`       | Headless CLI entrypoint                                           |

## Quick start

```bash
# Build everything
cargo build --release

# Generate a CA and install it in the system trust store (one-time)
cargo run --release -- cert init
cargo run --release -- cert export --der ca.der

# Run the proxy on the default port (8080)
cargo run --release -- proxy --listen 127.0.0.1:8080 \
    --project ./demo.lancer

# Inspect captured history
cargo run --release -- history list --project ./demo.lancer
```

## Tech stack

- `tokio` async runtime
- `hyper` 1.x for HTTP/1.1 and HTTP/2
- `rustls` 0.23 for TLS (no OpenSSL dependency)
- `rcgen` for on-the-fly leaf certificate generation
- `sqlx` + SQLite for project files
- `rhai` for in-app scripting (Bambda equivalent)
- `clap` for the CLI; Tauri shell planned for the GUI

## License

Dual-licensed under MIT or Apache-2.0, at your option.
