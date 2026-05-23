# Lancer GUI — Svelte frontend

Drop-in SPA. Pages: Proxy, History, Repeater, Intruder, Scanner, Issues,
Reports, Palette, Settings.

## Dev loop

```bash
cd crates/lancer-gui/web
npm install
npm run dev    # http://127.0.0.1:5173 with /api proxied to lancer-api on :9191
```

Run the API in another terminal:

```bash
cargo run --release --bin lancer-api -- --listen 127.0.0.1:9191 --project ./demo.lancer
```

## Production build

```bash
cd crates/lancer-gui/web
npm run build  # outputs to ../dist
```

Then either:

- serve `../dist/` directly out of `lancer-api` (statics handler — todo), or
- embed it with `include_dir!` into `lancer-gui` for the Tauri shell:
  ```rust
  static FRONTEND: include_dir::Dir = include_dir::include_dir!("dist");
  ```
