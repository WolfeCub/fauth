# fauth

## Local testing

### Docker

```bash
docker compose up --build
```

### Locally
Alternatively you can run each service individually locally for faster development. Firstly in the `api` directory run:

```bash
FAUTH_CONFIG=../example_config.yaml cargo run
```

Then in the `ui` directory run

```bash
pnpm build -w
```
