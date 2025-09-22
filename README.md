# FlowSpec parser

A parser for BGP FlowSpec rules as they appear in the routers output.

## How to use

- Install the dependencies:

```bash
uv sync --all-extras
```

- Edit the `config.toml` with your own values.

- Make sure you have a PostgreSQL database running:

```bash
docker run -d --name timescaledb -p 5432:5432 -e POSTGRES_PASSWORD=password timescale/timescaledb-ha:pg17
```

- Run the worker:

```bash
python -m src.worker
```

- Open the web interface:

```bash
python -m streamlit run ./src/app.py
```
