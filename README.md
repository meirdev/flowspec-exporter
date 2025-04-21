# FlowSpec parser

A parser for BGP FlowSpec rules as they appear in the routers output.

## How to use

- Install the dependencies:

```bash
uv sync --all-extras
```

- Edit the `config.toml` with your own values.

- Run the worker:

```bash
python -m src.worker
```

- Open the web interface:

```bash
python -m streamlit run ./src/app.py
```
