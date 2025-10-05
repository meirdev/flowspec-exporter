# FlowSpec Exporter

A tool to export FlowSpec rules from routers and parse them into a structured format.

You can either collect the data directly into a PostgreSQL database or export it and use Prometheus to scrape it.

## Supported Routers

- Cisco IOS
- Juniper JunOS
- Huawei VRP

## Kwown Issues / Limitations

- Long rules may be truncated in the routers output. Hence, the parser may not be able to parse them correctly.
- Routers can interpret rules differently. So even if you send the same rule to different routers, they may appear differently in the output.

## How to Use

- Install the dependencies:

```bash
uv sync --extra all
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
