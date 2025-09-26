import argparse
import logging
import tomllib
from dataclasses import dataclass, field
from typing import Any, cast

import asyncssh
import uvicorn
from fastapi import FastAPI, HTTPException, Response
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    generate_latest,
)
from pythonjsonlogger.json import JsonFormatter

from src.parser import Platform, parse_flow_spec

DEFAULT_SSH_PORT = 22

DEFAULT_SSH_CONNECT_TIMEOUT = 10

logger = logging.getLogger("flowspec-exporter")

logger_handler = logging.StreamHandler()
logger_handler.setFormatter(JsonFormatter())
logger.addHandler(logger_handler)

app = FastAPI()


class CustomCounter(Counter):
    def set(self, value: float) -> None:
        old_value = self._value.get()
        if value < old_value:
            self._value.set(value)
        else:
            self._value.inc(value - old_value)


@dataclass
class Router:
    platform: str
    ssh_host: str
    ssh_port: int
    ssh_username: str | None
    ssh_password: str | None
    ssh_kwargs: dict[str, Any]
    parameters: dict[str, str]

    collector_registry: CollectorRegistry = field(init=False)

    matched_packets: CustomCounter = field(init=False)
    matched_bytes: CustomCounter = field(init=False)
    transmitted_packets: CustomCounter = field(init=False)
    transmitted_bytes: CustomCounter = field(init=False)
    dropped_packets: CustomCounter = field(init=False)
    dropped_bytes: CustomCounter = field(init=False)

    filters: set[str] = field(init=False)

    def __post_init__(self) -> None:
        self.collector_registry = CollectorRegistry()

        self.matched_packets = CustomCounter(
            "matched_packets",
            "Number of matched packets",
            labelnames=["filter"],
            registry=self.collector_registry,
        )
        self.matched_bytes = CustomCounter(
            "matched_bytes",
            "Number of matched bytes",
            labelnames=["filter"],
            registry=self.collector_registry,
        )
        self.transmitted_packets = CustomCounter(
            "transmitted_packets",
            "Number of transmitted packets",
            labelnames=["filter"],
            registry=self.collector_registry,
        )
        self.transmitted_bytes = CustomCounter(
            "transmitted_bytes",
            "Number of transmitted bytes",
            labelnames=["filter"],
            registry=self.collector_registry,
        )
        self.dropped_packets = CustomCounter(
            "dropped_packets",
            "Number of dropped packets",
            labelnames=["filter"],
            registry=self.collector_registry,
        )
        self.dropped_bytes = CustomCounter(
            "dropped_bytes",
            "Number of dropped bytes",
            labelnames=["filter"],
            registry=self.collector_registry,
        )

        self.filters = set()


@app.get("/metrics")
async def metrics(target: str):
    if target not in app.extra:
        raise HTTPException(
            status_code=404,
            detail=f"Router '{target}' not found",
        )

    router: Router = app.extra[target]

    if "connect_timeout" not in router.ssh_kwargs:
        router.ssh_kwargs["connect_timeout"] = DEFAULT_SSH_CONNECT_TIMEOUT

    async with asyncssh.connect(
        host=router.ssh_host,
        port=router.ssh_port,
        username=router.ssh_username,
        password=router.ssh_password,
        known_hosts=None,
        **router.ssh_kwargs,
    ) as conn:
        logger.debug("Connected to router", extra={"host": router.ssh_host})

        entries = await parse_flow_spec(
            platform=cast(Platform, router.platform),
            connection=conn,
            **router.parameters,
        )

        logger.debug(
            "Parsed flow spec", extra={"host": router.ssh_host, "entries": entries}
        )

        active_filters = {entry.str_filter() for entry in entries}

        for i in router.filters - active_filters:
            router.matched_packets.labels(filter=i).remove()
            router.matched_bytes.labels(filter=i).remove()

            router.transmitted_packets.labels(filter=i).remove()
            router.transmitted_bytes.labels(filter=i).remove()

            router.dropped_packets.labels(filter=i).remove()
            router.dropped_bytes.labels(filter=i).remove()

        for entry in entries:
            filter = entry.str_filter()

            if (matched_packets := entry.matched_packets) is not None:
                router.matched_packets.labels(filter=filter).set(matched_packets)
            if (matched_bytes := entry.matched_bytes) is not None:
                router.matched_bytes.labels(filter=filter).set(matched_bytes)

            if (transmitted_packets := entry.transmitted_packets) is not None:
                router.transmitted_packets.labels(filter=filter).set(
                    transmitted_packets
                )
            if (transmitted_bytes := entry.transmitted_bytes) is not None:
                router.transmitted_bytes.labels(filter=filter).set(transmitted_bytes)

            if (dropped_packets := entry.dropped_packets) is not None:
                router.dropped_packets.labels(filter=filter).set(dropped_packets)
            if (dropped_bytes := entry.dropped_bytes) is not None:
                router.dropped_bytes.labels(filter=filter).set(dropped_bytes)

        router.filters.update(active_filters)

    data = generate_latest(router.collector_registry)

    return Response(
        content=data,
        media_type=CONTENT_TYPE_LATEST,
    )


if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument(
        "config",
        nargs="?",
        type=argparse.FileType("rb"),
        default=open("config.toml", "rb"),
    )
    arg_parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )

    args = arg_parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)

    with args.config as fp:
        config = tomllib.load(fp)

    app.extra = {}

    for router in config["routers"]:
        app.extra[router["name"]] = Router(
            platform=router["platform"],
            ssh_host=router["ssh_host"],
            ssh_port=router.get("ssh_port", DEFAULT_SSH_PORT),
            ssh_username=router.get("ssh_username"),
            ssh_password=router.get("ssh_password"),
            ssh_kwargs=router.get("ssh_kwargs", {}),
            parameters=router.get("parameters", {}),
        )

    uvicorn.run(app)
