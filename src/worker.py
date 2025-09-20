import argparse
import asyncio
import logging
import sqlite3
import tomllib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import cast

import asyncssh
import tenacity
from pythonjsonlogger.json import JsonFormatter
from pytimeparse import parse as parse_time  # type: ignore

from src.parser import Platform, parse_flow_spec

DEFAULT_SCRAP_INTERVAL = "1m"
DEFAULT_SCRAP_TIMEOUT = "10s"

DEFAULT_SSH_PORT = 22

RETRY_INTERVAL = 10

logger = logging.getLogger("router-scraper-worker")

logger_handler = logging.StreamHandler()
logger_handler.setFormatter(JsonFormatter())
logger.addHandler(logger_handler)


@dataclass
class Router:
    name: str
    platform: str
    scrape_interval: str
    scrape_timeout: str
    ssh_host: str
    ssh_port: int
    ssh_username: str | None
    ssh_password: str | None
    ssh_command: str
    parameters: dict[str, str]


@tenacity.retry(
    wait=tenacity.wait_fixed(RETRY_INTERVAL),
    before=tenacity.before_log(logger, logging.DEBUG),
    after=tenacity.after_log(logger, logging.DEBUG),
)
async def scrape(db_conn: sqlite3.Connection, router: Router):
    scrape_interval = parse_time(router.scrape_interval)
    scrape_timeout = parse_time(router.scrape_timeout)

    assert scrape_interval is not None, "Invalid scrape interval"
    assert scrape_timeout is not None, "Invalid scrape timeout"

    logger.debug("Trying to connect to router", extra={"router": router.name})

    async with asyncssh.connect(
        router.ssh_host,
        port=router.ssh_port,
        username=router.ssh_username,
        password=router.ssh_password,
        known_hosts=None,
        connect_timeout=scrape_timeout,
    ) as conn:
        logger.debug("Connected to router", extra={"router": router.name})

        while True:
            entries = await parse_flow_spec(
                platform=cast(Platform, router.platform),
                connection=conn,
                **router.parameters,
            )

            logger.debug(
                "Parsed flow spec", extra={"router": router.name, "entries": entries}
            )

            now = datetime.now(timezone.utc)

            try:
                db_conn.executemany(
                    """
                    INSERT INTO flowspecs (
                        router,
                        timestamp,
                        filter,
                        matched_packets,
                        matched_bytes,
                        transmitted_packets,
                        transmitted_bytes,
                        dropped_packets,
                        dropped_bytes
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        [
                            router.name,
                            str(now),
                            entry.str_filter(),
                            entry.matched_packets,
                            entry.matched_bytes,
                            entry.transmitted_packets,
                            entry.transmitted_bytes,
                            entry.dropped_packets,
                            entry.dropped_bytes,
                        ]
                        for entry in entries
                    ],
                )
                db_conn.commit()
            except Exception as e:
                logger.error(
                    "Failed to insert flow spec data into database",
                    extra={"error": str(e)},
                )

            await asyncio.sleep(scrape_interval)


async def main() -> None:
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

    routers: list[Router] = []

    for router in config["routers"]:
        routers.append(
            Router(
                name=router["name"],
                platform=router["platform"],
                scrape_interval=router.get("scrape_interval", DEFAULT_SCRAP_INTERVAL),
                scrape_timeout=router.get("scrape_timeout", DEFAULT_SCRAP_TIMEOUT),
                ssh_host=router["ssh_host"],
                ssh_port=router.get("ssh_port", DEFAULT_SSH_PORT),
                ssh_username=router.get("ssh_username"),
                ssh_password=router.get("ssh_password"),
                ssh_command=router["ssh_command"],
                parameters=router.get("parameters", {}),
            )
        )

    logger.debug("Starting router scraper worker", extra={"routers": routers})

    db_conn = sqlite3.connect("db.sqlite")

    db_conn.executescript("""
    CREATE TABLE IF NOT EXISTS flowspecs (
        router TEXT,
        timestamp TIMESTAMP,
        filter TEXT,
        matched_packets INT,
        matched_bytes INT,
        transmitted_packets INT,
        transmitted_bytes INT,
        dropped_packets INT,
        dropped_bytes  INT
    );
    
    CREATE INDEX IF NOT EXISTS idx_flowspecs ON flowspecs (router, filter, timestamp DESC);
    """)
    db_conn.commit()

    async with asyncio.TaskGroup() as tg:
        for router in routers:
            tg.create_task(scrape(db_conn, router))


if __name__ == "__main__":
    asyncio.run(main())
