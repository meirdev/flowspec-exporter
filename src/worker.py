import argparse
import asyncio
import logging
import tomllib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, cast

import asyncpg
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
    ssh_kwargs: dict[str, Any]
    parameters: dict[str, str]


@tenacity.retry(
    wait=tenacity.wait_fixed(RETRY_INTERVAL),
    reraise=True,
    before=tenacity.before_log(logger, logging.DEBUG),
    after=tenacity.after_log(logger, logging.DEBUG),
    before_sleep=tenacity.before_sleep_log(logger, logging.DEBUG),
)
async def scrape(db_conn: asyncpg.Connection, router: Router):
    scrape_interval = parse_time(router.scrape_interval)
    scrape_timeout = parse_time(router.scrape_timeout)

    assert scrape_interval is not None, "Invalid scrape interval"
    assert scrape_timeout is not None, "Invalid scrape timeout"

    logger.debug("Trying to connect to router", extra={"router": router.name})

    while True:
        async with asyncssh.connect(
            router.ssh_host,
            port=router.ssh_port,
            username=router.ssh_username,
            password=router.ssh_password,
            known_hosts=None,
            connect_timeout=scrape_timeout,
            **router.ssh_kwargs,
        ) as conn:
            logger.debug("Connected to router", extra={"router": router.name})

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
                await db_conn.executemany(
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
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                    """,
                    [
                        [
                            router.name,
                            now,
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
    arg_parser.add_argument(
        "--connection",
        help="Database connection string",
        default="postgresql://postgres:password@localhost/postgres",
    )
    arg_parser.add_argument(
        "--tigerdata",
        action="store_true",
        help="Use TigerData for database connection",
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
                ssh_kwargs=router.get("ssh_kwargs", {}),
                parameters=router.get("parameters", {}),
            )
        )

    logger.debug("Starting router scraper worker", extra={"routers": routers})

    db_conn: asyncpg.Connection = await asyncpg.connect(args.connection)

    await db_conn.execute("""
    CREATE TABLE IF NOT EXISTS flowspecs (
        router text not null,
        filter text not null,
        timestamp timestamptz not null,
        matched_packets bigint,
        matched_bytes bigint,
        transmitted_packets bigint,
        transmitted_bytes bigint,
        dropped_packets bigint,
        dropped_bytes bigint,
        primary key (router, filter, timestamp)
    );
    """)

    if args.tigerdata:
        await db_conn.execute("""
        SELECT create_hypertable('flowspecs', by_range('timestamp'), if_not_exists => TRUE);
        """)

    await db_conn.execute("""
    CREATE INDEX IF NOT EXISTS flowspecs_router_filter_timestamp_idx ON flowspecs (router, filter, timestamp DESC);
    """)

    async with asyncio.TaskGroup() as tg:
        for router in routers:
            tg.create_task(scrape(db_conn, router))


if __name__ == "__main__":
    asyncio.run(main())
