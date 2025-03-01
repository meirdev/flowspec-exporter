import sqlite3

import polars as pl
import streamlit as st
from streamlit_autorefresh import st_autorefresh

REFRESH_RATE = 60

db_conn = sqlite3.connect("db.sqlite")

st.set_page_config(layout="wide")

st_autorefresh(interval=REFRESH_RATE * 1000)

placeholder = st.empty()

with placeholder.container():
    df = pl.read_database(
        query="SELECT * FROM flowspecs WHERE timestamp > DATETIME('now', '-4 hours')",
        connection=db_conn,
    )

    if df.is_empty():
        st.write("No data available")
    else:
        router = st.selectbox("Router", df.select("router").unique())

        df_router = df.filter(pl.col("router") == router).with_columns(pl.col("timestamp").str.to_datetime()).select(
            "timestamp",
            "router",
            "filter",
            "dropped_bytes",
            "dropped_packets",
        )

        if df_router.is_empty():
            st.write("No data available")
        else:
            df_router_ = (
                df_router.select(
                    "timestamp",
                    "filter",
                    pl.col("timestamp")
                    .diff()
                    .over("filter", order_by="timestamp")
                    .alias("diff_timestamp"),
                    pl.col("dropped_bytes")
                    .diff()
                    .over("filter", order_by="timestamp")
                    .alias("diff_dropped_bytes"),
                    pl.col("dropped_packets")
                    .diff()
                    .over("filter", order_by="timestamp")
                    .alias("diff_dropped_packets"),
                )
                .with_columns(
                    pl.when(pl.col("diff_dropped_bytes") < 0)
                    .then(0)
                    .otherwise(pl.col("diff_dropped_bytes"))
                    .alias("diff_dropped_bytes"),
                    pl.when(pl.col("diff_dropped_packets") < 0)
                    .then(0)
                    .otherwise(pl.col("diff_dropped_packets"))
                    .alias("diff_dropped_packets"),
                )
                .with_columns(
                    (
                        pl.col("diff_dropped_bytes")
                        // pl.col("diff_timestamp").dt.total_seconds()
                        // 1e6
                    ).alias("dropped_mbps"),
                    (
                        pl.col("diff_dropped_packets")
                        // pl.col("diff_timestamp").dt.total_seconds()
                    ).alias("dropped_pps"),
                )
            )

            col1, col2 = st.columns(2)

            with col1:
                st.write("Dropped Traffic")
                st.line_chart(
                    df_router_.select("timestamp", "dropped_mbps", "filter"),
                    x_label="Time",
                    y_label="Mb/s",
                    x="timestamp",
                    y="dropped_mbps",
                    color="filter",
                )

            with col2:
                st.write("Dropped Packets")
                st.line_chart(
                    df_router_.select("timestamp", "dropped_pps", "filter"),
                    x_label="Time",
                    y_label="Packet/s",
                    x="timestamp",
                    y="dropped_pps",
                    color="filter",
                )

            df_router = df_router.group_by("filter").agg(
                pl.last("dropped_bytes"),
                pl.last("dropped_packets"),
                pl.last("timestamp"),
            )

            st.dataframe(
                df_router,
                use_container_width=True,
                column_order=[
                    "timestamp",
                    "filter",
                    "dropped_bytes",
                    "dropped_packets",
                ],
            )
