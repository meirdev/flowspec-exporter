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
            "matched_bytes",
            "matched_packets",
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
                    pl.col("matched_bytes")
                    .diff()
                    .over("filter", order_by="timestamp")
                    .alias("diff_matched_bytes"),
                    pl.col("matched_packets")
                    .diff()
                    .over("filter", order_by="timestamp")
                    .alias("diff_matched_packets"),
                )
                .with_columns(
                    pl.when(pl.col("diff_matched_bytes") < 0)
                    .then(0)
                    .otherwise(pl.col("diff_matched_bytes"))
                    .alias("diff_matched_bytes"),
                    pl.when(pl.col("diff_matched_packets") < 0)
                    .then(0)
                    .otherwise(pl.col("diff_matched_packets"))
                    .alias("diff_matched_packets"),
                )
                .with_columns(
                    (
                        pl.col("diff_matched_bytes")
                        // pl.col("diff_timestamp").dt.total_seconds()
                        // 1e6
                    ).alias("matched_mbps"),
                    (
                        pl.col("diff_matched_packets")
                        // pl.col("diff_timestamp").dt.total_seconds()
                    ).alias("matched_pps"),
                )
            )

            col1, col2 = st.columns(2)

            with col1:
                st.write("Traffic")
                st.line_chart(
                    df_router_.select("timestamp", "matched_mbps", "filter"),
                    x_label="Time",
                    y_label="Mb/s",
                    x="timestamp",
                    y="matched_mbps",
                    color="filter",
                )

            with col2:
                st.write("Packets")
                st.line_chart(
                    df_router_.select("timestamp", "matched_pps", "filter"),
                    x_label="Time",
                    y_label="Packet/s",
                    x="timestamp",
                    y="matched_pps",
                    color="filter",
                )

            df_router = df_router.group_by("filter").agg(
                pl.last("matched_bytes"),
                pl.last("matched_packets"),
                pl.last("timestamp"),
            )

            st.dataframe(
                df_router,
                use_container_width=True,
                column_order=[
                    "timestamp",
                    "filter",
                    "matched_bytes",
                    "matched_packets",
                ],
            )
