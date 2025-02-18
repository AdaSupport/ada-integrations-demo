from collections import namedtuple
from contextlib import closing
from datetime import datetime
import sqlite3

Installation = namedtuple(
    "Installation",
    [
        "installation_id",
        "access_token",
        "refresh_token",
        "expiry_ts",
        "installation_secret",
        "installer_bot_handle",
    ],
)


def dt_adapter(dt):
    return dt.isoformat()


def dt_converter(val):
    return datetime.fromisoformat(val.decode("utf-8"))


sqlite3.register_adapter(datetime, dt_adapter)
sqlite3.register_converter("TIMESTAMP", dt_converter)

DB_URI = "file:memdb1?mode=memory&cache=shared"
# This connection is left open to retain the in-memory database
persistent_database_conn = sqlite3.connect(DB_URI, detect_types=sqlite3.PARSE_DECLTYPES)
with persistent_database_conn:
    persistent_database_conn.execute(
        """
        CREATE TABLE IF NOT EXISTS installations (
            installation_id TEXT PRIMARY KEY,
            access_token TEXT,
            refresh_token TEXT,
            expiry_ts TIMESTAMP,
            installation_secret TEXT,
            installer_bot_handle TEXT
        )
        """
    )


def get_installation(installation_id):
    with closing(sqlite3.connect(DB_URI, detect_types=sqlite3.PARSE_DECLTYPES)) as conn:
        with conn:
            return Installation(
                *conn.execute(
                    """
                    SELECT
                        installation_id,
                        access_token,
                        refresh_token,
                        expiry_ts,
                        installation_secret,
                        installer_bot_handle
                    FROM installations
                    WHERE installation_id = ?
                    """,
                    (installation_id,),
                ).fetchone()
            )


def insert_installation(
    installation_id,
    access_token,
    refresh_token,
    expiry_ts,
    installation_secret,
    installer_bot_handle,
):
    with closing(sqlite3.connect(DB_URI, detect_types=sqlite3.PARSE_DECLTYPES)) as conn:
        with conn:
            conn.execute(
                """
                INSERT INTO installations (
                    installation_id,
                    access_token,
                    refresh_token,
                    expiry_ts,
                    installation_secret,
                    installer_bot_handle
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    installation_id,
                    access_token,
                    refresh_token,
                    expiry_ts,
                    installation_secret,
                    installer_bot_handle,
                ),
            )


def update_installation(
    installation_id,
    access_token,
    refresh_token,
    expiry_ts,
    installation_secret,
    installer_bot_handle,
):
    with closing(sqlite3.connect(DB_URI, detect_types=sqlite3.PARSE_DECLTYPES)) as conn:
        with conn:
            conn.execute(
                """
                UPDATE installations
                SET
                    access_token = ?,
                    refresh_token = ?,
                    expiry_ts = ?,
                    installation_secret = ?,
                    installer_bot_handle = ?
                WHERE installation_id = ?
                """,
                (
                    access_token,
                    refresh_token,
                    expiry_ts,
                    installation_secret,
                    installer_bot_handle,
                    installation_id,
                ),
            )
            return Installation(
                installation_id,
                access_token,
                refresh_token,
                expiry_ts,
                installation_secret,
                installer_bot_handle,
            )


def delete_installation(installation_id):
    with closing(sqlite3.connect(DB_URI, detect_types=sqlite3.PARSE_DECLTYPES)) as conn:
        with conn:
            conn.execute(
                "DELETE FROM installations WHERE installation_id = ?",
                (installation_id,),
            )
