#!/usr/bin/env python

"""
ONLY TO BE USED IN DEVELOPMENT!

This script creates the databases of this applicatoin if they do not exist.
"""

import os

import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

from src.utils.shared import LOGGER


def create_database(
    db_name: str, db_user: str, db_password: str, db_host: str, db_port: str
):
    """
    Create a PostgreSQL database if it does not exist.
    """
    conn_info = f"dbname='postgres' user='{db_user}' password='{db_password}' host='{db_host}' port='{db_port}'"

    try:
        # connect to the PostgreSQL server
        conn = psycopg2.connect(conn_info)
        conn.set_isolation_level(
            ISOLATION_LEVEL_AUTOCOMMIT
        )  # set isolation level to autocommit so we can create a database
        cur = conn.cursor()

        # check if database exists
        cur.execute(
            "SELECT 1 FROM pg_catalog.pg_database WHERE datname = %s", (db_name,)
        )
        exists = cur.fetchone()  # returns None if database does not exist
        if not exists:
            # execute SQL query to create a database if it does not exist
            cur.execute(f"CREATE DATABASE {db_name}")
            LOGGER.info(f"Database {db_name} created successfully.")
        else:
            LOGGER.info(f"Database {db_name} already exists.")

        cur.close()

    except Exception as e:
        LOGGER.error(f"An error occurred: {e}")

    finally:
        if conn:
            conn.close()


if __name__ == "__main__":
    # get database info from environment variables
    db_name = os.getenv("DATABASE_NAME")
    db_user = os.getenv("DATABASE_USER")
    db_password = os.getenv("DATABASE_PASSWORD")
    db_host = os.getenv("DATABASE_HOST")
    db_port = os.getenv("DATABASE_PORT")

    pytest_db_name = os.getenv("PYTEST_DATABASE_NAME")
    pytest_db_user = os.getenv("PYTEST_DATABASE_USER")
    pytest_db_password = os.getenv("PYTEST_DATABASE_PASSWORD")
    pytest_db_host = os.getenv("PYTEST_DATABASE_HOST")
    pytest_db_port = os.getenv("PYTEST_DATABASE_PORT")

    # create the databases if they do not exist
    create_database(db_name, db_user, db_password, db_host, db_port)
    create_database(
        pytest_db_name,
        pytest_db_user,
        pytest_db_password,
        pytest_db_host,
        pytest_db_port,
    )
