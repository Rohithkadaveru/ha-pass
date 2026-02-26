"""Alembic environment configuration for HAPass.

Runs synchronous SQLite migrations using raw SQL (no SQLAlchemy models).
The database URL is derived from app.config.settings.db_path.
"""
from alembic import context
from sqlalchemy import create_engine

from app.config import settings

config = context.config

url = f"sqlite:///{settings.db_path}"
config.set_main_option("sqlalchemy.url", url)


def run_migrations_online() -> None:
    connectable = create_engine(url)
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=None)
        with context.begin_transaction():
            context.run_migrations()


run_migrations_online()
