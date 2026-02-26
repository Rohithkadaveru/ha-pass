"""Fix access_log foreign key: nullable token_id with ON DELETE SET NULL.

The 001 migration used CREATE TABLE IF NOT EXISTS, which was a no-op on
databases created before Alembic was introduced.  The original access_log
schema had ``token_id TEXT NOT NULL REFERENCES tokens(id)`` — missing the
ON DELETE SET NULL clause and incorrectly marked NOT NULL.  This causes
sqlite3.IntegrityError when deleting tokens that have access_log rows.

SQLite cannot ALTER foreign-key constraints in place, so we recreate the
table.

Revision ID: 002
Revises: 001
Create Date: 2026-02-25
"""
from typing import Sequence, Union

from alembic import op

revision: str = "002"
down_revision: Union[str, None] = "001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # SQLite table-rebuild dance: rename → create correct → copy → drop old
    op.execute("ALTER TABLE access_log RENAME TO _access_log_old")
    op.execute("""
        CREATE TABLE access_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            token_id    TEXT REFERENCES tokens(id) ON DELETE SET NULL,
            timestamp   INTEGER NOT NULL,
            event_type  TEXT NOT NULL,
            entity_id   TEXT,
            service     TEXT,
            ip_address  TEXT,
            user_agent  TEXT
        )
    """)
    op.execute("""
        INSERT INTO access_log (id, token_id, timestamp, event_type, entity_id, service, ip_address, user_agent)
        SELECT id, token_id, timestamp, event_type, entity_id, service, ip_address, user_agent
        FROM _access_log_old
    """)
    op.execute("DROP TABLE _access_log_old")
    op.execute("CREATE INDEX IF NOT EXISTS idx_access_log_token_id ON access_log(token_id)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_access_log_timestamp ON access_log(timestamp)")


def downgrade() -> None:
    op.execute("ALTER TABLE access_log RENAME TO _access_log_old")
    op.execute("""
        CREATE TABLE access_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            token_id    TEXT NOT NULL REFERENCES tokens(id),
            timestamp   INTEGER NOT NULL,
            event_type  TEXT NOT NULL,
            entity_id   TEXT,
            service     TEXT,
            ip_address  TEXT,
            user_agent  TEXT
        )
    """)
    op.execute("""
        INSERT INTO access_log (id, token_id, timestamp, event_type, entity_id, service, ip_address, user_agent)
        SELECT id, token_id, timestamp, event_type, entity_id, service, ip_address, user_agent
        FROM _access_log_old
        WHERE token_id IS NOT NULL
    """)
    op.execute("DROP TABLE _access_log_old")
    op.execute("CREATE INDEX IF NOT EXISTS idx_access_log_token_id ON access_log(token_id)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_access_log_timestamp ON access_log(timestamp)")
