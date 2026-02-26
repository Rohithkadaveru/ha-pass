"""Initial schema.

Revision ID: 001
Revises:
Create Date: 2025-02-25
"""
from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS admin_sessions (
            id          TEXT PRIMARY KEY,
            created_at  INTEGER NOT NULL,
            expires_at  INTEGER NOT NULL
        )
    """)
    op.execute("""
        CREATE TABLE IF NOT EXISTS tokens (
            id              TEXT PRIMARY KEY,
            slug            TEXT UNIQUE NOT NULL,
            label           TEXT NOT NULL,
            created_at      INTEGER NOT NULL,
            expires_at      INTEGER NOT NULL,
            revoked         INTEGER NOT NULL DEFAULT 0,
            last_accessed   INTEGER,
            rate_limit_rpm  INTEGER NOT NULL DEFAULT 30,
            ip_allowlist    TEXT
        )
    """)
    op.execute("""
        CREATE TABLE IF NOT EXISTS token_entities (
            token_id    TEXT NOT NULL REFERENCES tokens(id) ON DELETE CASCADE,
            entity_id   TEXT NOT NULL,
            PRIMARY KEY (token_id, entity_id)
        )
    """)
    op.execute("""
        CREATE TABLE IF NOT EXISTS access_log (
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
    op.execute("CREATE INDEX IF NOT EXISTS idx_tokens_slug ON tokens(slug)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_tokens_expires_at ON tokens(expires_at)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_access_log_token_id ON access_log(token_id)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_access_log_timestamp ON access_log(timestamp)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_token_entities_token_id ON token_entities(token_id)")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS access_log")
    op.execute("DROP TABLE IF EXISTS token_entities")
    op.execute("DROP TABLE IF EXISTS tokens")
    op.execute("DROP TABLE IF EXISTS admin_sessions")
