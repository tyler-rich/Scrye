"""Migration-vs-metadata drift test (QUA-23).

`tests/conftest.py` builds the schema with ``Base.metadata.create_all`` for
speed, which means a migration that drifts from the models would pass the rest of
the suite unnoticed. This test runs the **actual Alembic chain** to head against a
throwaway database and asserts the resulting tables/columns match the SQLAlchemy
metadata, so an added/dropped/renamed table or column that a migration forgot is
caught.
"""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import create_engine, inspect

from alembic import command
from alembic.config import Config
from app.db.base import Base

_BACKEND_DIR = Path(__file__).resolve().parent.parent


def _alembic_config(database_url: str) -> Config:
    """Build an Alembic config pinned to a specific database URL."""
    cfg = Config(str(_BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(_BACKEND_DIR / "alembic"))
    cfg.set_main_option("sqlalchemy.url", database_url)
    return cfg


def test_alembic_head_matches_models(tmp_path: Path) -> None:
    """`alembic upgrade head` must produce the same tables/columns as the models."""
    db_file = tmp_path / "migration_check.db"
    url = f"sqlite:///{db_file}"

    command.upgrade(_alembic_config(url), "head")

    engine = create_engine(url)
    try:
        inspector = inspect(engine)
        db_tables = set(inspector.get_table_names()) - {"alembic_version"}
        model_tables = set(Base.metadata.tables)
        assert db_tables == model_tables, (
            "migration/model table drift: "
            f"only in DB={db_tables - model_tables}, only in models={model_tables - db_tables}"
        )
        for table in model_tables:
            db_cols = {col["name"] for col in inspector.get_columns(table)}
            model_cols = set(Base.metadata.tables[table].columns.keys())
            assert db_cols == model_cols, (
                f"migration/model column drift in {table!r}: "
                f"only in DB={db_cols - model_cols}, only in models={model_cols - db_cols}"
            )
    finally:
        engine.dispose()
