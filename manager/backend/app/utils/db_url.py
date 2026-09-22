"""Coerce the shared ``DB_URL`` env var to the scheme each consumer needs.

manager/backend has two ``DB_URL`` consumers with incompatible connection
-string conventions for the *same* value: ``alembic/env.py`` talks to the
database through raw SQLAlchemy (``create_engine``), which requires the
standard dialect scheme (``postgresql://``, ``sqlite:///`` for a relative
path); ``app/db.py`` and the ``*_service.py`` modules talk to it through
penguin-dal, which accepts the PyDAL-style shorthand (``postgres://``,
``sqlite://`` 2-slash) and normalizes it internally
(``penguin_dal.backends.normalize_uri``).

Only the SQLAlchemy side needs coercion here: penguin-dal already
normalizes PyDAL-style input on its own, and re-normalizing a URL that is
already in SQLAlchemy form there double-adds a slash (a latent penguin-dal
quirk, out of scope for this service) -- so consumers going through
penguin-dal must keep passing ``DB_URL`` through unchanged.
"""

from __future__ import annotations

_MEMORY_ALIASES = frozenset({"sqlite:memory:", "sqlite://:memory:"})

# (PyDAL-style prefix, SQLAlchemy-style prefix)
_PYDAL_TO_SQLALCHEMY_PREFIXES: tuple[tuple[str, str], ...] = (
    ("postgres://", "postgresql://"),
    ("sqlite://", "sqlite:///"),
)


def to_sqlalchemy_url(url: str) -> str:
    """Coerce a shared DB_URL to the scheme SQLAlchemy/Alembic requires.

    Idempotent: a URL already in SQLAlchemy form (``postgresql://``,
    ``sqlite:///relative``, ``sqlite:////absolute``) passes through
    unchanged, so it is always safe to call regardless of which
    convention the caller happened to use.
    """
    if url in _MEMORY_ALIASES:
        return "sqlite://"

    for pydal_prefix, sa_prefix in _PYDAL_TO_SQLALCHEMY_PREFIXES:
        if url.startswith(sa_prefix):
            return url
        if url.startswith(pydal_prefix):
            return sa_prefix + url[len(pydal_prefix):]

    return url
