"""STRATA read-only Streamlit UI (spec section 15).

Everything under this package is read-only: `data.py` opens its own
`mode=ro` SQLite URI connection (see its module docstring), never
`model.store.get_connection` (which sets up WAL/foreign_keys/migrations --
a writer's job, not a viewer's). The CLI (`strata collect`/`strata build`/
`strata hunt run`/...) remains the only thing that mutates state.
"""

from __future__ import annotations
