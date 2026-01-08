from typing import Any, List, Dict, Optional
from datetime import datetime, timezone
from tinydb import TinyDB, Query
from tinydb.table import Table

class BaseRepository:
    """Base repository with common functionality"""

    def __init__(self, db: TinyDB, table_name: str):
        self.db = db
        self.table = db.table(table_name)
        self.query = Query()

    def _now(self) -> str:
        """Return current timestamp as ISO string"""
        return datetime.now(timezone.utc).isoformat()
