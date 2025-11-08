"""Metabase client for executing queries and managing BI operations."""

import logging
from typing import Any
import httpx
import os

logger = logging.getLogger(__name__)


class MetabaseClient:
    """Client for interacting with Metabase API.

    Supports comprehensive Metabase operations including:
    - Database operations
    - Questions (saved queries)
    - Dashboards
    - Collections
    - Cards and visualizations
    - Data exports
    - Metadata exploration
    """

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        username: str | None = None,
        password: str | None = None
    ):
        """Initialize the Metabase client.

        Args:
            base_url: Metabase instance URL (e.g., https://metabase.company.com)
            api_key: Metabase API key (recommended, created in admin panel)
            username: Username for session auth (alternative to API key)
            password: Password for session auth (alternative to API key)
        """
        self.base_url = (base_url or os.getenv("METABASE_URL", "")).rstrip('/')
        self.api_key = api_key or os.getenv("METABASE_API_KEY")
        self.session_token = None
        self.client = httpx.AsyncClient(timeout=60.0)

        # If using username/password, store for lazy authentication
        self.username = username or os.getenv("METABASE_USERNAME")
        self.password = password or os.getenv("METABASE_PASSWORD")

        if not self.base_url:
            raise ValueError("METABASE_URL must be provided")

        logger.info(f"Metabase client initialized for {self.base_url}")

    def _get_headers(self) -> dict[str, str]:
        """Get headers for API requests."""
        headers = {"Content-Type": "application/json"}

        if self.api_key:
            headers["X-API-KEY"] = self.api_key
        elif self.session_token:
            headers["X-Metabase-Session"] = self.session_token

        return headers

    async def _ensure_authenticated(self):
        """Ensure we have valid authentication."""
        if self.api_key:
            return  # API key doesn't need session

        if not self.session_token and self.username and self.password:
            await self._authenticate()

    async def _authenticate(self):
        """Authenticate and get session token."""
        try:
            response = await self.client.post(
                f"{self.base_url}/api/session",
                json={"username": self.username, "password": self.password}
            )
            response.raise_for_status()
            self.session_token = response.json()["id"]
            logger.info("Successfully authenticated with Metabase")
        except Exception as e:
            logger.error(f"Failed to authenticate: {e}")
            raise

    # ==================== DATABASE OPERATIONS ====================

    async def list_databases(self) -> list[dict[str, Any]]:
        """List all databases configured in Metabase."""
        await self._ensure_authenticated()

        try:
            response = await self.client.get(
                f"{self.base_url}/api/database",
                headers=self._get_headers()
            )
            response.raise_for_status()

            databases = response.json()["data"]
            return [
                {
                    "id": db["id"],
                    "name": db["name"],
                    "engine": db["engine"],
                    "is_sample": db.get("is_sample", False),
                    "is_full_sync": db.get("is_full_sync", False),
                    "created_at": db.get("created_at"),
                    "features": db.get("features", [])
                }
                for db in databases
            ]
        except Exception as e:
            logger.error(f"Failed to list databases: {e}")
            raise

    async def get_database(self, database_id: int) -> dict[str, Any]:
        """Get detailed information about a specific database."""
        await self._ensure_authenticated()

        try:
            response = await self.client.get(
                f"{self.base_url}/api/database/{database_id}",
                headers=self._get_headers()
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to get database {database_id}: {e}")
            raise

    async def get_database_metadata(self, database_id: int) -> dict[str, Any]:
        """Get complete metadata for a database including tables and fields."""
        await self._ensure_authenticated()

        try:
            response = await self.client.get(
                f"{self.base_url}/api/database/{database_id}/metadata",
                headers=self._get_headers()
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to get database metadata: {e}")
            raise

    # ==================== TABLE OPERATIONS ====================

    async def get_table(self, table_id: int) -> dict[str, Any]:
        """Get table information."""
        await self._ensure_authenticated()

        try:
            response = await self.client.get(
                f"{self.base_url}/api/table/{table_id}",
                headers=self._get_headers()
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to get table {table_id}: {e}")
            raise

    async def get_table_metadata(self, table_id: int) -> dict[str, Any]:
        """Get detailed metadata for a table including fields and foreign keys."""
        await self._ensure_authenticated()

        try:
            response = await self.client.get(
                f"{self.base_url}/api/table/{table_id}/query_metadata",
                headers=self._get_headers()
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to get table metadata: {e}")
            raise

    # ==================== QUERY EXECUTION ====================

    async def execute_query(
        self,
        database_id: int,
        query: str,
        parameters: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Execute a native SQL query."""
        await self._ensure_authenticated()

        # Validate read-only (basic check)
        query_upper = query.strip().upper()
        forbidden = ["INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER", "TRUNCATE", "GRANT", "REVOKE"]
        for keyword in forbidden:
            if query_upper.startswith(keyword) or f" {keyword} " in f" {query_upper} ":
                raise ValueError(f"Forbidden keyword: {keyword}. Only read-only queries are allowed.")

        try:
            payload = {
                "database": database_id,
                "type": "native",
                "native": {
                    "query": query
                }
            }

            if parameters:
                payload["native"]["template-tags"] = parameters

            response = await self.client.post(
                f"{self.base_url}/api/dataset",
                json=payload,
                headers=self._get_headers()
            )
            response.raise_for_status()

            data = response.json()

            # Extract columns and rows
            columns = [col["name"] for col in data["data"]["cols"]]
            rows = data["data"]["rows"]

            return {
                "columns": columns,
                "rows": rows,
                "row_count": len(rows),
                "native_form": data.get("native_form", {}),
                "status": data.get("status", "completed")
            }
        except Exception as e:
            logger.error(f"Failed to execute query: {e}")
            raise

    async def execute_mbql_query(
        self,
        database_id: int,
        source_table: int,
        aggregations: list[dict] | None = None,
        breakouts: list[dict] | None = None,
        filters: list[dict] | None = None,
        limit: int | None = None
    ) -> dict[str, Any]:
        """Execute an MBQL (Metabase Query Language) query."""
        await self._ensure_authenticated()

        try:
            query_spec = {"source-table": source_table}

            if aggregations:
                query_spec["aggregation"] = aggregations
            if breakouts:
                query_spec["breakout"] = breakouts
            if filters:
                query_spec["filter"] = filters
            if limit:
                query_spec["limit"] = limit

            payload = {
                "database": database_id,
                "type": "query",
                "query": query_spec
            }

            response = await self.client.post(
                f"{self.base_url}/api/dataset",
                json=payload,
                headers=self._get_headers()
            )
            response.raise_for_status()

            data = response.json()
            columns = [col["name"] for col in data["data"]["cols"]]
            rows = data["data"]["rows"]

            return {
                "columns": columns,
                "rows": rows,
                "row_count": len(rows),
                "status": data.get("status", "completed")
            }
        except Exception as e:
            logger.error(f"Failed to execute MBQL query: {e}")
            raise

    # ==================== QUESTIONS (SAVED QUERIES) ====================

    async def list_questions(
        self,
        collection_id: int | None = None,
        archived: bool = False
    ) -> list[dict[str, Any]]:
        """List all questions (saved queries)."""
        await self._ensure_authenticated()

        try:
            params = {"archived": str(archived).lower()}
            if collection_id is not None:
                params["collection"] = str(collection_id)

            response = await self.client.get(
                f"{self.base_url}/api/card",
                params=params,
                headers=self._get_headers()
            )
            response.raise_for_status()

            questions = response.json()
            return [
                {
                    "id": q["id"],
                    "name": q["name"],
                    "description": q.get("description"),
                    "database_id": q.get("database_id"),
                    "collection_id": q.get("collection_id"),
                    "creator_id": q.get("creator_id"),
                    "created_at": q.get("created_at"),
                    "updated_at": q.get("updated_at"),
                    "query_type": q.get("query_type"),
                    "display": q.get("display")
                }
                for q in questions
            ]
        except Exception as e:
            logger.error(f"Failed to list questions: {e}")
            raise

    async def get_question(self, question_id: int) -> dict[str, Any]:
        """Get a specific question by ID."""
        await self._ensure_authenticated()

        try:
            response = await self.client.get(
                f"{self.base_url}/api/card/{question_id}",
                headers=self._get_headers()
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to get question {question_id}: {e}")
            raise

    async def run_question(
        self,
        question_id: int,
        parameters: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Execute a saved question and return results."""
        await self._ensure_authenticated()

        try:
            payload = {}
            if parameters:
                payload["parameters"] = [
                    {"type": key, "target": ["variable", ["template-tag", key]], "value": value}
                    for key, value in parameters.items()
                ]

            response = await self.client.post(
                f"{self.base_url}/api/card/{question_id}/query",
                json=payload if payload else None,
                headers=self._get_headers()
            )
            response.raise_for_status()

            data = response.json()
            columns = [col["name"] for col in data["data"]["cols"]]
            rows = data["data"]["rows"]

            return {
                "columns": columns,
                "rows": rows,
                "row_count": len(rows),
                "status": data.get("status", "completed")
            }
        except Exception as e:
            logger.error(f"Failed to run question {question_id}: {e}")
            raise

    async def search_questions(self, query: str) -> list[dict[str, Any]]:
        """Search for questions by name or description."""
        await self._ensure_authenticated()

        try:
            response = await self.client.get(
                f"{self.base_url}/api/search",
                params={"q": query, "models": "card"},
                headers=self._get_headers()
            )
            response.raise_for_status()

            return response.json()["data"]
        except Exception as e:
            logger.error(f"Failed to search questions: {e}")
            raise

    # ==================== DASHBOARDS ====================

    async def list_dashboards(self, collection_id: int | None = None) -> list[dict[str, Any]]:
        """List all dashboards."""
        await self._ensure_authenticated()

        try:
            params = {}
            if collection_id is not None:
                params["collection"] = str(collection_id)

            response = await self.client.get(
                f"{self.base_url}/api/dashboard",
                params=params,
                headers=self._get_headers()
            )
            response.raise_for_status()

            dashboards = response.json()
            return [
                {
                    "id": d["id"],
                    "name": d["name"],
                    "description": d.get("description"),
                    "collection_id": d.get("collection_id"),
                    "creator_id": d.get("creator_id"),
                    "created_at": d.get("created_at"),
                    "updated_at": d.get("updated_at"),
                    "public_uuid": d.get("public_uuid")
                }
                for d in dashboards
            ]
        except Exception as e:
            logger.error(f"Failed to list dashboards: {e}")
            raise

    async def get_dashboard(self, dashboard_id: int) -> dict[str, Any]:
        """Get a dashboard with all its cards and layout."""
        await self._ensure_authenticated()

        try:
            response = await self.client.get(
                f"{self.base_url}/api/dashboard/{dashboard_id}",
                headers=self._get_headers()
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to get dashboard {dashboard_id}: {e}")
            raise

    async def get_dashboard_card_data(
        self,
        dashboard_id: int,
        card_id: int,
        parameters: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Get data for a specific card in a dashboard."""
        await self._ensure_authenticated()

        try:
            payload = {}
            if parameters:
                payload["parameters"] = parameters

            response = await self.client.post(
                f"{self.base_url}/api/dashboard/{dashboard_id}/dashcard/{card_id}/card/{card_id}/query",
                json=payload if payload else None,
                headers=self._get_headers()
            )
            response.raise_for_status()

            data = response.json()
            if "data" in data and "cols" in data["data"]:
                columns = [col["name"] for col in data["data"]["cols"]]
                rows = data["data"]["rows"]
                return {
                    "columns": columns,
                    "rows": rows,
                    "row_count": len(rows)
                }
            return data
        except Exception as e:
            logger.error(f"Failed to get dashboard card data: {e}")
            raise

    # ==================== COLLECTIONS ====================

    async def list_collections(self) -> list[dict[str, Any]]:
        """List all collections."""
        await self._ensure_authenticated()

        try:
            response = await self.client.get(
                f"{self.base_url}/api/collection",
                headers=self._get_headers()
            )
            response.raise_for_status()

            collections = response.json()
            return [
                {
                    "id": c["id"],
                    "name": c["name"],
                    "description": c.get("description"),
                    "slug": c.get("slug"),
                    "color": c.get("color"),
                    "archived": c.get("archived", False),
                    "personal_owner_id": c.get("personal_owner_id")
                }
                for c in collections
            ]
        except Exception as e:
            logger.error(f"Failed to list collections: {e}")
            raise

    async def get_collection_items(self, collection_id: int | str) -> list[dict[str, Any]]:
        """Get all items in a collection."""
        await self._ensure_authenticated()

        try:
            response = await self.client.get(
                f"{self.base_url}/api/collection/{collection_id}/items",
                headers=self._get_headers()
            )
            response.raise_for_status()
            return response.json()["data"]
        except Exception as e:
            logger.error(f"Failed to get collection items: {e}")
            raise

    # ==================== DATA EXPORTS ====================

    async def export_query_csv(
        self,
        database_id: int,
        query: str
    ) -> str:
        """Export query results as CSV."""
        await self._ensure_authenticated()

        try:
            payload = {
                "database": database_id,
                "type": "native",
                "native": {
                    "query": query
                }
            }

            response = await self.client.post(
                f"{self.base_url}/api/dataset/csv",
                json=payload,
                headers=self._get_headers()
            )
            response.raise_for_status()
            return response.text
        except Exception as e:
            logger.error(f"Failed to export CSV: {e}")
            raise

    async def export_question_csv(self, question_id: int) -> str:
        """Export a saved question's results as CSV."""
        await self._ensure_authenticated()

        try:
            response = await self.client.post(
                f"{self.base_url}/api/card/{question_id}/query/csv",
                headers=self._get_headers()
            )
            response.raise_for_status()
            return response.text
        except Exception as e:
            logger.error(f"Failed to export question CSV: {e}")
            raise

    # ==================== SEARCH & DISCOVERY ====================

    async def search(self, query: str, models: list[str] | None = None) -> list[dict[str, Any]]:
        """Search across Metabase resources."""
        await self._ensure_authenticated()

        try:
            params = {"q": query}
            if models:
                params["models"] = ",".join(models)

            response = await self.client.get(
                f"{self.base_url}/api/search",
                params=params,
                headers=self._get_headers()
            )
            response.raise_for_status()
            return response.json()["data"]
        except Exception as e:
            logger.error(f"Failed to search: {e}")
            raise

    async def get_activity(self, limit: int = 10) -> list[dict[str, Any]]:
        """Get recent activity in Metabase."""
        await self._ensure_authenticated()

        try:
            response = await self.client.get(
                f"{self.base_url}/api/activity",
                params={"limit": limit},
                headers=self._get_headers()
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to get activity: {e}")
            raise

    # WRITE OPERATIONS

    async def create_question(
        self,
        name: str,
        database_id: int,
        query: dict[str, Any],
        description: str | None = None,
        collection_id: int | None = None,
        visualization_settings: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Create a new question (saved query) in Metabase.

        Args:
            name: Question name
            database_id: Database ID for the query
            query: Query definition (native SQL or MBQL)
            description: Optional description
            collection_id: Optional collection ID to save in
            visualization_settings: Optional visualization configuration

        Returns:
            Created question data
        """
        await self._ensure_authenticated()

        payload = {
            "name": name,
            "database": database_id,
            "dataset_query": query,
            "display": visualization_settings.get("display", "table") if visualization_settings else "table",
            "visualization_settings": visualization_settings or {}
        }

        if description:
            payload["description"] = description
        if collection_id is not None:
            payload["collection_id"] = collection_id

        try:
            response = await self.client.post(
                f"{self.base_url}/api/card",
                json=payload,
                headers=self._get_headers()
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to create question: {e}")
            raise

    async def update_question(
        self,
        question_id: int,
        name: str | None = None,
        description: str | None = None,
        query: dict[str, Any] | None = None,
        visualization_settings: dict[str, Any] | None = None,
        collection_id: int | None = None
    ) -> dict[str, Any]:
        """Update an existing question.

        Args:
            question_id: Question ID to update
            name: New name (optional)
            description: New description (optional)
            query: New query definition (optional)
            visualization_settings: New visualization settings (optional)
            collection_id: New collection ID (optional)

        Returns:
            Updated question data
        """
        await self._ensure_authenticated()

        # Get existing question first
        try:
            existing = await self.get_question(question_id)

            # Build update payload with only changed fields
            payload = {
                "name": name if name is not None else existing["name"],
                "description": description if description is not None else existing.get("description", ""),
                "dataset_query": query if query is not None else existing["dataset_query"],
                "display": existing["display"],
                "visualization_settings": visualization_settings if visualization_settings is not None else existing.get("visualization_settings", {})
            }

            if collection_id is not None:
                payload["collection_id"] = collection_id
            elif "collection_id" in existing:
                payload["collection_id"] = existing["collection_id"]

            response = await self.client.put(
                f"{self.base_url}/api/card/{question_id}",
                json=payload,
                headers=self._get_headers()
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to update question: {e}")
            raise

    async def delete_question(self, question_id: int) -> dict[str, Any]:
        """Delete a question.

        Args:
            question_id: Question ID to delete

        Returns:
            Deletion confirmation
        """
        await self._ensure_authenticated()

        try:
            response = await self.client.delete(
                f"{self.base_url}/api/card/{question_id}",
                headers=self._get_headers()
            )
            response.raise_for_status()
            return {"id": question_id, "deleted": True}
        except Exception as e:
            logger.error(f"Failed to delete question: {e}")
            raise

    async def create_dashboard(
        self,
        name: str,
        description: str | None = None,
        collection_id: int | None = None
    ) -> dict[str, Any]:
        """Create a new dashboard.

        Args:
            name: Dashboard name
            description: Optional description
            collection_id: Optional collection ID

        Returns:
            Created dashboard data
        """
        await self._ensure_authenticated()

        payload = {"name": name}
        if description:
            payload["description"] = description
        if collection_id is not None:
            payload["collection_id"] = collection_id

        try:
            response = await self.client.post(
                f"{self.base_url}/api/dashboard",
                json=payload,
                headers=self._get_headers()
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to create dashboard: {e}")
            raise

    async def update_dashboard(
        self,
        dashboard_id: int,
        name: str | None = None,
        description: str | None = None,
        collection_id: int | None = None
    ) -> dict[str, Any]:
        """Update an existing dashboard.

        Args:
            dashboard_id: Dashboard ID to update
            name: New name (optional)
            description: New description (optional)
            collection_id: New collection ID (optional)

        Returns:
            Updated dashboard data
        """
        await self._ensure_authenticated()

        # Get existing dashboard
        try:
            existing = await self.get_dashboard(dashboard_id)

            payload = {
                "name": name if name is not None else existing["name"],
                "description": description if description is not None else existing.get("description", "")
            }

            if collection_id is not None:
                payload["collection_id"] = collection_id
            elif "collection_id" in existing:
                payload["collection_id"] = existing["collection_id"]

            response = await self.client.put(
                f"{self.base_url}/api/dashboard/{dashboard_id}",
                json=payload,
                headers=self._get_headers()
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to update dashboard: {e}")
            raise

    async def delete_dashboard(self, dashboard_id: int) -> dict[str, Any]:
        """Delete a dashboard.

        Args:
            dashboard_id: Dashboard ID to delete

        Returns:
            Deletion confirmation
        """
        await self._ensure_authenticated()

        try:
            response = await self.client.delete(
                f"{self.base_url}/api/dashboard/{dashboard_id}",
                headers=self._get_headers()
            )
            response.raise_for_status()
            return {"id": dashboard_id, "deleted": True}
        except Exception as e:
            logger.error(f"Failed to delete dashboard: {e}")
            raise

    async def add_card_to_dashboard(
        self,
        dashboard_id: int,
        card_id: int,
        row: int = 0,
        col: int = 0,
        size_x: int = 4,
        size_y: int = 4
    ) -> dict[str, Any]:
        """Add a question card to a dashboard.

        Args:
            dashboard_id: Dashboard ID
            card_id: Question/card ID to add
            row: Row position (default: 0)
            col: Column position (default: 0)
            size_x: Card width (default: 4)
            size_y: Card height (default: 4)

        Returns:
            Dashboard card data
        """
        await self._ensure_authenticated()

        payload = {
            "cardId": card_id,
            "row": row,
            "col": col,
            "sizeX": size_x,
            "sizeY": size_y
        }

        try:
            response = await self.client.post(
                f"{self.base_url}/api/dashboard/{dashboard_id}/cards",
                json=payload,
                headers=self._get_headers()
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to add card to dashboard: {e}")
            raise

    def close(self):
        """Close HTTP client."""
        try:
            import asyncio
            asyncio.create_task(self.client.aclose())
        except:
            pass
        logger.info("Metabase client cleanup complete")
