"""MCP tool definitions and execution logic for Metabase.

This module provides comprehensive access to Metabase's BI capabilities including:
- Database operations and metadata exploration
- Native SQL and MBQL query execution
- Saved questions (queries) management and execution
- Dashboard access and data retrieval
- Collections management
- Search and discovery
- Data exports
- Activity monitoring
"""

import csv
import io
import json
from typing import Any

import mcp.types as types

from .metabase_client import MetabaseClient

# ==================== TOOL DEFINITIONS ====================

TOOL_DEFINITIONS = [
    # DATABASE TOOLS
    types.Tool(
        name="list_databases",
        description="List all databases configured in Metabase. Shows database connections, engines, and sync status.",
        inputSchema={
            "type": "object",
            "properties": {},
            "required": [],
        },
    ),
    types.Tool(
        name="get_database",
        description="Get detailed information about a specific database including configuration and connection details.",
        inputSchema={
            "type": "object",
            "properties": {
                "database_id": {
                    "type": "integer",
                    "description": "The database ID in Metabase",
                }
            },
            "required": ["database_id"],
        },
    ),
    types.Tool(
        name="get_database_metadata",
        description="Get complete metadata for a database including all tables, fields, and relationships. Essential for understanding database structure.",
        inputSchema={
            "type": "object",
            "properties": {
                "database_id": {
                    "type": "integer",
                    "description": "The database ID in Metabase",
                }
            },
            "required": ["database_id"],
        },
    ),

    # TABLE TOOLS
    types.Tool(
        name="get_table",
        description="Get information about a specific table including its schema and basic metadata.",
        inputSchema={
            "type": "object",
            "properties": {
                "table_id": {
                    "type": "integer",
                    "description": "The table ID in Metabase",
                }
            },
            "required": ["table_id"],
        },
    ),
    types.Tool(
        name="get_table_metadata",
        description="Get detailed metadata for a table including all fields, types, foreign keys, and relationships.",
        inputSchema={
            "type": "object",
            "properties": {
                "table_id": {
                    "type": "integer",
                    "description": "The table ID in Metabase",
                }
            },
            "required": ["table_id"],
        },
    ),

    # QUERY EXECUTION TOOLS
    types.Tool(
        name="execute_sql_query",
        description="Execute a native SQL query against a database. Read-only queries only. Returns formatted results with columns and rows.",
        inputSchema={
            "type": "object",
            "properties": {
                "database_id": {
                    "type": "integer",
                    "description": "The database ID to query",
                },
                "query": {
                    "type": "string",
                    "description": "SQL query to execute (SELECT statements only)",
                },
                "parameters": {
                    "type": "object",
                    "description": "Optional query parameters for template variables",
                }
            },
            "required": ["database_id", "query"],
        },
    ),
    types.Tool(
        name="execute_mbql_query",
        description="Execute a Metabase Query Language (MBQL) query. MBQL provides a structured way to query data without SQL.",
        inputSchema={
            "type": "object",
            "properties": {
                "database_id": {
                    "type": "integer",
                    "description": "The database ID to query",
                },
                "source_table": {
                    "type": "integer",
                    "description": "The table ID to query",
                },
                "aggregations": {
                    "type": "array",
                    "description": "Optional aggregations (e.g., count, sum, avg)",
                },
                "breakouts": {
                    "type": "array",
                    "description": "Optional breakout fields for grouping",
                },
                "filters": {
                    "type": "array",
                    "description": "Optional filters to apply",
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of rows to return",
                }
            },
            "required": ["database_id", "source_table"],
        },
    ),

    # QUESTION (SAVED QUERY) TOOLS
    types.Tool(
        name="list_questions",
        description="List all saved questions (queries) in Metabase. Questions are pre-built queries created by users.",
        inputSchema={
            "type": "object",
            "properties": {
                "collection_id": {
                    "type": "integer",
                    "description": "Filter by collection ID (optional)",
                },
                "archived": {
                    "type": "boolean",
                    "description": "Include archived questions (default: false)",
                    "default": False,
                }
            },
            "required": [],
        },
    ),
    types.Tool(
        name="get_question",
        description="Get detailed information about a saved question including its query definition and metadata.",
        inputSchema={
            "type": "object",
            "properties": {
                "question_id": {
                    "type": "integer",
                    "description": "The question ID",
                }
            },
            "required": ["question_id"],
        },
    ),
    types.Tool(
        name="run_question",
        description="Execute a saved question and return its results. This is often faster than writing raw SQL as questions are pre-optimized.",
        inputSchema={
            "type": "object",
            "properties": {
                "question_id": {
                    "type": "integer",
                    "description": "The question ID to execute",
                },
                "parameters": {
                    "type": "object",
                    "description": "Optional parameters for parameterized questions",
                }
            },
            "required": ["question_id"],
        },
    ),
    types.Tool(
        name="search_questions",
        description="Search for questions by name or description. Useful for discovering existing queries.",
        inputSchema={
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search term to find questions",
                }
            },
            "required": ["query"],
        },
    ),

    # DASHBOARD TOOLS
    types.Tool(
        name="list_dashboards",
        description="List all dashboards in Metabase. Dashboards contain multiple visualizations and questions.",
        inputSchema={
            "type": "object",
            "properties": {
                "collection_id": {
                    "type": "integer",
                    "description": "Filter by collection ID (optional)",
                }
            },
            "required": [],
        },
    ),
    types.Tool(
        name="get_dashboard",
        description="Get a complete dashboard including all its cards, layout, and configuration.",
        inputSchema={
            "type": "object",
            "properties": {
                "dashboard_id": {
                    "type": "integer",
                    "description": "The dashboard ID",
                }
            },
            "required": ["dashboard_id"],
        },
    ),
    types.Tool(
        name="get_dashboard_card_data",
        description="Get data for a specific card (visualization) within a dashboard.",
        inputSchema={
            "type": "object",
            "properties": {
                "dashboard_id": {
                    "type": "integer",
                    "description": "The dashboard ID",
                },
                "card_id": {
                    "type": "integer",
                    "description": "The card ID within the dashboard",
                },
                "parameters": {
                    "type": "object",
                    "description": "Optional parameters for the card",
                }
            },
            "required": ["dashboard_id", "card_id"],
        },
    ),

    # COLLECTION TOOLS
    types.Tool(
        name="list_collections",
        description="List all collections in Metabase. Collections organize questions, dashboards, and other resources.",
        inputSchema={
            "type": "object",
            "properties": {},
            "required": [],
        },
    ),
    types.Tool(
        name="get_collection_items",
        description="Get all items (questions, dashboards) in a specific collection.",
        inputSchema={
            "type": "object",
            "properties": {
                "collection_id": {
                    "type": ["integer", "string"],
                    "description": "The collection ID ('root' for root collection)",
                }
            },
            "required": ["collection_id"],
        },
    ),

    # EXPORT TOOLS
    types.Tool(
        name="export_query_csv",
        description="Export the results of a SQL query as CSV format. Useful for data extraction and analysis.",
        inputSchema={
            "type": "object",
            "properties": {
                "database_id": {
                    "type": "integer",
                    "description": "The database ID",
                },
                "query": {
                    "type": "string",
                    "description": "SQL query to execute and export",
                }
            },
            "required": ["database_id", "query"],
        },
    ),
    types.Tool(
        name="export_question_csv",
        description="Export a saved question's results as CSV format.",
        inputSchema={
            "type": "object",
            "properties": {
                "question_id": {
                    "type": "integer",
                    "description": "The question ID to export",
                }
            },
            "required": ["question_id"],
        },
    ),

    # SEARCH & DISCOVERY TOOLS
    types.Tool(
        name="search",
        description="Search across all Metabase resources (questions, dashboards, collections, etc.).",
        inputSchema={
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search term",
                },
                "models": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Filter by resource types: card, dashboard, collection, table, database",
                }
            },
            "required": ["query"],
        },
    ),
    types.Tool(
        name="get_activity",
        description="Get recent activity in Metabase (recently viewed items, queries run, etc.).",
        inputSchema={
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of activity items to return (default: 10)",
                    "default": 10,
                }
            },
            "required": [],
        },
    ),
]


# ==================== TOOL EXECUTION ====================

async def execute_tool(
    client: MetabaseClient, tool_name: str, arguments: dict[str, Any]
) -> str:
    """Execute a tool and return formatted results.

    Args:
        client: Initialized MetabaseClient
        tool_name: Name of the tool to execute
        arguments: Tool arguments

    Returns:
        Formatted string result
    """
    # DATABASE TOOLS
    if tool_name == "list_databases":
        databases = await client.list_databases()
        return _format_databases(databases)

    elif tool_name == "get_database":
        database_id = arguments["database_id"]
        database = await client.get_database(database_id)
        return _format_database(database)

    elif tool_name == "get_database_metadata":
        database_id = arguments["database_id"]
        metadata = await client.get_database_metadata(database_id)
        return _format_database_metadata(metadata)

    # TABLE TOOLS
    elif tool_name == "get_table":
        table_id = arguments["table_id"]
        table = await client.get_table(table_id)
        return _format_table(table)

    elif tool_name == "get_table_metadata":
        table_id = arguments["table_id"]
        metadata = await client.get_table_metadata(table_id)
        return _format_table_metadata(metadata)

    # QUERY EXECUTION
    elif tool_name == "execute_sql_query":
        database_id = arguments["database_id"]
        query = arguments["query"]
        parameters = arguments.get("parameters")
        result = await client.execute_query(database_id, query, parameters)
        return _format_query_result(result, f"SQL Query on Database {database_id}")

    elif tool_name == "execute_mbql_query":
        database_id = arguments["database_id"]
        source_table = arguments["source_table"]
        aggregations = arguments.get("aggregations")
        breakouts = arguments.get("breakouts")
        filters = arguments.get("filters")
        limit = arguments.get("limit")
        result = await client.execute_mbql_query(
            database_id, source_table, aggregations, breakouts, filters, limit
        )
        return _format_query_result(result, f"MBQL Query on Table {source_table}")

    # QUESTION TOOLS
    elif tool_name == "list_questions":
        collection_id = arguments.get("collection_id")
        archived = arguments.get("archived", False)
        questions = await client.list_questions(collection_id, archived)
        return _format_questions_list(questions)

    elif tool_name == "get_question":
        question_id = arguments["question_id"]
        question = await client.get_question(question_id)
        return _format_question(question)

    elif tool_name == "run_question":
        question_id = arguments["question_id"]
        parameters = arguments.get("parameters")
        result = await client.run_question(question_id, parameters)
        return _format_query_result(result, f"Question #{question_id}")

    elif tool_name == "search_questions":
        query = arguments["query"]
        results = await client.search_questions(query)
        return _format_search_results(results, "Questions")

    # DASHBOARD TOOLS
    elif tool_name == "list_dashboards":
        collection_id = arguments.get("collection_id")
        dashboards = await client.list_dashboards(collection_id)
        return _format_dashboards_list(dashboards)

    elif tool_name == "get_dashboard":
        dashboard_id = arguments["dashboard_id"]
        dashboard = await client.get_dashboard(dashboard_id)
        return _format_dashboard(dashboard)

    elif tool_name == "get_dashboard_card_data":
        dashboard_id = arguments["dashboard_id"]
        card_id = arguments["card_id"]
        parameters = arguments.get("parameters")
        result = await client.get_dashboard_card_data(dashboard_id, card_id, parameters)
        return _format_query_result(result, f"Dashboard {dashboard_id} Card {card_id}")

    # COLLECTION TOOLS
    elif tool_name == "list_collections":
        collections = await client.list_collections()
        return _format_collections_list(collections)

    elif tool_name == "get_collection_items":
        collection_id = arguments["collection_id"]
        items = await client.get_collection_items(collection_id)
        return _format_collection_items(items, collection_id)

    # EXPORT TOOLS
    elif tool_name == "export_query_csv":
        database_id = arguments["database_id"]
        query = arguments["query"]
        csv_data = await client.export_query_csv(database_id, query)
        return _format_csv_export(csv_data, f"Query on Database {database_id}")

    elif tool_name == "export_question_csv":
        question_id = arguments["question_id"]
        csv_data = await client.export_question_csv(question_id)
        return _format_csv_export(csv_data, f"Question #{question_id}")

    # SEARCH & DISCOVERY
    elif tool_name == "search":
        query = arguments["query"]
        models = arguments.get("models")
        results = await client.search(query, models)
        return _format_search_results(results, "All Resources")

    elif tool_name == "get_activity":
        limit = arguments.get("limit", 10)
        activity = await client.get_activity(limit)
        return _format_activity(activity)

    else:
        raise ValueError(f"Unknown tool: {tool_name}")


# ==================== FORMATTING FUNCTIONS ====================

def _format_databases(databases: list[dict[str, Any]]) -> str:
    """Format database list for display."""
    if not databases:
        return "No databases found in Metabase."

    lines = [f"# Metabase Databases ({len(databases)})\n"]
    for db in databases:
        lines.append(f"## {db['name']} (ID: {db['id']})")
        lines.append(f"- **Engine**: {db['engine']}")
        lines.append(f"- **Sample Database**: {'Yes' if db.get('is_sample') else 'No'}")
        lines.append(f"- **Full Sync**: {'Yes' if db.get('is_full_sync') else 'No'}")
        if db.get('features'):
            lines.append(f"- **Features**: {', '.join(db['features'])}")
        lines.append("")

    return "\n".join(lines)


def _format_database(database: dict[str, Any]) -> str:
    """Format single database details."""
    lines = [f"# Database: {database.get('name', 'Unknown')}\n"]
    lines.append(f"**ID**: {database.get('id')}")
    lines.append(f"**Engine**: {database.get('engine')}")
    lines.append(f"**Description**: {database.get('description', 'N/A')}")
    lines.append(f"**Is Sample**: {'Yes' if database.get('is_sample') else 'No'}")
    lines.append(f"**Created**: {database.get('created_at', 'N/A')}")
    lines.append(f"**Updated**: {database.get('updated_at', 'N/A')}\n")

    if database.get('details'):
        lines.append("## Connection Details:")
        details = database['details']
        for key, value in details.items():
            if 'password' not in key.lower():  # Don't display sensitive info
                lines.append(f"- **{key}**: {value}")

    return "\n".join(lines)


def _format_database_metadata(metadata: dict[str, Any]) -> str:
    """Format database metadata including tables and fields."""
    lines = [f"# Database Metadata: {metadata.get('name', 'Unknown')}\n"]

    tables = metadata.get('tables', [])
    lines.append(f"**Total Tables**: {len(tables)}\n")

    if tables:
        lines.append("## Tables:\n")
        for table in tables[:20]:  # Limit to first 20 tables
            lines.append(f"### {table.get('name')} (ID: {table.get('id')})")
            lines.append(f"- **Schema**: {table.get('schema', 'N/A')}")
            lines.append(f"- **Display Name**: {table.get('display_name', 'N/A')}")

            fields = table.get('fields', [])
            lines.append(f"- **Fields**: {len(fields)} columns")

            if fields:
                lines.append("  - Key fields:")
                for field in fields[:5]:  # Show first 5 fields
                    lines.append(f"    - {field.get('name')} ({field.get('base_type', 'unknown')})")
            lines.append("")

        if len(tables) > 20:
            lines.append(f"\n*... and {len(tables) - 20} more tables*")

    return "\n".join(lines)


def _format_table(table: dict[str, Any]) -> str:
    """Format table information."""
    lines = [f"# Table: {table.get('name', 'Unknown')}\n"]
    lines.append(f"**ID**: {table.get('id')}")
    lines.append(f"**Database ID**: {table.get('db_id')}")
    lines.append(f"**Schema**: {table.get('schema', 'N/A')}")
    lines.append(f"**Display Name**: {table.get('display_name', 'N/A')}")
    lines.append(f"**Description**: {table.get('description', 'N/A')}")
    lines.append(f"**Created**: {table.get('created_at', 'N/A')}")

    return "\n".join(lines)


def _format_table_metadata(metadata: dict[str, Any]) -> str:
    """Format table metadata including fields and relationships."""
    lines = [f"# Table Metadata: {metadata.get('name', 'Unknown')}\n"]

    fields = metadata.get('fields', [])
    lines.append(f"**Total Fields**: {len(fields)}\n")

    if fields:
        lines.append("## Fields:\n")
        lines.append("| Name | Type | Description | Special Type |")
        lines.append("|------|------|-------------|--------------|")

        for field in fields:
            name = field.get('name', 'N/A')
            base_type = field.get('base_type', 'unknown')
            description = field.get('description', '-')[:50]
            special_type = field.get('special_type', '-')
            lines.append(f"| {name} | {base_type} | {description} | {special_type} |")

    fks = metadata.get('fks', [])
    if fks:
        lines.append(f"\n## Foreign Keys ({len(fks)}):\n")
        for fk in fks:
            origin = fk.get('origin', {})
            destination = fk.get('destination', {})
            lines.append(f"- {origin.get('name')} → {destination.get('table', {}).get('name')}.{destination.get('name')}")

    return "\n".join(lines)


def _format_query_result(result: dict[str, Any], title: str) -> str:
    """Format query results."""
    if "columns" not in result or "rows" not in result:
        return f"# {title}\n\nNo tabular data available.\n\n" + json.dumps(result, indent=2)

    columns = result["columns"]
    rows = result["rows"]
    row_count = result.get("row_count", len(rows))

    lines = [f"# {title}\n"]
    lines.append(f"**Rows Returned**: {row_count}")
    lines.append(f"**Status**: {result.get('status', 'completed')}\n")

    if rows:
        # Create markdown table
        lines.append("## Results:\n")
        lines.append("| " + " | ".join(columns) + " |")
        lines.append("|" + "|".join(["---" for _ in columns]) + "|")

        for row in rows[:100]:  # Limit to 100 rows for display
            formatted_row = []
            for cell in row:
                if isinstance(cell, (list, dict)):
                    formatted_row.append(json.dumps(cell)[:50])
                else:
                    str_cell = str(cell) if cell is not None else ""
                    formatted_row.append(str_cell[:50])
            lines.append("| " + " | ".join(formatted_row) + " |")

        if len(rows) > 100:
            lines.append(f"\n*... and {len(rows) - 100} more rows*")
    else:
        lines.append("\n*No rows returned*")

    return "\n".join(lines)


def _format_questions_list(questions: list[dict[str, Any]]) -> str:
    """Format list of questions."""
    if not questions:
        return "No questions found."

    lines = [f"# Saved Questions ({len(questions)})\n"]

    for q in questions:
        lines.append(f"## {q['name']} (ID: {q['id']})")
        if q.get('description'):
            lines.append(f"- **Description**: {q['description']}")
        lines.append(f"- **Database ID**: {q.get('database_id', 'N/A')}")
        lines.append(f"- **Collection ID**: {q.get('collection_id', 'N/A')}")
        lines.append(f"- **Query Type**: {q.get('query_type', 'N/A')}")
        lines.append(f"- **Visualization**: {q.get('display', 'N/A')}")
        lines.append(f"- **Created**: {q.get('created_at', 'N/A')}")
        lines.append("")

    return "\n".join(lines)


def _format_question(question: dict[str, Any]) -> str:
    """Format single question details."""
    lines = [f"# Question: {question.get('name', 'Unknown')}\n"]
    lines.append(f"**ID**: {question.get('id')}")
    lines.append(f"**Description**: {question.get('description', 'N/A')}")
    lines.append(f"**Database ID**: {question.get('database_id', 'N/A')}")
    lines.append(f"**Collection ID**: {question.get('collection_id', 'N/A')}")
    lines.append(f"**Query Type**: {question.get('query_type', 'N/A')}")
    lines.append(f"**Visualization**: {question.get('display', 'N/A')}")
    lines.append(f"**Created**: {question.get('created_at', 'N/A')}")
    lines.append(f"**Updated**: {question.get('updated_at', 'N/A')}\n")

    if question.get('dataset_query'):
        lines.append("## Query Definition:")
        lines.append("```json")
        lines.append(json.dumps(question['dataset_query'], indent=2))
        lines.append("```")

    return "\n".join(lines)


def _format_dashboards_list(dashboards: list[dict[str, Any]]) -> str:
    """Format list of dashboards."""
    if not dashboards:
        return "No dashboards found."

    lines = [f"# Dashboards ({len(dashboards)})\n"]

    for d in dashboards:
        lines.append(f"## {d['name']} (ID: {d['id']})")
        if d.get('description'):
            lines.append(f"- **Description**: {d['description']}")
        lines.append(f"- **Collection ID**: {d.get('collection_id', 'N/A')}")
        lines.append(f"- **Created**: {d.get('created_at', 'N/A')}")
        lines.append(f"- **Public**: {'Yes' if d.get('public_uuid') else 'No'}")
        lines.append("")

    return "\n".join(lines)


def _format_dashboard(dashboard: dict[str, Any]) -> str:
    """Format dashboard details."""
    lines = [f"# Dashboard: {dashboard.get('name', 'Unknown')}\n"]
    lines.append(f"**ID**: {dashboard.get('id')}")
    lines.append(f"**Description**: {dashboard.get('description', 'N/A')}")
    lines.append(f"**Collection ID**: {dashboard.get('collection_id', 'N/A')}")
    lines.append(f"**Created**: {dashboard.get('created_at', 'N/A')}")
    lines.append(f"**Updated**: {dashboard.get('updated_at', 'N/A')}\n")

    cards = dashboard.get('dashcards', [])
    if cards:
        lines.append(f"## Cards ({len(cards)}):\n")
        for card in cards:
            card_info = card.get('card', {})
            lines.append(f"### {card_info.get('name', 'Unnamed Card')} (Card ID: {card.get('card_id')})")
            lines.append(f"- **Visualization**: {card_info.get('display', 'N/A')}")
            lines.append(f"- **Position**: Row {card.get('row', 0)}, Col {card.get('col', 0)}")
            lines.append(f"- **Size**: {card.get('size_x', 0)}x{card.get('size_y', 0)}")
            lines.append("")

    return "\n".join(lines)


def _format_collections_list(collections: list[dict[str, Any]]) -> str:
    """Format list of collections."""
    if not collections:
        return "No collections found."

    lines = [f"# Collections ({len(collections)})\n"]

    for c in collections:
        lines.append(f"## {c['name']} (ID: {c['id']})")
        if c.get('description'):
            lines.append(f"- **Description**: {c['description']}")
        lines.append(f"- **Slug**: {c.get('slug', 'N/A')}")
        lines.append(f"- **Color**: {c.get('color', 'N/A')}")
        lines.append(f"- **Archived**: {'Yes' if c.get('archived') else 'No'}")
        if c.get('personal_owner_id'):
            lines.append(f"- **Personal Collection**: User ID {c['personal_owner_id']}")
        lines.append("")

    return "\n".join(lines)


def _format_collection_items(items: list[dict[str, Any]], collection_id: Any) -> str:
    """Format collection items."""
    if not items:
        return f"No items found in collection {collection_id}."

    lines = [f"# Collection Items ({len(items)})\n"]

    for item in items:
        model = item.get('model', 'unknown')
        lines.append(f"## {item.get('name', 'Unnamed')} ({model})")
        lines.append(f"- **ID**: {item.get('id')}")
        if item.get('description'):
            lines.append(f"- **Description**: {item['description']}")
        lines.append(f"- **Updated**: {item.get('updated_at', 'N/A')}")
        lines.append("")

    return "\n".join(lines)


def _format_csv_export(csv_data: str, title: str) -> str:
    """Format CSV export."""
    lines = [f"# CSV Export: {title}\n"]

    # Count rows
    row_count = len(csv_data.strip().split('\n')) - 1  # Subtract header

    lines.append(f"**Total Rows**: {row_count}\n")
    lines.append("## CSV Data:\n")
    lines.append("```csv")
    lines.append(csv_data.strip())
    lines.append("```\n")
    lines.append("**Instructions**: Copy the CSV data above and save as a .csv file.")

    return "\n".join(lines)


def _format_search_results(results: list[dict[str, Any]], category: str) -> str:
    """Format search results."""
    if not results:
        return f"No {category} found matching your search."

    lines = [f"# Search Results: {category} ({len(results)})\n"]

    for item in results:
        model = item.get('model', 'unknown')
        lines.append(f"## {item.get('name', 'Unnamed')} ({model})")
        lines.append(f"- **ID**: {item.get('id')}")
        if item.get('description'):
            lines.append(f"- **Description**: {item['description']}")
        if item.get('collection'):
            lines.append(f"- **Collection**: {item['collection'].get('name', 'N/A')}")
        lines.append(f"- **Updated**: {item.get('updated_at', 'N/A')}")
        lines.append("")

    return "\n".join(lines)


def _format_activity(activity: list[dict[str, Any]]) -> str:
    """Format activity feed."""
    if not activity:
        return "No recent activity."

    lines = [f"# Recent Activity ({len(activity)} items)\n"]

    for item in activity:
        topic = item.get('topic', 'unknown')
        lines.append(f"## {topic}")
        lines.append(f"- **User ID**: {item.get('user_id', 'N/A')}")
        lines.append(f"- **Model**: {item.get('model', 'N/A')}")
        lines.append(f"- **Model ID**: {item.get('model_id', 'N/A')}")
        if item.get('details'):
            lines.append(f"- **Details**: {json.dumps(item['details'])[:100]}")
        lines.append(f"- **Timestamp**: {item.get('timestamp', 'N/A')}")
        lines.append("")

    return "\n".join(lines)
