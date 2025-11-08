# Metabase MCP Server for Dust.tt

**Comprehensive Model Context Protocol (MCP) server connecting Dust.tt AI agents to Metabase BI platform.**

This MCP server provides full access to Metabase's rich BI capabilities including databases, saved questions, dashboards, collections, and more - going far beyond simple SQL query execution.

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org/)
[![MCP](https://img.shields.io/badge/MCP-1.5%2B-green)](https://modelcontextprotocol.io/)
[![Metabase](https://img.shields.io/badge/Metabase-API-orange)](https://www.metabase.com/docs/latest/api-documentation)

---

## 🎯 Features

### Complete Metabase API Coverage

Unlike simple database query servers, this MCP implementation leverages **all of Metabase's BI capabilities**:

#### 📊 Database Operations (5 tools)
- **list_databases** - Discover all connected databases
- **get_database** - Get database details and configuration
- **get_database_metadata** - Explore complete schema (tables, fields, relationships)
- **get_table** - Get table information
- **get_table_metadata** - Detailed field metadata and foreign keys

#### 🔍 Query Execution (2 tools)
- **execute_sql_query** - Run native SQL queries (read-only)
- **execute_mbql_query** - Execute Metabase Query Language queries

#### 💾 Saved Questions (4 tools)
- **list_questions** - Browse all saved queries
- **get_question** - Get question details and definition
- **run_question** - Execute pre-built queries (faster than raw SQL!)
- **search_questions** - Find questions by name/description

#### 📈 Dashboards (3 tools)
- **list_dashboards** - Browse all dashboards
- **get_dashboard** - Get dashboard with all cards and layout
- **get_dashboard_card_data** - Fetch data from specific dashboard cards

#### 📁 Collections (2 tools)
- **list_collections** - Browse collections (folders)
- **get_collection_items** - List all items in a collection

#### 📤 Data Export (2 tools)
- **export_query_csv** - Export SQL query results as CSV
- **export_question_csv** - Export saved question results as CSV

#### 🔎 Discovery (2 tools)
- **search** - Search across all Metabase resources
- **get_activity** - View recent activity (queries, views, etc.)

**Total: 22 comprehensive tools** providing full BI platform access!

---

## 🚀 Quick Start

### Prerequisites

- Python 3.10+
- Access to a Metabase instance (self-hosted or cloud)
- Metabase API key or username/password

### 1. Get Metabase API Key (Recommended)

**For Metabase Cloud/Self-hosted v0.41+:**

1. Go to your Metabase instance
2. Click on the gear icon (⚙️) → **Admin**
3. Navigate to **Settings** → **Authentication**
4. Scroll to **API Keys** section
5. Click **Create API Key**
6. Name it: `Dust MCP Server`
7. Copy the generated key (starts with `mb_`)

**Alternative: Username/Password**

You can use username/password authentication, but API keys are more secure and don't expire.

### 2. Local Setup

```bash
# Clone/navigate to directory
cd /Users/xaviergastaud/code/xgastaud/Forest/mcp-server-metabase

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure environment variables
cp .env.example .env
# Edit .env with your Metabase credentials
```

**Edit `.env`:**

```bash
# Option 1: API Key (Recommended)
METABASE_URL=https://metabase.yourcompany.com
METABASE_API_KEY=mb_xxxxxxxxxxxxxxxxxxxxx

# Option 2: Username/Password
# METABASE_URL=https://metabase.yourcompany.com
# METABASE_USERNAME=admin@company.com
# METABASE_PASSWORD=your_password

# MCP Server Security
MCP_AUTH_TOKEN=$(openssl rand -hex 32)
```

### 3. Run Locally

```bash
cd src
uvicorn forestadmin_metabase_mcp.server_sse:app --host 0.0.0.0 --port 8000
```

### 4. Test the Server

```bash
# Health check
curl http://localhost:8000/health

# List tools
curl -X POST http://localhost:8000/ \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'

# List databases
curl -X POST http://localhost:8000/ \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_databases","arguments":{}}}'
```

---

## 🌐 Deployment to Heroku

### Prerequisites

- Heroku account
- Heroku CLI installed

### Deploy

```bash
cd /Users/xaviergastaud/code/xgastaud/Forest/mcp-server-metabase

# Login to Heroku
heroku login

# Create app
heroku create your-metabase-mcp-app

# Set environment variables
heroku config:set METABASE_URL=https://metabase.yourcompany.com
heroku config:set METABASE_API_KEY=mb_xxxxxxxxxxxxxxxxxxxxx
heroku config:set MCP_AUTH_TOKEN=$(openssl rand -hex 32)

# Initialize git and deploy
git init
git add .
git commit -m "Initial commit - Metabase MCP Server"
heroku git:remote -a your-metabase-mcp-app
git push heroku master

# Verify deployment
heroku logs --tail
heroku open
```

**Your server URL:** `https://your-metabase-mcp-app.herokuapp.com`

---

## 🔌 Connect to Dust.tt

### 1. Add MCP Server

1. Go to **Dust.tt** → **Settings** → **MCP Servers**
2. Click **"Add MCP Server"**
3. Configure:
   - **Name**: `Metabase`
   - **URL**: Your deployed server URL (e.g., `https://your-metabase-mcp-app.herokuapp.com`)
   - **Transport**: `SSE`
   - **Endpoint**: `/` (root endpoint)
   - **Auth Method**: `Bearer Token`
   - **Token**: Your `MCP_AUTH_TOKEN` value

### 2. Configure Tool Permissions

#### Read-Only Tools (LOW stake):
All database exploration and query tools are read-only:
- Database tools: `list_databases`, `get_database`, `get_database_metadata`
- Table tools: `get_table`, `get_table_metadata`
- Query tools: `execute_sql_query`, `execute_mbql_query` (validated read-only)
- Question tools: `list_questions`, `get_question`, `run_question`, `search_questions`
- Dashboard tools: `list_dashboards`, `get_dashboard`, `get_dashboard_card_data`
- Collection tools: `list_collections`, `get_collection_items`
- Export tools: `export_query_csv`, `export_question_csv`
- Discovery tools: `search`, `get_activity`

**Recommendation**: Set all 22 tools to **LOW stake** (all are read-only and safe).

### 3. Create AI Assistant

Create an assistant with these instructions:

```
You are a business intelligence assistant with access to our Metabase analytics platform.

Capabilities:
- Explore databases, tables, and fields
- Run SQL queries and MBQL queries
- Execute saved questions (pre-built queries)
- View dashboards and extract data
- Search for existing analyses
- Export data to CSV

When users ask for data:
1. First discover available databases with list_databases
2. Explore metadata to understand structure
3. Check for existing saved questions before writing new SQL
4. Execute queries using either saved questions or native SQL
5. Present results clearly with context

Always explain what data you're retrieving and from where.
Use saved questions when they exist - they're pre-optimized!
```

### 4. Example Queries

```
"What databases are available in Metabase?"
"Show me all saved questions about sales"
"Run the 'Monthly Revenue' question"
"What dashboards do we have?"
"Show me data from the Sales Overview dashboard"
"Search for questions about customer retention"
"Execute this SQL: SELECT * FROM orders WHERE status = 'pending' LIMIT 10"
"Export the results of question #42 as CSV"
```

---

## 📚 Tool Reference

### Database Tools

#### `list_databases`
Lists all databases configured in Metabase.

**Parameters:** None

**Example:**
```json
{
  "name": "list_databases",
  "arguments": {}
}
```

**Returns:** List of databases with ID, name, engine, sync status.

---

#### `get_database_metadata`
Get complete metadata for a database including all tables and fields.

**Parameters:**
- `database_id` (integer) - The database ID

**Example:**
```json
{
  "name": "get_database_metadata",
  "arguments": {
    "database_id": 1
  }
}
```

**Returns:** Complete schema with tables, fields, types, and relationships.

---

### Query Tools

#### `execute_sql_query`
Execute a native SQL query (read-only).

**Parameters:**
- `database_id` (integer) - The database to query
- `query` (string) - SQL query (SELECT only)
- `parameters` (object, optional) - Query parameters

**Example:**
```json
{
  "name": "execute_sql_query",
  "arguments": {
    "database_id": 1,
    "query": "SELECT * FROM users WHERE created_at > '2024-01-01' LIMIT 10"
  }
}
```

**Returns:** Query results with columns, rows, and row count.

---

#### `execute_mbql_query`
Execute a Metabase Query Language query.

**Parameters:**
- `database_id` (integer) - The database ID
- `source_table` (integer) - The table ID to query
- `aggregations` (array, optional) - Aggregations to apply
- `breakouts` (array, optional) - Fields to group by
- `filters` (array, optional) - Filters to apply
- `limit` (integer, optional) - Maximum rows to return

**Example:**
```json
{
  "name": "execute_mbql_query",
  "arguments": {
    "database_id": 1,
    "source_table": 5,
    "aggregations": [["count"]],
    "breakouts": [["field", 10, null]],
    "limit": 100
  }
}
```

---

### Question Tools

#### `run_question`
Execute a saved question by ID.

**Parameters:**
- `question_id` (integer) - The question ID
- `parameters` (object, optional) - Parameters for parameterized questions

**Example:**
```json
{
  "name": "run_question",
  "arguments": {
    "question_id": 42
  }
}
```

**Returns:** Question results with columns and rows.

**Why use this?** Saved questions are pre-optimized and often faster than writing raw SQL. Plus, they're validated by your team!

---

#### `search_questions`
Search for questions by name or description.

**Parameters:**
- `query` (string) - Search term

**Example:**
```json
{
  "name": "search_questions",
  "arguments": {
    "query": "revenue"
  }
}
```

**Returns:** List of matching questions with IDs and metadata.

---

### Dashboard Tools

#### `get_dashboard`
Get a complete dashboard with all cards.

**Parameters:**
- `dashboard_id` (integer) - The dashboard ID

**Example:**
```json
{
  "name": "get_dashboard",
  "arguments": {
    "dashboard_id": 1
  }
}
```

**Returns:** Dashboard layout, cards, and configuration.

---

#### `get_dashboard_card_data`
Get data from a specific card in a dashboard.

**Parameters:**
- `dashboard_id` (integer) - The dashboard ID
- `card_id` (integer) - The card ID
- `parameters` (object, optional) - Dashboard parameters

**Example:**
```json
{
  "name": "get_dashboard_card_data",
  "arguments": {
    "dashboard_id": 1,
    "card_id": 5
  }
}
```

---

### Export Tools

#### `export_query_csv`
Export SQL query results as CSV.

**Parameters:**
- `database_id` (integer) - Database ID
- `query` (string) - SQL query

**Example:**
```json
{
  "name": "export_query_csv",
  "arguments": {
    "database_id": 1,
    "query": "SELECT * FROM orders"
  }
}
```

**Returns:** CSV formatted data.

---

## 🔧 Configuration

### Environment Variables

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `METABASE_URL` | Yes | Metabase instance URL | `https://metabase.company.com` |
| `METABASE_API_KEY` | Either this or username/password | API key from admin panel | `mb_xxxxx...` |
| `METABASE_USERNAME` | Alternative to API key | Username for authentication | `admin@company.com` |
| `METABASE_PASSWORD` | Alternative to API key | Password for authentication | `********` |
| `MCP_AUTH_TOKEN` | Yes | Token for MCP endpoint security | Generate with `openssl rand -hex 32` |
| `PORT` | No | Server port (default: 8000) | `8000` |

### Authentication Methods

**API Key (Recommended):**
- More secure
- No session expiration
- Created in Metabase admin panel

**Username/Password:**
- Session-based
- May expire after inactivity
- Requires re-authentication

---

## 🛠️ Architecture

### Components

1. **MetabaseClient** (`metabase_client.py`): Comprehensive HTTP client for Metabase API
   - 615 lines of code
   - Covers all major API endpoints
   - Handles authentication (API key + session tokens)
   - Async/await for performance

2. **Tools** (`tools.py`): 22 MCP tool definitions with execution logic
   - 838 lines of code
   - Database operations
   - Query execution
   - Questions, dashboards, collections
   - Data export
   - Search and discovery

3. **Server** (`server_sse.py`): FastAPI-based MCP server
   - SSE transport for Dust.tt
   - JSON-RPC 2.0 protocol
   - Health checks and monitoring

### MCP Protocol

- **Transport**: Server-Sent Events (SSE)
- **Protocol**: JSON-RPC 2.0
- **Specification**: MCP 2024-11-05
- **Authentication**: Bearer token
- **Endpoints**:
  - `GET /` - Health check
  - `GET /health` - Detailed health status
  - `POST /` - JSON-RPC method calls

---

## 🔒 Security

### Query Safety

- **Read-only enforcement**: All SQL queries are validated to prevent modifications
- **Forbidden keywords**: INSERT, UPDATE, DELETE, DROP, CREATE, ALTER, TRUNCATE, GRANT, REVOKE
- **Pattern matching**: Detects forbidden operations in query strings

### Authentication

- **MCP Endpoint**: Protected by bearer token (`MCP_AUTH_TOKEN`)
- **Metabase API**: Protected by API key or session authentication
- **No sensitive data exposure**: Passwords and secrets are filtered from responses

### Best Practices

1. **Use API keys** instead of username/password
2. **Rotate MCP_AUTH_TOKEN** regularly
3. **Use HTTPS** for all connections
4. **Limit Metabase permissions** to read-only databases
5. **Monitor activity** using the `get_activity` tool

---

## 📊 Use Cases

### 1. Natural Language Analytics

**User:** "Show me our top 10 customers by revenue this year"

**AI Agent:**
1. Lists databases to find the right one
2. Explores metadata to find customers and orders tables
3. Executes SQL query with proper joins and aggregations
4. Presents results in a clear format

### 2. Dashboard Exploration

**User:** "What's on the Executive Dashboard?"

**AI Agent:**
1. Searches for dashboards matching "Executive"
2. Gets dashboard with all cards
3. Retrieves data from each card
4. Summarizes key metrics

### 3. Saved Query Discovery

**User:** "Do we have any analysis on customer churn?"

**AI Agent:**
1. Searches questions for "churn"
2. Lists matching saved questions
3. Runs the most relevant question
4. Explains the findings

### 4. Data Export

**User:** "Export all pending orders to CSV"

**AI Agent:**
1. Executes SQL query for pending orders
2. Exports results as CSV
3. Provides download instructions

---

## 🐛 Troubleshooting

### Server won't start

```bash
# Check logs
heroku logs --tail --app your-metabase-mcp-app

# Verify environment variables
heroku config --app your-metabase-mcp-app

# Test locally first
cd src && uvicorn forestadmin_metabase_mcp.server_sse:app --reload
```

### Authentication failures

```bash
# Test API key directly
curl -H "X-API-KEY: YOUR_API_KEY" https://metabase.yourcompany.com/api/user/current

# Test username/password
curl -X POST https://metabase.yourcompany.com/api/session \
  -H "Content-Type: application/json" \
  -d '{"username":"user@example.com","password":"password"}'
```

### Queries failing

- **Check SQL syntax**: Test queries in Metabase UI first
- **Verify permissions**: Ensure user/API key has database access
- **Read-only validation**: Make sure query doesn't contain forbidden keywords

### Dust.tt connection issues

1. Verify URL is correct (no trailing slash)
2. Check MCP_AUTH_TOKEN matches in both places
3. Ensure Heroku app is running
4. Test endpoints manually with curl

---

## 📈 Performance

### Query Optimization

1. **Use saved questions** when possible - they're pre-optimized
2. **Limit result sets** with LIMIT clauses
3. **Use MBQL** for simple queries - it's optimized by Metabase
4. **Add indexes** to frequently queried columns in your database

### Caching

Metabase has built-in caching:
- Saved questions cache results based on configuration
- Dashboard cards may serve cached data
- Check cache settings in Metabase admin panel

---

## 🤝 Contributing

This server was built to provide comprehensive Metabase access to AI agents. Contributions welcome!

### Adding New Tools

1. Add method to `MetabaseClient` (`metabase_client.py`)
2. Define tool in `TOOL_DEFINITIONS` (`tools.py`)
3. Add execution handler in `execute_tool()` (`tools.py`)
4. Add formatting function for results
5. Update README with tool documentation

---

## 📝 License

MIT License - See LICENSE file for details

---

## 🙏 Acknowledgments

Built with:
- [MCP Protocol](https://modelcontextprotocol.io/) by Anthropic
- [Metabase](https://www.metabase.com/) BI platform
- [FastAPI](https://fastapi.tiangolo.com/) web framework
- [Dust.tt](https://dust.tt/) AI platform

---

## 📞 Support

- **Documentation**: This README
- **Metabase API Docs**: https://www.metabase.com/docs/latest/api-documentation
- **MCP Protocol**: https://modelcontextprotocol.io/
- **Dust.tt Docs**: https://docs.dust.tt/

---

**Built with ❤️ by Forest Admin**

Comprehensive BI access for AI agents - going beyond simple SQL to unlock the full power of Metabase!
