#!/usr/bin/env python3
"""Test authentication with the MCP server."""

import requests
import json

BASE_URL = "http://127.0.0.1:8001"
TOKEN = "529c5ab1c0ff2b90e083f1f5b0d7ef5f2237ada2b5b60dfbfdb564ba070f0b8f"

def test_no_auth():
    """Test request without authentication."""
    print("\n=== Test 1: No Authentication ===")
    response = requests.post(
        f"{BASE_URL}/",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    )
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.json()}")
    assert response.status_code == 401, "Should fail without auth"

def test_wrong_auth():
    """Test request with wrong token."""
    print("\n=== Test 2: Wrong Token ===")
    response = requests.post(
        f"{BASE_URL}/",
        headers={"Authorization": "Bearer wrong_token_12345"},
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    )
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.json()}")
    assert response.status_code == 403, "Should fail with wrong token"

def test_correct_auth():
    """Test request with correct token."""
    print("\n=== Test 3: Correct Token ===")
    response = requests.post(
        f"{BASE_URL}/",
        headers={"Authorization": f"Bearer {TOKEN}"},
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    )
    print(f"Status Code: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)[:500]}")
    assert response.status_code == 200, "Should succeed with correct token"
    assert "result" in response.json(), "Should return result"
    assert "tools" in response.json()["result"], "Should return tools list"

def test_tools_call():
    """Test calling a tool with authentication."""
    print("\n=== Test 4: Tool Call with Auth ===")
    response = requests.post(
        f"{BASE_URL}/",
        headers={"Authorization": f"Bearer {TOKEN}"},
        json={
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "list_databases", "arguments": {}}
        }
    )
    print(f"Status Code: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)[:500]}")
    assert response.status_code == 200, "Should succeed"

if __name__ == "__main__":
    try:
        test_no_auth()
        test_wrong_auth()
        test_correct_auth()
        test_tools_call()
        print("\n✅ All authentication tests passed!")
    except AssertionError as e:
        print(f"\n❌ Test failed: {e}")
    except Exception as e:
        print(f"\n❌ Error: {e}")
