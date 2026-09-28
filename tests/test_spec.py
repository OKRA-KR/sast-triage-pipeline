"""API 스펙 임포트 — OpenAPI v3 / Swagger v2 / Postman(JSON) → 라우트(주입점 포함)."""
import json
from sast import spec


def test_openapi3_paths_and_body_fields():
    doc = {
        "openapi": "3.0.0",
        "components": {"schemas": {"Login": {"properties": {"email": {}, "password": {}}}}},
        "paths": {
            "/api/auth/login": {"post": {
                "requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Login"}}}}}},
            "/api/users/{id}": {"get": {"parameters": [{"in": "path", "name": "id"}, {"in": "query", "name": "verbose"}]}},
        },
    }
    R = {(r["method"], r["path"]): r for r in spec.routes_from_spec(doc)}
    assert set(R[("POST", "/api/auth/login")]["params"]) == {"email", "password"}
    assert R[("POST", "/api/auth/login")]["body"] == "json"
    assert ("GET", "/api/users/1") in R
    assert set(R[("GET", "/api/users/1")]["params"]) >= {"id", "verbose"}


def test_swagger2_body_ref():
    doc = {
        "swagger": "2.0",
        "definitions": {"Order": {"properties": {"item": {}, "qty": {}}}},
        "paths": {"/order": {"post": {"parameters": [
            {"in": "body", "name": "body", "schema": {"$ref": "#/definitions/Order"}}]}}},
    }
    R = {(r["method"], r["path"]): r for r in spec.routes_from_spec(doc)}
    assert set(R[("POST", "/order")]["params"]) == {"item", "qty"}
    assert R[("POST", "/order")]["body"] == "json"


def test_postman_collection():
    doc = {
        "info": {"_postman_id": "x", "name": "c"},
        "item": [
            {"name": "login", "request": {"method": "POST",
                "url": {"raw": "{{base}}/api/login", "path": ["api", "login"]},
                "body": {"mode": "raw", "raw": '{"email":"a","password":"b"}'}}},
            {"name": "folder", "item": [
                {"name": "list", "request": {"method": "GET",
                    "url": {"path": ["api", "orders"], "query": [{"key": "page"}]}}}]},
        ],
    }
    R = {(r["method"], r["path"]): r for r in spec.routes_from_spec(doc)}
    assert set(R[("POST", "/api/login")]["params"]) == {"email", "password"}
    assert ("GET", "/api/orders") in R and "page" in R[("GET", "/api/orders")]["params"]


def test_is_spec_distinguishes_har():
    assert spec.is_spec({"openapi": "3.0.0", "paths": {}})
    assert spec.is_spec({"swagger": "2.0", "paths": {}})
    assert spec.is_spec({"info": {"name": "c"}, "item": []})
    assert not spec.is_spec({"log": {"entries": []}})       # HAR 은 스펙 아님
    assert not spec.is_spec({"findings": []})


def test_spec_routes_feed_to_exchanges():
    from sast import routes
    rs = spec.routes_from_spec({"openapi": "3.0.0",
        "paths": {"/api/x": {"post": {"requestBody": {"content": {"application/json": {"schema": {"properties": {"q": {}}}}}}}}}})
    ex = routes.to_exchanges(rs, "http://h")[0]
    assert ex["req_headers"]["content-type"] == "application/json"
    assert "q" in json.loads(ex["req_body"])
