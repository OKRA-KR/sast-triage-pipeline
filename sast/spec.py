"""API 스펙 임포트 — OpenAPI(v3)·Swagger(v2)·Postman(JSON)에서 엔드포인트+주입점 추출.

왜: 라우트 다리(routes.py)는 소스가 있어야 돈다. 소스 없는 URL-only 블랙박스에서도 API 앱은
스펙을 노출(/openapi.json·/swagger.json·/v3/api-docs)하거나 Postman 컬렉션을 준다. 스펙은
라우트 다리와 똑같은 것(경로·메서드·바디 스키마=주입점)을 소스 없이 준다 → 4번째 발굴원.

이식성: stdlib(JSON)만. YAML 스펙은 후순위(stdlib YAML 없음). 산출 형태는 routes.py 와 동일
(method·path·template·params·body·framework·source) → to_exchanges/select_for_active 그대로 재사용.
"""
import json
from . import routes as _routes

_METHODS = ("get", "post", "put", "delete", "patch")


def is_spec(obj):
    """dict 가 OpenAPI/Swagger/Postman 스펙인가(캡처 HAR 와 구분)."""
    if not isinstance(obj, dict):
        return False
    if obj.get("openapi") or obj.get("swagger"):
        return True
    if isinstance(obj.get("info"), dict) and isinstance(obj.get("item"), list):
        return True                                  # Postman collection
    if isinstance(obj.get("paths"), dict) and "log" not in obj:
        return True                                  # paths 있고 HAR(.log) 아님
    return False


def _resolve_ref(ref, root):
    """'#/components/schemas/X' 또는 '#/definitions/X' → 스키마 객체."""
    if not isinstance(ref, str) or not ref.startswith("#/"):
        return {}
    node = root
    for part in ref[2:].split("/"):
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return {}
    return node if isinstance(node, dict) else {}


def _schema_fields(schema, root, depth=0):
    """스키마의 최상위 속성명(=바디 주입점). $ref·allOf 해석(얕게)."""
    if not isinstance(schema, dict) or depth > 5:
        return []
    if "$ref" in schema:
        schema = _resolve_ref(schema["$ref"], root)
    out = list((schema.get("properties") or {}).keys())
    for sub in schema.get("allOf", []) + schema.get("oneOf", []) + schema.get("anyOf", []):
        out += _schema_fields(sub, root, depth + 1)
    if schema.get("type") == "array" and isinstance(schema.get("items"), dict):
        out += _schema_fields(schema["items"], root, depth + 1)
    return out


def _mk_route(method, path, params, body, framework):
    pnames, concrete = _routes._path_vars(path)
    r = dict(method=method.upper(), path=_routes._norm_path(concrete),
             template=_routes._norm_path(path), params=sorted(set(params + pnames)),
             framework=framework, body=body, source="spec")
    return _routes._annotate_risk(r)


def _parse_openapi3(obj):
    out = []
    for path, item in (obj.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        shared = item.get("parameters", []) if isinstance(item.get("parameters"), list) else []
        for method in _METHODS:
            op = item.get(method)
            if not isinstance(op, dict):
                continue
            params, body = [], None
            for p in shared + (op.get("parameters") or []):
                if isinstance(p, dict) and p.get("in") in ("query", "path") and p.get("name"):
                    params.append(p["name"])
            content = ((op.get("requestBody") or {}).get("content") or {})
            js = content.get("application/json") or content.get("*/*")
            form = content.get("application/x-www-form-urlencoded") or content.get("multipart/form-data")
            if js:
                body = "json"; params += _schema_fields(js.get("schema", {}), obj)
            elif form:
                body = "form"; params += _schema_fields(form.get("schema", {}), obj)
            out.append(_mk_route(method, path, params, body, "openapi"))
    return out


def _parse_swagger2(obj):
    out = []
    for path, item in (obj.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        shared = item.get("parameters", []) if isinstance(item.get("parameters"), list) else []
        for method in _METHODS:
            op = item.get(method)
            if not isinstance(op, dict):
                continue
            params, body = [], None
            for p in shared + (op.get("parameters") or []):
                if not isinstance(p, dict):
                    continue
                loc = p.get("in")
                if loc in ("query", "path") and p.get("name"):
                    params.append(p["name"])
                elif loc == "formData" and p.get("name"):
                    params.append(p["name"]); body = body or "form"
                elif loc == "body":
                    body = "json"; params += _schema_fields(p.get("schema", {}), obj)
            out.append(_mk_route(method, path, params, body, "swagger"))
    return out


def _postman_path(url):
    if isinstance(url, str):
        from urllib.parse import urlsplit
        raw = url.replace("{{", "").replace("}}", "")
        return urlsplit(raw).path or "/" + "/".join(p for p in url.split("/")[3:] if "?" not in p)
    if isinstance(url, dict):
        segs = url.get("path") or []
        segs = [str(s).replace("{{", "").replace("}}", "") for s in segs]
        return "/" + "/".join(segs)
    return "/"


def _parse_postman(obj):
    out = []

    def walk(items):
        for it in items or []:
            if isinstance(it, dict) and isinstance(it.get("item"), list):
                walk(it["item"]); continue
            req = it.get("request") if isinstance(it, dict) else None
            if not isinstance(req, dict):
                continue
            method = (req.get("method") or "GET").upper()
            url = req.get("url")
            path = _postman_path(url)
            params, body = [], None
            b = req.get("body") or {}
            if b.get("mode") == "raw":
                try:
                    o2 = json.loads(b.get("raw") or "{}")
                    if isinstance(o2, dict):
                        params += list(o2.keys()); body = "json"
                except Exception:
                    pass
            elif b.get("mode") == "urlencoded":
                params += [x.get("key") for x in (b.get("urlencoded") or []) if x.get("key")]
                body = "form"
            if isinstance(url, dict):
                params += [q.get("key") for q in (url.get("query") or []) if q.get("key")]
            out.append(_mk_route(method, path, [p for p in params if p], body, "postman"))
    walk(obj.get("item", []))
    return out


def routes_from_spec(text_or_obj):
    """스펙(JSON 문자열/dict) → 라우트 목록(routes.py 형태). 형식 자동판별. 실패 시 []."""
    try:
        obj = json.loads(text_or_obj) if isinstance(text_or_obj, (str, bytes)) else text_or_obj
    except Exception:
        return []
    if not is_spec(obj):
        return []
    if isinstance(obj.get("item"), list) and isinstance(obj.get("info"), dict):
        return _parse_postman(obj)
    sw = str(obj.get("swagger") or "")
    if sw.startswith("2") or (sw and not obj.get("openapi")):
        return _parse_swagger2(obj)
    return _parse_openapi3(obj)


# 라이브 대상이 흔히 노출하는 스펙 경로(발굴 시 프로브)
WELL_KNOWN = ("/openapi.json", "/swagger.json", "/v3/api-docs", "/api-docs",
              "/swagger/v1/swagger.json", "/api/swagger.json", "/openapi/v3")
