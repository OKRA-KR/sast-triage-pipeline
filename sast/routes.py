"""SAST→DAST 라우트 다리 — 소스의 서버 라우트 정의를 뽑아 DAST 프로브 대상으로.

왜: SPA/AJAX 앱은 공격 엔드포인트가 정적 HTML 에 없고 런타임(require/AMD·동적 URL)으로
생성돼 크롤러가 못 찾는다(WebGoat 레슨 등). 하지만 서버 소스엔 라우트가 프레임워크
애노테이션/등록으로 '결정론적으로' 박혀 있다. 이걸 추출해 base URL 에 얹어 인벤토리+replay
대상으로 넘기면, 인증 뒤에만 있는 진짜 표면을 정적으로 정확히 발굴한다(리빌딩 P3 인텔 다리).

이식성: stdlib 정규식만. 소스 있을 때만 동작(URL-only 대상은 SPA 크롤 휴리스틱이 담당).
지원: Spring(Java) · Flask/FastAPI(Python) · Express(JS/TS) · Django(urls.py).
경로 템플릿 변수({id}·:id·<id>)는 DAST 프로브용으로 자리표시값을 넣고 파라미터로도 기록.
"""
import os
import re

# 테스트/빌드/벤더 디렉터리는 앱 라우트가 아니므로 제외(노이즈·오탐 방지)
_SKIP_DIR = re.compile(r"(^|[\\/])(test|tests|node_modules|\.git|build|dist|target|vendor|"
                       r"site-packages|__pycache__|\.venv|venv)([\\/]|$)", re.I)

# ── Java / Spring ─────────────────────────────────────────────────────
_SPRING_METHOD = {"Get": "GET", "Post": "POST", "Put": "PUT",
                  "Delete": "DELETE", "Patch": "PATCH"}
_SPRING_MAP = re.compile(
    r"@(Get|Post|Put|Delete|Patch|Request)Mapping\s*\(\s*([^)]*)\)", re.S)
_ANNO_PATH = re.compile(r"""(?:value\s*=\s*|path\s*=\s*)?["']([^"']+)["']""")
_ANNO_METHOD = re.compile(r"RequestMethod\.(GET|POST|PUT|DELETE|PATCH)")
_JAVA_PARAM = re.compile(
    r"@(?:RequestParam|PathVariable|RequestPart|ModelAttribute)\b"
    r"(?:\s*\(\s*(?:value\s*=\s*|name\s*=\s*)?[\"']([^\"']+)[\"'][^)]*\))?"
    r"(?:\s*(?:final\s+)?[\w.<>\[\]]+\s+(\w+))?")

# ── Python / Flask · FastAPI ──────────────────────────────────────────
_PY_ROUTE = re.compile(
    r"@(?:\w+)\.(route|get|post|put|delete|patch)\s*\(\s*[\"']([^\"']+)[\"']([^)]*)\)")
_PY_METHODS = re.compile(r"""methods\s*=\s*\[([^\]]*)\]""")

# ── JS/TS / Express ───────────────────────────────────────────────────
_JS_ROUTE = re.compile(
    r"\b(?:app|router|r)\.(get|post|put|delete|patch|all)\s*\(\s*[\"'`]([^\"'`]+)[\"'`]")

# ── Django urls.py ────────────────────────────────────────────────────
_DJ_ROUTE = re.compile(r"\b(?:re_)?path\s*\(\s*[\"']([^\"']+)[\"']")

# ── 요청 바디 필드 마이닝(A: JSON-API 주입점 확보) ─────────────────────
# Spring: @RequestBody <DTO타입> → DTO 클래스 필드가 JSON 바디 필드
_JAVA_REQBODY = re.compile(r"@RequestBody\b\s*(?:@\w+(?:\([^)]*\))?\s*)*(?:final\s+)?([A-Za-z_]\w*)(?:<[^>]*>)?\s+\w+")
_JAVA_FIELD = re.compile(r"(?:private|protected|public)\s+(?:final\s+|static\s+|transient\s+)*"
                         r"[\w.$]+(?:<[^>;=]*>)?(?:\[\])?\s+([a-z_]\w*)\s*(?:=|;)")
_JAVA_CLASS = re.compile(r"\bclass\s+(\w+)")
# Python(Django/Flask): request.data/json/POST 필드 접근
_PY_BODY = re.compile(r"request\.(?:data|json|POST|body)(?:\.get\(|\[)\s*[\"'](\w+)[\"']"
                      r"|(?:\bdata|\bpayload|\bbody)\.get\(\s*[\"'](\w+)[\"']")
# Express: req.body.x / req.body['x'] / const {a,b} = req.body
_JS_BODY = re.compile(r"req(?:uest)?\.body\.(\w+)|req(?:uest)?\.body\[\s*[\"'](\w+)[\"']")
_JS_BODY_DESTRUCT = re.compile(r"(?:const|let|var)\s*\{([^}]+)\}\s*=\s*req(?:uest)?\.body")
_FIELD_NOISE = {"serialVersionUID", "logger", "log", "serialversionuid"}

# 경로 템플릿 변수 → 프로브 자리표시값 + 파라미터명 추출
_PATH_VAR = re.compile(r"\{(\w+)(?::[^}]*)?\}|:(\w+)|<(?:[^:>]+:)?(\w+)>")

# 상태변경 메서드 — 능동 주입 시 실제로 서버 상태를 바꾼다(옵트인 대상).
_WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
# 파괴적/비가역·고비용 동사 — 경로에 있으면 능동 주입에서 기본 제외(인벤토리만).
# 결제·삭제·초기화·권한변경처럼 되돌리기 어렵거나 부수효과가 큰 것.
_DESTRUCTIVE = re.compile(
    r"delete|remove|destroy|drop|purge|wipe|truncate|revoke|deactivat|disable|"
    r"pay(ment)?|charge|billing|transfer|refund|withdraw|checkout|cancel|"
    r"reset|shutdown|restart|reboot|deploy|migrat|logout|unsubscrib", re.I)


def _annotate_risk(r):
    """라우트에 write(상태변경)·destructive(파괴적) 위험 태그 부여."""
    r["write"] = r["method"] in _WRITE_METHODS
    r["destructive"] = (r["method"] == "DELETE") or bool(_DESTRUCTIVE.search(r["path"]))
    return r


def select_for_active(routes, allow_writes=False, allow_destructive=False):
    """능동 주입 대상 선별(디스커버리-우선 안전레일).
    - GET 등 비-상태변경: 항상 대상.
    - 상태변경(POST/PUT/PATCH): allow_writes 일 때만.
    - 파괴적(DELETE·삭제/결제/초기화 등): allow_destructive 일 때만.
    인벤토리(표면 목록)는 이 필터와 무관하게 전체를 쓴다 — 발굴은 다 하되 주입만 게이트."""
    picked = []
    for r in routes:
        if r.get("destructive"):
            if allow_destructive:
                picked.append(r)
        elif r.get("write"):
            if allow_writes:
                picked.append(r)
        else:
            picked.append(r)
    return picked


def _norm_path(p):
    """라우트 경로 정규화 — 절대경로화, 중복 슬래시 정리."""
    p = p.strip()
    if not p:
        return "/"
    if not p.startswith("/"):
        p = "/" + p
    return re.sub(r"//+", "/", p)


def _path_vars(path):
    """경로 템플릿 변수명 목록 + 프로브용 구체 경로(변수→'1')."""
    names = []
    for m in _PATH_VAR.finditer(path):
        names.append(next(g for g in m.groups() if g))
    concrete = _PATH_VAR.sub("1", path)
    return names, concrete


def _java_params(sig):
    """메서드 시그니처 텍스트에서 @RequestParam/@PathVariable 파라미터명."""
    out = []
    for m in _JAVA_PARAM.finditer(sig):
        name = m.group(1) or m.group(2)
        if name:
            out.append(name)
    return out


def java_dto_index(texts):
    """Java 소스들에서 클래스명 → 필드명 목록(요청 DTO 해석용). 필드는 각 클래스 선언 이후
    나온 것으로 귀속(파일당 다중 클래스 대략 처리). 상수(ALL_CAPS)·노이즈 제외."""
    idx = {}
    for text in texts:
        marks = [(m.start(), m.group(1)) for m in _JAVA_CLASS.finditer(text)]
        for m in _JAVA_FIELD.finditer(text):
            fname = m.group(1)
            if fname in _FIELD_NOISE or fname.isupper():
                continue
            cls = None
            for pos, name in marks:
                if pos < m.start():
                    cls = name
                else:
                    break
            if cls:
                idx.setdefault(cls, [])
                if fname not in idx[cls]:
                    idx[cls].append(fname)
    return idx


def _handler_window(text, pos):
    """라우트 정의 위치부터 다음 라우트/함수 경계까지의 핸들러 본문(바디 필드 스캔용, 대략)."""
    w = text[pos:pos + 1500]
    nxt = re.search(r"\n@(?:app|router|r|\w+Mapping)|\n\s*def\s+\w+\s*\(", w[40:])
    return w[:nxt.start() + 40] if nxt else w


def _py_body_fields(win):
    out = []
    for m in _PY_BODY.finditer(win):
        f = m.group(1) or m.group(2)
        if f and f not in out:
            out.append(f)
    return out


def _js_body_fields(win):
    out = []
    for m in _JS_BODY.finditer(win):
        f = m.group(1) or m.group(2)
        if f and f not in out:
            out.append(f)
    md = _JS_BODY_DESTRUCT.search(win)
    if md:
        for part in md.group(1).split(","):
            f = part.split(":")[0].split("=")[0].strip()
            if re.match(r"^\w+$", f) and f not in out:
                out.append(f)
    return out


def _extract_java(text):
    routes = []
    # 클래스 레벨 프리픽스(@RequestMapping("/x") 가 class 선언 직전) — 있으면 메서드 경로에 prepend
    cls_prefix = ""
    mcls = re.search(r"@RequestMapping\s*\(\s*[\"']([^\"']+)[\"']\s*\)\s*"
                     r"(?:@\w+(?:\([^)]*\))?\s*)*(?:public\s+)?(?:final\s+)?(?:abstract\s+)?class\b",
                     text, re.S)
    if mcls:
        cls_prefix = _norm_path(mcls.group(1)).rstrip("/")
    for m in _SPRING_MAP.finditer(text):
        kind, args = m.group(1), m.group(2)
        pm = _ANNO_PATH.search(args)
        if not pm:
            continue
        path = _norm_path(pm.group(1))
        if kind == "Request":
            mm = _ANNO_METHOD.search(args)
            method = mm.group(1) if mm else "GET"
            if mcls and m.start() == mcls.start(getattr(mcls, "lastindex", 0) or 0):
                continue                      # 클래스 레벨 프리픽스 자체는 라우트 아님
        else:
            method = _SPRING_METHOD[kind]
        full = (cls_prefix + path) if cls_prefix and not path.startswith(cls_prefix) else path
        # 메서드 시그니처(다음 '{' 까지) 에서 파라미터 추출
        tail = text[m.end():m.end() + 600]
        sig = tail.split("{", 1)[0]
        pnames, concrete = _path_vars(full)
        pnames += _java_params(sig)
        # @RequestBody DTO → JSON 바디. 타입은 extract_routes 후처리에서 필드로 해석(_rbtype)
        body = None
        rbtype = None
        rbm = _JAVA_REQBODY.search(sig)
        if rbm:
            body = "json"
            if rbm.group(1) not in ("Map", "String", "Object", "JsonNode", "byte"):
                rbtype = rbm.group(1)
        routes.append(dict(method=method, path=_norm_path(concrete), template=full,
                           params=sorted(set(pnames)), framework="spring", body=body, _rbtype=rbtype))
    return routes


def _extract_python(text):
    routes = []
    for m in _PY_ROUTE.finditer(text):
        verb, path, rest = m.group(1), m.group(2), m.group(3)
        methods = ["GET"]
        if verb == "route":
            mm = _PY_METHODS.search(rest)
            methods = ([x.strip().strip("'\"").upper() for x in mm.group(1).split(",") if x.strip()]
                       if mm else ["GET"])
        else:
            methods = [verb.upper()]
        pnames, concrete = _path_vars(path)
        bf = _py_body_fields(_handler_window(text, m.end())) if any(x in methods for x in _WRITE_METHODS) else []
        body = "json" if bf else None
        for mtd in methods:
            routes.append(dict(method=mtd, path=_norm_path(concrete), template=_norm_path(path),
                               params=sorted(set(pnames + bf)), framework="flask/fastapi", body=body))
    return routes


def _extract_js(text):
    routes = []
    for m in _JS_ROUTE.finditer(text):
        verb, path = m.group(1), m.group(2)
        methods = ["GET", "POST", "PUT", "DELETE", "PATCH"] if verb == "all" else [verb.upper()]
        pnames, concrete = _path_vars(path)
        bf = _js_body_fields(_handler_window(text, m.end())) if any(x in methods for x in _WRITE_METHODS) else []
        body = "json" if bf else None
        for mtd in methods:
            routes.append(dict(method=mtd, path=_norm_path(concrete), template=_norm_path(path),
                               params=sorted(set(pnames + bf)), framework="express", body=body))
    return routes


def _extract_django(text):
    routes = []
    for m in _DJ_ROUTE.finditer(text):
        path = m.group(1)
        pnames, concrete = _path_vars(path)
        routes.append(dict(method="GET", path=_norm_path(concrete), template=_norm_path(path),
                           params=sorted(set(pnames)), framework="django"))
    return routes


_EXTRACT = {".java": _extract_java, ".py": _extract_python, ".kt": _extract_java,
            ".js": _extract_js, ".ts": _extract_js, ".mjs": _extract_js}


def extract_routes(root):
    """소스 트리에서 서버 라우트 추출 → [{method, path, template, params, framework, source}].
    (method, path) 로 중복 제거."""
    seen = {}
    java_texts = []
    for dirpath, dirnames, files in os.walk(root):
        if _SKIP_DIR.search(dirpath):
            dirnames[:] = []
            continue
        for fn in files:
            ext = os.path.splitext(fn)[1].lower()
            fx = _EXTRACT.get(ext)
            if not fx:
                continue
            fp = os.path.join(dirpath, fn)
            try:
                text = open(fp, encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            if ext in (".java", ".kt"):
                java_texts.append(text)
            # Django 는 urls.py 에서만
            if ext == ".py" and fn == "urls.py":
                rs = _extract_django(text)
            else:
                rs = fx(text)
            for r in rs:
                key = (r["method"], r["path"])
                if key not in seen:
                    r["source"] = os.path.relpath(fp, root)
                    r.setdefault("body", None)
                    seen[key] = _annotate_risk(r)
    # A: Spring @RequestBody DTO 타입 → 클래스 필드를 JSON 바디 주입점으로 해석
    dto = java_dto_index(java_texts)
    for r in seen.values():
        rb = r.pop("_rbtype", None)
        if rb and dto.get(rb):
            r["params"] = sorted(set((r.get("params") or []) + dto[rb]))
    for r in seen.values():
        r.pop("_rbtype", None)               # 남은 전이키 정리
    return list(seen.values())


def to_exchanges(routes, base_url, cookie=None):
    """라우트 → capture 교환. GET=쿼리 자리표시, 그 외=바디 자리표시(JSON DTO 엔드포인트는
    실제 필드가 든 JSON 바디 → replay 가 리프를 주입점으로 인식). base_url 은 앱 컨텍스트 포함."""
    import json
    from . import capture
    base = base_url.rstrip("/")
    exs = []
    hdr = {"cookie": cookie} if cookie else {}
    for r in routes:
        url = base + r["path"]
        params = r.get("params") or []
        if r["method"] == "GET":
            q = "&".join(k + "=1" for k in params)
            full = url + (("?" + q) if q else "")
            exs.append(capture._mk("GET", full, dict(hdr), "", "", "", "", "", ""))
        elif r.get("body") == "json":
            h = dict(hdr); h["content-type"] = "application/json"
            body = json.dumps({k: "1" for k in params}) if params else "{}"
            exs.append(capture._mk(r["method"], url, h, body, "", "", "", "", ""))
        else:
            h = dict(hdr); h["content-type"] = "application/x-www-form-urlencoded"
            body = "&".join(k + "=1" for k in params)
            exs.append(capture._mk(r["method"], url, h, body, "", "", "", "", ""))
    return exs
