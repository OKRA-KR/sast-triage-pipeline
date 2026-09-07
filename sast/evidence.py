"""5단계 — 증거 번들 + 전제조건 평가 (오프라인 결정론 우선, stdlib 전용).

finding 1건에 1단계 산출물(SAST 코드 · correlate 도달성 · crossval taint · replay/passive
동적관측 · 캡처 응답)을 조인해 '사실(fact)'을 뽑고, 각 전제조건(precondition)의 상태를
satisfied / failed / unknown 으로 판정한다.

- 오프라인에서 결정론적으로 판정 가능한 조건(응답 content-type, 도달성, 동적 확증, IDOR
  파라미터명 등)은 여기서 확정한다. hard=True 면 refuted(하드 오탐) 근거가 될 수 있다.
- 코드 추론이 필요한 조건(문자열결합 SQL? 출력 인코딩? allowlist?)은 오프라인 토큰
  휴리스틱으로 1차 시도하고, 애매하면 unknown 으로 남겨 layer2 가 LLM 으로 보강한다.
"""
import os, re
from urllib.parse import urlparse

# 싱크 경로에 방어(인코딩/이스케이프/파라미터라이즈/allowlist)가 보이는가 — no_* 조건 판정용
_SANITIZE_TOK = re.compile(
    r"htmlspecialchars|htmlentities|escapeHtml|encodeURI|DOMPurify|sanitiz|"
    r"prepare\(|preparedstatement|parameteriz|bindparam|bindvalue|placeholder|\?\s*,|:\w+\s*=>|"
    r"realpath|basename|canonical|allowlist|whitelist|in_array|\.contains\(|"
    r"intval|parseint|is_numeric|ctype_digit|Number\(|escapeshellarg|escapeshellcmd|"
    r"quote\(|addslashes|striptags|strip_tags|filter_var|validator|schema\.|joi\.",
    re.I)

# 카테고리별 '위험한 싱크' 토큰 — flows_to_* 조건의 오프라인 근거
_SINK_TOK = {
    "sql-injection": re.compile(r"select\s|insert\s|update\s|delete\s|\"\s*\+|\'\s*\+|`\s*\$|execute\(|query\(|rawquery|createquerybuilder|\.raw\(|sequelize\.literal|\.literal\(|createStatement|executeQuery|executeUpdate|createQuery\(", re.I),
    "nosql-injection": re.compile(r"\$where|find\(|findone|aggregate\(|\{\s*\$", re.I),
    "command-injection": re.compile(r"exec\(|execsync|spawn\(|system\(|popen|shell_exec|passthru|proc_open|os\.system|subprocess|Runtime\.getRuntime|ProcessBuilder", re.I),
    "code-injection": re.compile(r"\beval\(|new Function|assert\(|create_function|pickle\.loads|yaml\.load\b|Function\(", re.I),
    "ssti": re.compile(r"render_template_string|Template\(|\.render\(|Twig|Velocity|Freemarker|__proto__|\{\{", re.I),
    "path-traversal": re.compile(r"fopen|file_get_contents|readfile|include\s|require\s|open\(|createReadStream|sendFile|fs\.read|Files\.read|new FileInputStream|Paths\.get", re.I),
    "ssrf": re.compile(r"urlopen|requests\.(get|post)|fetch\(|axios|curl_exec|HttpClient|URLConnection|http\.get|got\(|WebClient", re.I),
    "xxe": re.compile(r"DocumentBuilder|SAXParser|XMLReader|libxml|simplexml_load|etree\.parse|XmlDocument|DTD|noent", re.I),
    "open-redirect": re.compile(r"redirect\(|sendRedirect|header\(\s*['\"]?location|res\.redirect|Location:", re.I),
    "ldap-injection": re.compile(r"ldap_search|InitialDirContext|search\(|DirContext|ldap://", re.I),
    "xpath-injection": re.compile(r"xpath|evaluate\(|selectNodes|compile\(", re.I),
    "log-injection": re.compile(r"log\.(info|warn|error|debug)|logger\.|console\.log|System\.out", re.I),
    "crlf-injection": re.compile(r"setHeader|header\(|addHeader|Location:|Set-Cookie", re.I),
    "deserialization": re.compile(r"unserialize|pickle\.loads|readObject|ObjectInputStream|yaml\.load\b|Marshal\.load|fromJson", re.I),
    "prototype-pollution": re.compile(r"merge\(|extend\(|Object\.assign|__proto__|deepmerge|_\.merge", re.I),
}

_IDOR_NAME = re.compile(r"(_sn|_id|_no|_seq|_idx|_num|(^|_)(id|no|seq|idx|uid|sn|num|pk|key))$", re.I)
_NONHTML_CT = re.compile(r"application/json|text/plain|text/csv|image/|application/octet|application/pdf|font/", re.I)
_PARAM_RE = re.compile(
    r"""\$_(?:POST|GET|REQUEST|COOKIE)\s*\[\s*['"]([\w-]+)['"]|"""
    r"""req(?:uest)?\.(?:query|body|params)\.(\w+)|"""                       # req.body.x / request.query.y
    r"""req(?:uest)?\.(?:query|body|params)\[\s*['"]([\w-]+)['"]|"""         # req.body['x']
    r"""(?:const|let|var)\s*\{\s*(\w+)[\w,\s]*\}\s*=\s*req(?:uest)?\.(?:query|body|params)|"""  # const {x}=req.body (TS 구조분해)
    r"""getParameter\(\s*['"](\w+)['"]|"""                                   # Java servlet
    r"""@(?:Request(?:Param|Body|Header)|PathVariable)\s*\(?\s*(?:value\s*=\s*)?['"]?(\w+)""")  # Spring(WebGoat)


def _first_group(m):
    return next((g for g in m.groups() if g), "") if m else ""


_FILE_CACHE = {}


def _file_lines(path):
    if path not in _FILE_CACHE:
        try:
            _FILE_CACHE[path] = open(path, encoding="utf-8", errors="ignore").read().splitlines()
        except OSError:
            _FILE_CACHE[path] = None
    return _FILE_CACHE[path]


def _resolve(f, root):
    """finding.file(대개 타깃 기준 상대경로) → 실제 파일 경로. URL/미존재면 None."""
    p = f.get("file", "") or ""
    if not p or p.startswith("http"):
        return None
    if os.path.isabs(p) and os.path.isfile(p):
        return p
    if root:
        cand = os.path.join(root, p)
        if os.path.isfile(cand):
            return cand
    return p if os.path.isfile(p) else None


def _context(f, root, before=30, after=15):
    """엔진이 준 매칭 스니펫 대신, 실제 소스에서 감싸는 문맥을 읽어 반환.
    param 선언·sanitizer 가 매칭 창 밖에 있어도 보이게 한다(성립검증의 연료)."""
    path = _resolve(f, root)
    line = f.get("line", 0) or 0
    if not path or line <= 0:
        return f.get("code", "") or ""
    lines = _file_lines(path)
    if not lines:
        return f.get("code", "") or ""
    lo = max(0, line - 1 - before)
    hi = min(len(lines), line + after)
    return chr(10).join(lines[lo:hi])


def index_exchanges(exs):
    """캡처 exchange 를 (method,path) 로 인덱싱 — 도달성/응답 컨텍스트 조회용."""
    idx = {}
    for ex in exs or []:
        idx.setdefault((ex["method"], ex["path"]), []).append(ex)
        idx.setdefault(("*", ex["path"]), []).append(ex)
    return idx


def _matched_exchange(f, idx):
    """finding.file(엔드포인트 문자열) 또는 code 의 파라미터로 대응 exchange 추정."""
    if not idx:
        return None
    fileref = f.get("file", "") or ""
    # DAST/PASSIVE finding 은 file 이 URL — path 로 매칭
    path = urlparse(fileref).path if fileref.startswith("http") else ""
    if path and ("*", path) in idx:
        return idx[("*", path)][0]
    return None


def build_bundle(f, idx=None, root=None):
    """finding → 사실(fact) dict. 없는 사실은 넣지 않는다(=unknown)."""
    b = {}
    code = _context(f, root)          # 매칭 라인 아닌 감싸는 함수 문맥
    b["code"] = code
    b["category"] = f.get("category", "other")

    # 파라미터 제어성
    param = _first_group(_PARAM_RE.search(code)) or ""
    b["param"] = param
    b["idor_param"] = bool(param and _IDOR_NAME.search(param))

    # taint 흐름 확증 (crossval / codeql)
    engines = set(f.get("engines") or [])
    b["taint"] = bool(f.get("corroborated")) or ("codeql" in engines)

    # 도달성 (correlate)
    b["reachable"] = f.get("reachable", "unknown")

    # 동적 관측
    dyn = f.get("dynamic") or {}
    b["dyn_status"] = dyn.get("status", "")
    ev = (f.get("evidence") or "") + " " + (dyn.get("evidence") or "")
    b["db_error"] = bool(re.search(r"SQL\s*오류|sql error|db 오류|SQLException|ORA-\d", ev, re.I))
    b["oob_hit"] = bool(re.search(r"OOB\s*콜백|역접속|out-of-band", ev, re.I))
    b["idor_observed"] = bool(re.search(r"타 (객체|사용자).*id|BOLA|남의 객체", ev, re.I))
    b["reflected"] = bool(re.search(r"반사|reflect|미이스케이프", ev, re.I))

    # 방어 흔적 / 위험 싱크 (코드 토큰 휴리스틱)
    b["sanitizer"] = bool(_SANITIZE_TOK.search(code)) if code else None
    sink_re = _SINK_TOK.get(b["category"])
    b["dangerous_sink"] = bool(sink_re.search(code)) if (sink_re and code) else None

    # 응답 컨텍스트 (캡처 매칭 시)
    ex = _matched_exchange(f, idx)
    if ex:
        rct = (ex.get("mime") or "")
        b["resp_content_type"] = rct
        b["nonhtml_response"] = bool(_NONHTML_CT.search(rct)) if rct else None
        b["html_response"] = "html" in rct.lower() if rct else None
    return b


# ── 전제조건 평가기 ─────────────────────────────────────────────
# 각 함수: (bundle) -> (state, evidence, hard)
#   state: "satisfied" | "failed" | "unknown"
#   hard : True 면 결정론적 근거(오프라인). failed+hard 만 refuted(하드 오탐) 가능.

def _sat(msg, hard=True):   return ("satisfied", msg, hard)
def _fail(msg, hard=True):  return ("failed", msg, hard)
def _unk(msg=""):           return ("unknown", msg, False)


def _input_controllable(b):
    if b.get("param"):
        return _sat(f"싱크에 닿는 파라미터 '{b['param']}' 식별", hard=False)
    if b.get("taint"):
        return _sat("taint 엔진이 소스→싱크 흐름 확증", hard=False)
    return _unk("입력 파라미터 미식별 — 코드 확인 필요")

def _taint_flow(b):
    return _sat("taint 흐름 확증(2엔진/CodeQL)", hard=False) if b.get("taint") else _unk()

def _reachable(b):
    r = b.get("reachable")
    if r == "reachable":
        return _sat("캡처에서 대응 엔드포인트 관측(도달 가능)", hard=False)
    if r == "unobserved":
        return _unk("캡처에 미관측 — 도달성 불명(캡처는 부분적)")
    return _unk("도달성 미확인")

def _dangerous_sink(b):
    v = b.get("dangerous_sink")
    if v is True:
        return _sat(f"위험 싱크 토큰 확인({b['category']})", hard=False)
    if v is False:
        return _unk("코드에 명확한 위험 싱크 토큰 없음 — LLM 확인")
    return _unk()

def _no_neutralization(b):
    s = b.get("sanitizer")
    if s is True:
        return _fail("싱크 경로에 방어(이스케이프/파라미터라이즈/allowlist) 흔적 — 중화됨", hard=False)
    if s is False:
        return _sat("코드에 방어 흔적 없음", hard=False)
    return _unk()

def _html_context(b):
    if b.get("nonhtml_response") is True:
        return _fail(f"응답이 비-HTML({b.get('resp_content_type')}) — 태그/핸들러 탈출 불가", hard=True)
    if b.get("html_response") is True:
        return _sat("응답 content-type text/html — HTML 컨텍스트", hard=True)
    return _unk("출력 컨텍스트 미확인")

def _reaches_response(b):
    if b.get("reflected"):
        return _sat("입력이 응답에 반사 관측", hard=False)
    return _unk("반사 미관측 — 정적 스캔이면 동적 확인 필요")

def _no_output_encoding(b):
    if b.get("reflected") and b.get("sanitizer") is False:
        return _sat("반사값이 원문 그대로 + 인코딩 흔적 없음", hard=False)
    if b.get("sanitizer") is True:
        return _fail("출력 인코딩/이스케이프 흔적 있음", hard=False)
    return _unk()

def _injectable_signal(b):
    if b.get("db_error"):
        return _sat("응답에 DB 오류 노출(주입 정황)", hard=True)
    if b.get("dyn_status") in ("confirmed", "corroborated"):
        return _sat("동적 관측으로 확증", hard=True)
    return _unk("주입 신호 미관측")

def _dynamic_signal(b):
    if b.get("oob_hit"):
        return _sat("OOB 역접속 수신 — blind 확증", hard=True)
    if b.get("dyn_status") in ("confirmed", "corroborated"):
        return _sat("동적 관측 확증", hard=True)
    return _unk("동적 신호 미관측")

def _confirmed_callback(b):
    return _sat("OOB 역접속 수신", hard=True) if b.get("oob_hit") else _unk("OOB 콜백 없음")

def _object_ref_param(b):
    if b.get("idor_param"):
        return _sat(f"객체참조 파라미터 '{b['param']}'", hard=True)
    return _unk("객체참조 파라미터 미식별")

def _no_ownership_check(b):
    if b.get("idor_observed"):
        return _sat("타 객체 id 로 데이터 반환 관측(인가 부재)", hard=True)
    return _unk("교차 접근 미검증 — 수동/2계정 확인 필요")

def _auth_context(b):
    if b.get("dyn_status") or b.get("reachable") == "reachable":
        return _sat("인증/관측 컨텍스트 존재", hard=False)
    return _unk()


EVALUATORS = {
    "input_controllable": _input_controllable,
    "input_controllable_url": _input_controllable,
    "object_ref_param": _object_ref_param,
    "taint_flow": _taint_flow,
    "reachable": _reachable,
    "returns_object_data": _reachable,
    "dynamic_query": _dangerous_sink,
    "flows_to_shell": _dangerous_sink,
    "flows_to_eval": _dangerous_sink,
    "flows_to_template": _dangerous_sink,
    "flows_to_fs": _dangerous_sink,
    "flows_to_outbound": _dangerous_sink,
    "flows_to_redirect": _dangerous_sink,
    "flows_to_ldap": _dangerous_sink,
    "flows_to_xpath": _dangerous_sink,
    "flows_to_log": _dangerous_sink,
    "flows_to_header": _dangerous_sink,
    "xml_external_entities": _dangerous_sink,
    "merge_sink": _dangerous_sink,
    "deser_sink": _dangerous_sink,
    "no_neutralization": _no_neutralization,
    "no_path_neutralization": _no_neutralization,
    "no_target_allowlist": _no_neutralization,
    "no_url_validation": _no_neutralization,
    "no_output_encoding": _no_output_encoding,
    "html_context": _html_context,
    "reaches_response": _reaches_response,
    "injectable_signal": _injectable_signal,
    "dynamic_signal": _dynamic_signal,
    "confirmed_callback": _confirmed_callback,
    "no_ownership_check": _no_ownership_check,
    "auth_context": _auth_context,
}


def evaluate(cid, bundle):
    fn = EVALUATORS.get(cid)
    if not fn:
        return _unk("평가기 미정의")
    return fn(bundle)
