"""P1-2: schema.categorize/fingerprint + capture 파서/엔드포인트."""
import base64, csv, json, os, tempfile
from sast import schema, capture


def test_categorize():
    assert schema.categorize("php-superglobal-sqli", ["CWE-89"]) == "sql-injection"
    assert schema.categorize("x", ["CWE-79"]) == "xss"
    assert schema.categorize("command-inj", ["CWE-78"]) == "command-injection"
    assert schema.categorize("weak-md5", ["CWE-327"]) == "weak-crypto"
    assert schema.categorize("totally-unknown-rule", []) == "other"


def test_fingerprint_stability():
    a = schema.fingerprint("r", "f.py", 10, "code")
    assert a == schema.fingerprint("r", "f.py", 10, "code")     # 안정
    assert a != schema.fingerprint("r", "f.py", 11, "code")     # 라인 다르면 다름
    assert a != schema.fingerprint("r2", "f.py", 10, "code")


def test_group_of():
    assert schema.group_of("sql-injection") == "injection"
    assert schema.group_of("idor") == "broken-access"
    assert schema.group_of("user-enumeration") == "info-disclosure"


_BURP = """<?xml version="1.0"?>
<items>
 <item>
  <url>https://t/api/x.php?p=1</url><host>t</host><port>443</port><protocol>https</protocol>
  <method>POST</method><path>/api/x.php</path><extension>php</extension>
  <request base64="true">{req}</request>
  <status>200</status><responselength>5</responselength><mimetype>HTML</mimetype>
  <response base64="true">{resp}</response><comment></comment>
 </item>
</items>"""


def _b64(s):
    return base64.b64encode(s.encode()).decode()


def test_parse_burp_and_body_params():
    req = "POST /api/x.php?p=1 HTTP/1.1\r\nHost: t\r\nCookie: SID=1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\na=1&b=2"
    resp = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nhi"
    xml = _BURP.format(req=_b64(req), resp=_b64(resp))
    with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False, encoding="utf-8") as fh:
        fh.write(xml); path = fh.name
    try:
        exs = capture.parse(path)
        assert len(exs) == 1
        ex = exs[0]
        assert ex["method"] == "POST" and ex["path"] == "/api/x.php"
        assert dict(ex["query"]).get("p") == "1"
        bp = {k for k, _, _ in capture._body_params(ex)}
        assert bp == {"a", "b"}
        assert ex["req_headers"].get("cookie") == "SID=1"
    finally:
        os.unlink(path)


def test_parse_har_json_body():
    har = {"log": {"entries": [{
        "request": {"method": "POST", "url": "https://t/api/y",
                    "headers": [{"name": "Content-Type", "value": "application/json"}],
                    "postData": {"text": json.dumps({"id": 7, "q": "z"})}},
        "response": {"status": 200, "headers": [], "content": {"mimeType": "application/json", "text": "{}"}}}]}}
    with tempfile.NamedTemporaryFile("w", suffix=".har", delete=False, encoding="utf-8") as fh:
        json.dump(har, fh); path = fh.name
    try:
        exs = capture.parse(path)
        assert exs[0]["method"] == "POST"
        bp = {k for k, _, _ in capture._body_params(exs[0])}
        assert bp == {"id", "q"}
    finally:
        os.unlink(path)


def test_endpoints_csv():
    req = "POST /api/pay.php HTTP/1.1\r\nHost: t\r\nCookie: SID=1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\ncorp_sn=1"
    resp = "HTTP/1.1 200 OK\r\n\r\nok"
    xml = _BURP.format(req=_b64(req), resp=_b64(resp)).replace("/api/x.php", "/api/pay.php")
    with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False, encoding="utf-8") as fh:
        fh.write(xml); path = fh.name
    outdir = tempfile.mkdtemp()
    try:
        exs = capture.parse(path)
        inv = capture.endpoints(exs)
        csvp = os.path.join(outdir, "e.csv")
        capture.write_endpoints_csv(inv, csvp)
        rows = list(csv.reader(open(csvp, encoding="utf-8-sig")))
        assert rows[0][:3] == ["method", "path", "params"]
        assert any(r[0] == "POST" and "corp_sn" in r[2] and r[4] == "Y" for r in rows[1:])
    finally:
        os.unlink(path)
