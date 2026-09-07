"""Burp Scanner 이슈 export(XML) 파싱 → finding 병합 검증."""
import base64
from sast import capture


def _write(tmp_path, issues_xml):
    p = tmp_path / "burp_issues.xml"
    p.write_text('<?xml version="1.0"?>\n<!DOCTYPE issues [<!ELEMENT issues (issue*)>]>\n'
                 '<issues burpVersion="2024.9">\n' + issues_xml + '\n</issues>', encoding="utf-8")
    return str(p)


def _rr():
    req = base64.b64encode(b"GET /search?q=x HTTP/1.1\r\nHost: t\r\nCookie: SID=1\r\n\r\n").decode()
    resp = base64.b64encode(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>x</html>").decode()
    return (f'<requestresponse><request base64="true" method="GET"><![CDATA[{req}]]></request>'
            f'<response base64="true"><![CDATA[{resp}]]></response></requestresponse>')


ISSUE_SQLI = (
    '<issue><type>1049088</type><name>SQL injection</name>'
    '<host ip="1.2.3.4">http://t</host><path>/search</path><location>/search [q parameter]</location>'
    '<severity>High</severity><confidence>Firm</confidence>'
    '<issueDetail><![CDATA[The <b>q</b> parameter is vulnerable.]]></issueDetail>'
    '<remediationDetail><![CDATA[<p>Use parameterized queries.</p>]]></remediationDetail>'
    '<vulnerabilityClassifications><![CDATA[<a href="x">CWE-89</a>]]></vulnerabilityClassifications>'
    + _rr() + '</issue>')

ISSUE_XSS_TENTATIVE = (
    '<issue><type>2097936</type><name>Cross-site scripting (reflected)</name>'
    '<host>http://t</host><path>/echo</path><location>/echo [name]</location>'
    '<severity>Medium</severity><confidence>Tentative</confidence>'
    '<issueDetail><![CDATA[Reflected value.]]></issueDetail>'
    '<vulnerabilityClassifications><![CDATA[CWE-79]]></vulnerabilityClassifications></issue>')


def test_is_burp_issues_detects(tmp_path):
    p = _write(tmp_path, ISSUE_SQLI)
    assert capture.is_burp_issues(p) is True


def test_proxy_items_not_misdetected(tmp_path):
    # 프록시 items export(<items>)는 Burp 이슈로 오판하면 안 됨
    p = tmp_path / "items.xml"
    p.write_text('<?xml version="1.0"?>\n<items><item><url>http://t/</url></item></items>', encoding="utf-8")
    assert capture.is_burp_issues(str(p)) is False


def test_sqli_firm_is_confirmed(tmp_path):
    fs, exs = capture.parse_burp_issues(_write(tmp_path, ISSUE_SQLI))
    assert len(fs) == 1
    f = fs[0]
    assert f["category"] == "sql-injection"
    assert f["severity"] == "high"
    assert f["verdict"] == "true_positive"                      # Firm → 확정
    assert (f.get("dynamic") or {}).get("status") == "confirmed"
    assert "CWE-89" in f["cwe"]
    assert f["source"] == "BURP"
    assert "parameteriz" in f["fix"].lower()
    assert len(exs) == 1 and exs[0]["path"] == "/search"        # requestresponse → exchange


def test_tentative_is_needs_review(tmp_path):
    fs, _ = capture.parse_burp_issues(_write(tmp_path, ISSUE_XSS_TENTATIVE))
    f = fs[0]
    assert f["category"] == "xss"                               # CWE-79 로 분류
    assert f["verdict"] == "needs_review"                       # Tentative → 검토대상
    assert f.get("dynamic") is None                             # 확정 아님


def test_dedup_same_issue(tmp_path):
    fs, _ = capture.parse_burp_issues(_write(tmp_path, ISSUE_SQLI + "\n" + ISSUE_SQLI))
    assert len(fs) == 1                                          # 동일 지문 중복 제거
