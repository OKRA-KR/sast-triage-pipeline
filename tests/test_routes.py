"""SAST→DAST 라우트 다리 — 프레임워크별 라우트 추출 + 교환 변환."""
import os
from sast import routes


def _write(tmp, name, text):
    p = os.path.join(tmp, name)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    open(p, "w", encoding="utf-8").write(text)
    return p


def test_spring_mapping_and_params(tmp_path):
    _write(str(tmp_path), "src/main/java/Idor.java", """
        public class Idor implements AssignmentEndpoint {
          @PostMapping("/IDOR/login")
          public AttackResult login(@RequestParam String username, @RequestParam String password) { }
          @GetMapping("/IDOR/profile/{userId}")
          public String view(@PathVariable("userId") String id) { }
        }
    """)
    R = routes.extract_routes(str(tmp_path))
    by = {(r["method"], r["path"]): r for r in R}
    assert ("POST", "/IDOR/login") in by
    assert set(by[("POST", "/IDOR/login")]["params"]) == {"username", "password"}
    # 경로변수 {userId} → 프로브 경로는 /IDOR/profile/1, 파라미터로도 기록
    assert ("GET", "/IDOR/profile/1") in by
    assert "userId" in by[("GET", "/IDOR/profile/1")]["params"]


def test_spring_class_prefix(tmp_path):
    _write(str(tmp_path), "src/main/java/Api.java", """
        @RequestMapping("/api/v1")
        public class Api {
          @GetMapping("/users")
          public void users() {}
        }
    """)
    R = routes.extract_routes(str(tmp_path))
    paths = {r["path"] for r in R}
    assert "/api/v1/users" in paths


def test_flask_and_methods(tmp_path):
    _write(str(tmp_path), "app.py", """
        @app.route("/login", methods=["GET", "POST"])
        def login(): pass
        @app.get("/health")
        def health(): pass
    """)
    R = routes.extract_routes(str(tmp_path))
    pairs = {(r["method"], r["path"]) for r in R}
    assert ("GET", "/login") in pairs and ("POST", "/login") in pairs
    assert ("GET", "/health") in pairs


def test_express(tmp_path):
    _write(str(tmp_path), "routes.js", """
        router.post('/api/order/:id', h);
        app.get('/api/list', h);
    """)
    R = routes.extract_routes(str(tmp_path))
    by = {(r["method"], r["path"]): r for r in R}
    assert ("POST", "/api/order/1") in by
    assert "id" in by[("POST", "/api/order/1")]["params"]
    assert ("GET", "/api/list") in by


def test_skips_test_dirs(tmp_path):
    _write(str(tmp_path), "src/test/java/FooTest.java", '@GetMapping("/should/not/appear")')
    R = routes.extract_routes(str(tmp_path))
    assert all("/should/not/appear" != r["path"] for r in R)


def test_to_exchanges(tmp_path):
    rs = [dict(method="POST", path="/SqlInjection/attack", template="/SqlInjection/attack",
               params=["query"], framework="spring", source="x.java"),
          dict(method="GET", path="/IDOR/profile/1", template="/IDOR/profile/{id}",
               params=["userId"], framework="spring", source="y.java")]
    exs = routes.to_exchanges(rs, "http://h/WebGoat", cookie="SID=1")
    post = next(e for e in exs if e["method"] == "POST")
    assert post["url"] == "http://h/WebGoat/SqlInjection/attack"
    assert "query=1" in post["req_body"]
    get = next(e for e in exs if e["method"] == "GET")
    assert get["url"].startswith("http://h/WebGoat/IDOR/profile/1?userId=1")
