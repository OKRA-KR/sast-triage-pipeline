"""A: 요청 바디 필드 마이닝 — JSON-API 주입점 확보(Spring @RequestBody DTO·Python·Express)."""
import os, json
from sast import routes


def _w(tmp, name, text):
    p = os.path.join(tmp, name)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    open(p, "w", encoding="utf-8").write(text)


def test_spring_requestbody_dto_fields(tmp_path):
    t = str(tmp_path)
    _w(t, "src/main/java/AuthController.java", """
        public class AuthController {
          @PostMapping("/api/auth/login")
          public ResponseEntity login(@RequestBody LoginForm form) { }
        }
    """)
    _w(t, "src/main/java/dto/LoginForm.java", """
        public class LoginForm {
          private static final long serialVersionUID = 1L;
          private String email;
          private String password;
          public String getEmail() { return email; }
        }
    """)
    R = {(r["method"], r["path"]): r for r in routes.extract_routes(t)}
    r = R[("POST", "/api/auth/login")]
    assert set(r["params"]) == {"email", "password"}   # DTO 필드가 주입점으로
    assert r["body"] == "json"
    assert "serialVersionUID" not in r["params"]        # 상수/노이즈 제외


def test_python_request_data_fields(tmp_path):
    t = str(tmp_path)
    _w(t, "views.py", """
@app.route("/api/order", methods=["POST"])
def create_order():
    name = request.data.get("product_name")
    qty = request.data['quantity']
    return ok()
""")
    R = {(r["method"], r["path"]): r for r in routes.extract_routes(t)}
    r = R[("POST", "/api/order")]
    assert set(r["params"]) >= {"product_name", "quantity"}
    assert r["body"] == "json"


def test_express_reqbody_fields(tmp_path):
    t = str(tmp_path)
    _w(t, "routes.js", """
      router.post('/api/login', (req, res) => {
        const { email, password } = req.body;
        const t = req.body.token;
      });
    """)
    R = {(r["method"], r["path"]): r for r in routes.extract_routes(t)}
    r = R[("POST", "/api/login")]
    assert set(r["params"]) >= {"email", "password", "token"}
    assert r["body"] == "json"


def test_to_exchanges_json_body():
    rs = [dict(method="POST", path="/api/auth/login", template="/api/auth/login",
               params=["email", "password"], framework="spring", body="json")]
    ex = routes.to_exchanges(rs, "http://h")[0]
    assert ex["req_headers"]["content-type"] == "application/json"
    obj = json.loads(ex["req_body"])
    assert set(obj) == {"email", "password"}            # JSON 바디에 실제 필드 → replay 가 리프 주입
