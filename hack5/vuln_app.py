#!/usr/bin/env python3
"""
5단계 취약 웹앱 (상급, 교육용, localhost 전용).

1~4단계가 입력값 자체를 조작해 서버를 속이는 취약점이었다면,
5단계는 "입력은 멀쩡한데 서버가 흐름/권한을 안 지킨다"는 결함,
즉 접근제어(access control)와 비즈니스 로직 결함을 다룹니다.

경고: 고의로 취약. 127.0.0.1 에서 학습용으로만.
의존성 없음. 실행: python vuln_app.py  →  http://127.0.0.1:8004

포함 챌린지:
  1. Mass Assignment — 폼에 없는 필드도 서버가 그대로 반영해 권한 상승
  2. 결제 단계 건너뛰기 — /confirm이 /pay를 거쳤는지 검사하지 않음
  3. 음수 수량/가격 조작 — 클라이언트가 부른 값으로 총액을 계산
"""

import html
import os
import sqlite3
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln5.db")
HOST, PORT = "127.0.0.1", 8004

# 로그인 세션: 쿠키에 사용자명을 평문으로 저장 (이 단계의 주제는 아니라 단순화함).
# 장바구니/주문 상태: 서버 메모리에 order_id -> 주문정보 로 저장.
ORDERS = {}
_NEXT_ORDER_ID = [1]


# --------------------------------------------------------------------------
def init_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, "
        "email TEXT, bio TEXT, role TEXT)"
    )
    cur.executemany(
        "INSERT INTO users (username, password, email, bio, role) VALUES (?,?,?,?,?)",
        [
            ("alice", "password123", "alice@example.com", "안녕하세요, alice입니다.", "user"),
            ("bob", "qwerty", "bob@example.com", "안녕하세요, bob입니다.", "user"),
            ("admin", "s3cr3t_admin_pw", "admin@example.com", "시스템 관리자", "admin"),
        ],
    )
    con.commit()
    con.close()


def db():
    return sqlite3.connect(DB_PATH)


# --------------------------------------------------------------------------
CSS = """
<style>
  body{font-family:system-ui,Segoe UI,Arial,sans-serif;max-width:900px;margin:0 auto;
       padding:1rem;background:#120f1a;color:#e6e6e6;line-height:1.5}
  a{color:#c792ea} h1,h2{color:#fff}
  nav{display:flex;gap:.6rem;flex-wrap:wrap;padding:.75rem 0;border-bottom:1px solid #333;margin-bottom:1rem}
  nav a{padding:.3rem .6rem;background:#1e1830;border-radius:6px;text-decoration:none}
  .card{background:#191428;border:1px solid #2e2547;border-radius:10px;padding:1rem;margin:1rem 0}
  .hint{background:#241a0d;border-left:3px solid #d09a3a;padding:.6rem .9rem;margin:.6rem 0;border-radius:4px}
  .flag{color:#7ee787;font-weight:bold}
  input,textarea{background:#120f1a;color:#e6e6e6;border:1px solid #3a3255;border-radius:6px;
                 padding:.45rem;font-size:1rem;width:100%;max-width:440px;box-sizing:border-box}
  button{background:#8957e5;color:#fff;border:0;border-radius:6px;padding:.5rem 1rem;
         font-size:1rem;cursor:pointer;margin-top:.5rem}
  code,pre{background:#0c0a14;padding:.15rem .35rem;border-radius:4px;color:#e3b6ff}
  pre{padding:.8rem;overflow:auto;display:block}
  .warn{background:#3a1414;border:1px solid #7a2222;padding:.6rem;border-radius:8px;color:#ffb4b4}
  details summary{cursor:pointer;color:#d09a3a}
  label{display:block;margin:.5rem 0 .2rem}
  .lvl{font-size:.8rem;background:#3a1a1a;color:#ffb4a6;padding:.1rem .5rem;border-radius:10px}
</style>
"""

NAV = """
<nav>
  <a href="/">🏠 홈</a>
  <a href="/login">1. Mass Assignment</a>
  <a href="/cart">2·3. 장바구니/결제</a>
  <a href="/admin">관리자 페이지</a>
</nav>
"""


def page(title, body):
    return f"""<!doctype html><html lang="ko"><head><meta charset="utf-8">
<title>{title}</title>{CSS}</head><body>{NAV}{body}</body></html>""".encode("utf-8")


def get_cookie(headers, name):
    raw = headers.get("Cookie", "")
    for part in raw.split(";"):
        if "=" in part:
            k, v = part.strip().split("=", 1)
            if k == name:
                return v
    return None


# --------------------------------------------------------------------------
def view_home():
    body = """
    <h1>🗝️ 5단계 취약 웹앱 <span class="lvl">상급 — 접근제어/비즈니스 로직</span></h1>
    <div class="warn">고의로 취약. 127.0.0.1 학습 전용. 외부 노출 금지.</div>
    <p>지금까지는 입력값 자체(SQL, HTML, 명령어, 경로, 토큰)를 조작해 서버를 속였습니다.
    이번 단계는 다릅니다: <b>입력값은 멀쩡한데, 서버가 "누가 무엇을 할 수 있는지"
    "어떤 순서로 해야 하는지"를 제대로 지키지 않는</b> 결함입니다.</p>
    <div class="card">
      <h2>이 단계에서 새로 배우는 것</h2>
      <ul>
        <li><b>Mass Assignment</b> — 폼이 보여주지 않는 필드도 서버가 그대로 반영</li>
        <li><b>흐름 건너뛰기(Broken Workflow)</b> — 마지막 단계가 앞 단계를 거쳤는지 확인 안 함</li>
        <li><b>신뢰할 수 없는 클라이언트 값</b> — 가격/수량처럼 서버가 계산해야 할 값을 클라이언트가 부름</li>
      </ul>
    </div>
    <div class="card"><b>목표 FLAG 3개:</b> Mass Assignment로 관리자 승격,
    결제 단계 건너뛰기, 음수 가격 조작 — 각각에서 FLAG를 얻으세요.</div>
    """
    return page("5단계 취약 웹앱", body)


# 1) Mass Assignment ---------------------------------------------------------
def view_login(method, body_params, headers):
    msg = ""
    set_cookie = None
    if method == "POST":
        u = body_params.get("username", [""])[0]
        p = body_params.get("password", [""])[0]
        con = db()
        row = con.execute(
            "SELECT username FROM users WHERE username=? AND password=?", (u, p)
        ).fetchone()
        con.close()
        if row:
            set_cookie = row[0]
            msg = f'<div class="card">✅ {html.escape(row[0])}로 로그인했습니다. <a href="/profile">프로필로 이동</a></div>'
        else:
            msg = '<div class="warn">❌ 로그인 실패</div>'

    current = get_cookie(headers, "user")
    body = f"""
    <h1>1. Mass Assignment — 권한 상승</h1>
    <div class="card">
      <p>현재 로그인: <b>{html.escape(current) if current else "(없음)"}</b></p>
      <form method="post">
        <label>아이디</label><input name="username" autofocus>
        <label>비밀번호</label><input name="password">
        <button>로그인</button>
      </form>
      {msg}
    </div>
    <p>테스트 계정: <code>alice / password123</code>, <code>bob / qwerty</code></p>
    <p><b>🎯 목표:</b> 일반 계정으로 로그인한 뒤, <a href="/profile">프로필 수정</a> 요청에
    폼에는 없는 필드를 끼워 넣어 <code>admin</code> 권한을 얻고 <a href="/admin">관리자 페이지</a>의
    FLAG를 읽으세요.</p>
    <div class="hint">💡 힌트 1: 먼저 정상적으로 프로필(이메일/자기소개)을 수정해 보고, 서버가
      "제출한 필드를 그대로 저장"하는지 관찰하세요.</div>
    <div class="hint">💡 힌트 2: 프로필 폼에는 <code>role</code> 입력창이 없습니다. 하지만 서버가
      "폼에 있는 필드만" 검사하나요, 아니면 "온 값 전부"를 저장하나요? curl로 직접
      <code>role=admin</code> 필드를 추가해 POST 해 보세요.</div>
    <details><summary>정답 보기</summary>
      <pre>curl -c c.txt -b c.txt -X POST http://127.0.0.1:{PORT}/login \\
     -d "username=alice&password=password123"
curl -c c.txt -b c.txt -X POST http://127.0.0.1:{PORT}/profile \\
     -d "email=alice@example.com&bio=hi&role=admin"
curl -b c.txt http://127.0.0.1:{PORT}/admin</pre>
      <p><code>role</code>은 폼에 없던 필드지만, 서버가 body의 모든 필드를 그대로
      UPDATE에 사용하기 때문에 admin으로 승격됩니다. → <span class="flag">FLAG{{mass_assignment_privesc}}</span></p>
    </details>
    <div class="card"><b>🛡️ 방어:</b> 사용자 입력을 화이트리스트로 걸러
      (<code>email</code>, <code>bio</code>만) 명시적으로 반영하세요. <code>role</code>처럼
      민감한 필드는 별도의 관리자 전용 API로만 바꿀 수 있게 하세요.</div>
    """
    resp = page("Mass Assignment", body)
    return resp, set_cookie


def view_profile(method, body_params, headers):
    current = get_cookie(headers, "user")
    msg = ""
    if not current:
        msg = '<div class="warn">먼저 <a href="/login">로그인</a>하세요.</div>'
    else:
        con = db()
        if method == "POST":
            row = con.execute("SELECT username FROM users WHERE username=?", (current,)).fetchone()
            if row:
                allowed_columns = {"username", "password", "email", "bio", "role"}
                # 취약: 폼이 보여준 필드가 무엇이든 상관없이, 요청 본문에 온 필드를
                # 컬럼명이 일치하기만 하면 전부 UPDATE에 반영한다 (mass assignment).
                updates = {k: v[0] for k, v in body_params.items() if k in allowed_columns}
                if updates:
                    set_clause = ", ".join(f"{k}=?" for k in updates)
                    values = list(updates.values()) + [current]
                    con.execute(f"UPDATE users SET {set_clause} WHERE username=?", values)
                    con.commit()
                    msg = '<div class="card">✅ 프로필이 저장되었습니다.</div>'
        row = con.execute(
            "SELECT username, email, bio, role FROM users WHERE username=?", (current,)
        ).fetchone()
        con.close()
        if row:
            username, email, bio, role = row
            msg += f"""<div class="card">현재 role: <b>{html.escape(role)}</b>{' <span class="flag">(관리자!)</span>' if role == 'admin' else ''}</div>"""
            body_form = f"""
            <form method="post">
              <label>이메일</label><input name="email" value="{html.escape(email or '')}">
              <label>자기소개</label><textarea name="bio">{html.escape(bio or '')}</textarea>
              <button>저장</button>
            </form>
            """
            msg = body_form + msg

    body = f"""
    <h1>프로필 수정</h1>
    <div class="card">{msg}</div>
    <p>이 폼은 이메일/자기소개만 보여주지만, 서버가 실제로 검사하는 건
    <b>제출된 필드 이름</b>일 뿐입니다. <a href="/login">로그인 페이지</a>로 돌아가 힌트를 확인하세요.</p>
    """
    return page("프로필 수정", body)


def view_admin(headers):
    current = get_cookie(headers, "user")
    if not current:
        return page("관리자", '<div class="warn">로그인이 필요합니다. <a href="/login">로그인</a></div>'), 403
    con = db()
    row = con.execute("SELECT role FROM users WHERE username=?", (current,)).fetchone()
    con.close()
    if row and row[0] == "admin":
        body = f"""
        <h1>관리자 페이지</h1>
        <div class="card">환영합니다, <b>{html.escape(current)}</b> (role=admin).</div>
        <p class="flag">🎉 FLAG{{mass_assignment_privesc}}</p>
        """
        return page("관리자", body), 200
    body = f"""
    <h1>403 Forbidden</h1>
    <div class="warn">{html.escape(current)}(role=user)에게는 관리자 권한이 없습니다.</div>
    """
    return page("관리자", body), 403


# 2·3) 장바구니 / 결제 단계 건너뛰기 / 음수 가격 --------------------------------
def new_order():
    oid = _NEXT_ORDER_ID[0]
    _NEXT_ORDER_ID[0] += 1
    ORDERS[oid] = {"items": [], "total": 0, "paid": False, "pay_visited": False}
    return oid


def view_cart(method, params, body_params, headers):
    oid_raw = get_cookie(headers, "order_id")
    oid = int(oid_raw) if oid_raw and oid_raw.isdigit() and int(oid_raw) in ORDERS else None
    set_cookie = None
    neg_flag = ""

    if method == "POST":
        if oid is None:
            oid = new_order()
            set_cookie = str(oid)
        name = body_params.get("item", ["물건"])[0] or "물건"
        try:
            qty = int(body_params.get("qty", ["1"])[0])
        except ValueError:
            qty = 1
        try:
            price = int(body_params.get("price", ["1000"])[0])
        except ValueError:
            price = 1000
        # 취약: 수량/단가를 클라이언트가 부른 값 그대로 신뢰해 총액을 계산한다.
        # 서버가 상품 원가 테이블을 조회하거나, 음수/0 여부를 검증하지 않는다.
        item_total = qty * price
        order = ORDERS[oid]
        order["items"].append((name, qty, price, item_total))
        order["total"] += item_total
        if order["total"] <= 0:
            neg_flag = f'<p class="flag">🎉 FLAG{{negative_price_manipulation}} — 총액이 {order["total"]}원(0원 이하)인데 주문이 성립했습니다!</p>'

    items_html = ""
    total = 0
    if oid is not None:
        order = ORDERS[oid]
        total = order["total"]
        items_html = "".join(
            f"<div>{html.escape(n)} × {q}개 @ {p}원 = {t}원</div>" for n, q, p, t in order["items"]
        )

    order_block = ""
    if oid is not None:
        order_block = f"""
        <div class="card">
          <p>주문번호: <b>{oid}</b></p>
          {items_html or "<p>담긴 물건이 없습니다.</p>"}
          <p>총액: <b>{total}원</b></p>
          {neg_flag}
          <p><a href="/pay?order_id={oid}">결제하러 가기 →</a></p>
        </div>
        """

    body = f"""
    <h1>2·3. 장바구니 — 결제 단계 건너뛰기 / 음수 가격 조작</h1>
    <div class="card">
      <form method="post">
        <label>상품명</label><input name="item" value="한정판 키보드">
        <label>수량</label><input name="qty" value="1">
        <label>단가(원)</label><input name="price" value="150000">
        <button>장바구니 담기</button>
      </form>
    </div>
    {order_block}
    <p><b>🎯 목표 3 (음수 가격 조작):</b> 수량 또는 단가에 음수를 넣어 총액을 0원 이하로 만드세요.</p>
    <div class="hint">💡 힌트: 서버는 <code>qty * price</code>를 그대로 계산할 뿐, 값의 부호나 범위를
      검증하지 않습니다. 수량 칸에 <code>-1</code>을 넣어보세요.</div>
    <details><summary>정답 보기 (음수 가격)</summary>
      <pre>curl -c c.txt -X POST http://127.0.0.1:{PORT}/cart \\
     -d "item=키보드&qty=-1&price=150000"</pre>
      <p>총액이 -150000원이 되어 0원 이하 조건을 만족 →
      <span class="flag">FLAG{{negative_price_manipulation}}</span></p>
    </details>
    <p><b>🎯 목표 2 (결제 단계 건너뛰기):</b> 장바구니에 담은 뒤 <code>/pay</code>를 거치지 않고
      바로 <code>/confirm</code>을 호출해 "결제 완료" 상태를 만드세요.</p>
    <div class="hint">💡 힌트: 정상 흐름은 <code>/cart → /pay → /confirm</code> 3단계입니다.
      <code>/confirm</code>이 "정말 <code>/pay</code>를 거쳤는지"를 확인할까요?</div>
    <details><summary>정답 보기 (결제 건너뛰기)</summary>
      <pre>curl -c c.txt -X POST http://127.0.0.1:{PORT}/cart -d "item=키보드&qty=1&price=1000"
curl -b c.txt http://127.0.0.1:{PORT}/confirm?order_id=&lt;위에서 나온 order_id&gt;</pre>
      <p><code>/pay</code>를 한 번도 열지 않아도 <code>/confirm</code>이 바로 결제완료 처리를 합니다 →
      <span class="flag">FLAG{{skipped_payment_step}}</span></p>
    </details>
    <div class="card"><b>🛡️ 방어:</b> (2) 서버측 주문 상태 머신을 두고
      <code>/confirm</code>은 <code>status == 'payment_requested'</code>일 때만 처리하세요.
      (3) 가격은 서버가 보유한 카탈로그에서 조회하고, 수량은 <code>1 이상</code>인지 검증하세요.</div>
    """
    resp = page("장바구니", body)
    return resp, set_cookie


def view_pay(params, headers):
    oid_raw = params.get("order_id", [get_cookie(headers, "order_id") or ""])[0]
    oid = int(oid_raw) if oid_raw.isdigit() and int(oid_raw) in ORDERS else None
    if oid is None:
        body = '<div class="warn">유효한 주문번호가 없습니다. <a href="/cart">장바구니로</a></div>'
    else:
        ORDERS[oid]["pay_visited"] = True
        body = f"""
        <div class="card">
          <p>주문번호 {oid} 결제를 진행합니다. (실제 결제 연동은 없는 데모입니다)</p>
          <p><a href="/confirm?order_id={oid}">결제 완료 확인 →</a></p>
        </div>
        """
    return page("결제 진행", f"<h1>결제 진행 중</h1>{body}")


def view_confirm(params, headers):
    oid_raw = params.get("order_id", [get_cookie(headers, "order_id") or ""])[0]
    oid = int(oid_raw) if oid_raw.isdigit() and int(oid_raw) in ORDERS else None
    if oid is None:
        body = '<div class="warn">유효한 주문번호가 없습니다. <a href="/cart">장바구니로</a></div>'
        return page("결제 확인", f"<h1>결제 확인</h1>{body}")

    order = ORDERS[oid]
    # 취약: /pay를 거쳤는지(pay_visited) 확인하지 않고 그냥 paid=True로 만든다.
    skipped = not order["pay_visited"]
    order["paid"] = True
    flag = ""
    if skipped:
        flag = '<p class="flag">🎉 FLAG{skipped_payment_step} — /pay를 거치지 않고도 결제완료 처리되었습니다!</p>'
    body = f"""
    <h1>결제 확인</h1>
    <div class="card">
      <p>주문번호 {oid} 결제완료(paid=True) 처리되었습니다. 총액: {order['total']}원</p>
      {flag}
    </div>
    <p><a href="/cart">장바구니로 돌아가기</a></p>
    """
    return page("결제 확인", body)


# --------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    def _send(self, content, status=200, set_cookies=None):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        for name, value in (set_cookies or {}).items():
            self.send_header("Set-Cookie", f"{name}={value}; Path=/")
        self.end_headers()
        self.wfile.write(content)

    def _route(self, method):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        params = urllib.parse.parse_qs(parsed.query)
        body_params = {}
        if method == "POST":
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
            body_params = urllib.parse.parse_qs(raw)

        if path == "/":
            self._send(view_home())
        elif path == "/login":
            resp, set_cookie = view_login(method, body_params, self.headers)
            self._send(resp, set_cookies={"user": set_cookie} if set_cookie else None)
        elif path == "/profile":
            self._send(view_profile(method, body_params, self.headers))
        elif path == "/admin":
            resp, status = view_admin(self.headers)
            self._send(resp, status=status)
        elif path == "/cart":
            resp, set_cookie = view_cart(method, params, body_params, self.headers)
            self._send(resp, set_cookies={"order_id": set_cookie} if set_cookie else None)
        elif path == "/pay":
            self._send(view_pay(params, self.headers))
        elif path == "/confirm":
            self._send(view_confirm(params, self.headers))
        else:
            self._send(page("404", "<h1>404 Not Found</h1>"), status=404)

    def do_GET(self):
        self._route("GET")

    def do_POST(self):
        self._route("POST")

    def log_message(self, fmt, *args):
        print("[req]", self.address_string(), fmt % args)


def main():
    init_db()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"5단계 취약 웹앱 실행 중 → http://{HOST}:{PORT}  (Ctrl+C 로 종료)")
    print("경고: localhost 전용. 외부에 노출하지 마세요.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n종료합니다.")
        server.shutdown()


if __name__ == "__main__":
    main()
