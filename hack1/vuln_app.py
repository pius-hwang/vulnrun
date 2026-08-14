#!/usr/bin/env python3
"""
DVWA-스타일 의도적 취약 웹앱 (교육용, localhost 전용).

경고: 이 앱은 '고의로' 취약하게 만들어졌습니다. 절대 공용 네트워크/서버에
띄우지 마세요. 오직 본인 PC(127.0.0.1)에서 학습용으로만 사용하세요.

의존성 없음 (Python 표준 라이브러리만 사용).
실행:  python vuln_app.py
접속:  http://127.0.0.1:8000
"""

import html
import http.cookies
import os
import sqlite3
import subprocess
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln.db")
HOST, PORT = "127.0.0.1", 8000

# 아주 단순한 "세션": 로그인하면 예측 가능한 토큰을 준다 (취약: Broken Auth).
SESSIONS = {}  # token -> username


# --------------------------------------------------------------------------
# DB 준비
# --------------------------------------------------------------------------
def init_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, secret TEXT)")
    cur.executemany(
        "INSERT INTO users (username, password, secret) VALUES (?,?,?)",
        [
            ("admin", "s3cr3t_admin_pw", "FLAG{admin_only_secret}"),
            ("alice", "password123", "alice의 일기장"),
            ("bob", "qwerty", "bob의 메모"),
        ],
    )
    cur.execute("CREATE TABLE comments (id INTEGER PRIMARY KEY, author TEXT, body TEXT)")
    cur.executemany(
        "INSERT INTO comments (author, body) VALUES (?,?)",
        [("alice", "첫 댓글입니다."), ("bob", "안녕하세요~")],
    )
    con.commit()
    con.close()


def db():
    return sqlite3.connect(DB_PATH)


# --------------------------------------------------------------------------
# HTML 레이아웃
# --------------------------------------------------------------------------
CSS = """
<style>
  body{font-family:system-ui,Segoe UI,Arial,sans-serif;max-width:900px;margin:0 auto;
       padding:1rem;background:#0f1117;color:#e6e6e6;line-height:1.5}
  a{color:#6cb6ff} h1,h2{color:#fff}
  nav{display:flex;gap:.75rem;flex-wrap:wrap;padding:.75rem 0;border-bottom:1px solid #333;margin-bottom:1rem}
  nav a{padding:.3rem .6rem;background:#1b1f2a;border-radius:6px;text-decoration:none}
  .card{background:#161a23;border:1px solid #2a2f3a;border-radius:10px;padding:1rem;margin:1rem 0}
  .hint{background:#20160b;border-left:3px solid #d08a3a;padding:.6rem .9rem;margin:.6rem 0;border-radius:4px}
  .flag{color:#7ee787;font-weight:bold}
  input,textarea{background:#0f1117;color:#e6e6e6;border:1px solid #3a3f4a;border-radius:6px;
                 padding:.45rem;font-size:1rem;width:100%;max-width:420px;box-sizing:border-box}
  button{background:#238636;color:#fff;border:0;border-radius:6px;padding:.5rem 1rem;
         font-size:1rem;cursor:pointer;margin-top:.5rem}
  code,pre{background:#0b0e14;padding:.15rem .35rem;border-radius:4px;color:#ffa657}
  pre{padding:.8rem;overflow:auto;display:block}
  .warn{background:#3a1414;border:1px solid #7a2222;padding:.6rem;border-radius:8px;color:#ffb4b4}
  details summary{cursor:pointer;color:#d08a3a}
  label{display:block;margin:.5rem 0 .2rem}
</style>
"""

NAV = """
<nav>
  <a href="/">🏠 홈</a>
  <a href="/login">1. SQL Injection</a>
  <a href="/greet">2. Reflected XSS</a>
  <a href="/comments">3. Stored XSS</a>
  <a href="/ping">4. Command Injection</a>
  <a href="/read">5. Path Traversal</a>
</nav>
"""


def page(title, body):
    return f"""<!doctype html><html lang="ko"><head><meta charset="utf-8">
<title>{title}</title>{CSS}</head><body>{NAV}{body}</body></html>""".encode("utf-8")


# --------------------------------------------------------------------------
# 각 챌린지 페이지
# --------------------------------------------------------------------------
def view_home():
    body = """
    <h1>🩸 취약 웹 연습장 (DVWA-lite)</h1>
    <div class="warn">이 앱은 <b>고의로 취약</b>합니다. localhost(127.0.0.1)에서만,
    본인 학습용으로만 쓰세요. 외부에 노출하지 마세요.</div>
    <p>왼쪽 위 메뉴의 5개 챌린지를 순서대로 풀어보세요. 각 페이지에 <b>목표 · 힌트 · 정답(펼치기)</b>이 있습니다.</p>
    <div class="card">
      <h2>연습 방법</h2>
      <ol>
        <li>먼저 정상적으로 기능을 써 봅니다 (로그인, 인사, 댓글 등).</li>
        <li>입력값에 특수문자를 넣어 앱이 어떻게 반응하는지 관찰합니다.</li>
        <li>힌트를 참고해 공격 payload를 만들고, 막히면 정답을 펼쳐 확인합니다.</li>
        <li>왜 뚫렸는지, 어떻게 고치는지(방어법)를 각 페이지 하단에서 읽습니다.</li>
      </ol>
    </div>
    <div class="card">
      <h2>테스트 계정</h2>
      <p>일반 로그인용: <code>alice / password123</code>, <code>bob / qwerty</code><br>
      숨겨진 목표: <code>admin</code> 계정으로 로그인해 <span class="flag">FLAG</span>를 얻으세요.</p>
    </div>
    """
    return page("취약 웹 연습장", body)


# 1) SQL Injection ----------------------------------------------------------
def view_login(params, method, body_params, headers):
    msg = ""
    if method == "POST":
        u = body_params.get("username", [""])[0]
        p = body_params.get("password", [""])[0]
        # 취약: 사용자 입력을 문자열로 직접 SQL에 이어붙임
        query = f"SELECT username, secret FROM users WHERE username='{u}' AND password='{p}'"
        con = db()
        try:
            rows = con.execute(query).fetchall()
        except Exception as e:
            rows = []
            msg = f'<div class="warn">SQL 오류: {html.escape(str(e))}</div>'
        con.close()
        if rows:
            name = rows[0][0]
            secret = rows[0][1]
            flag = ""
            if name == "admin" or any(r[0] == "admin" for r in rows):
                flag = '<p class="flag">🎉 FLAG{admin_only_secret} 획득! admin secret을 읽었습니다.</p>'
            secrets = "<br>".join(f"{html.escape(str(r[0]))}: {html.escape(str(r[1]))}" for r in rows)
            msg = f'<div class="card">✅ 로그인/조회 성공:<br>{secrets}{flag}</div>'
        elif not msg:
            msg = '<div class="warn">❌ 로그인 실패</div>'
        # 디버그: 실제 실행된 쿼리를 노출 (학습 편의)
        msg += f"<p>실행된 쿼리:</p><pre>{html.escape(query)}</pre>"

    body = f"""
    <h1>1. SQL Injection — 로그인 우회</h1>
    <div class="card">
      <form method="post">
        <label>아이디</label><input name="username" autofocus>
        <label>비밀번호</label><input name="password" type="text">
        <button>로그인</button>
      </form>
      {msg}
    </div>
    <p><b>🎯 목표:</b> admin의 비밀번호를 모른 채, admin으로 로그인해 FLAG를 읽으세요.</p>
    <div class="hint">💡 힌트 1: 아이디 칸에 작은따옴표 <code>'</code> 하나만 넣어보세요. 오류 메시지가 뭘 알려주나요?</div>
    <div class="hint">💡 힌트 2: SQL의 <code>WHERE</code> 조건을 항상 참으로 만들거나, 조건을 <code>--</code>로 주석 처리해 없앨 수 있습니다.</div>
    <details><summary>정답 보기</summary>
      <p>아이디 칸에: <code>admin'--</code> (비밀번호는 아무거나)<br>
      또는 아이디: <code>' OR '1'='1' --</code></p>
      <p>실행 쿼리가 <code>... WHERE username='admin'--' AND password='...'</code> 가 되어
      비밀번호 조건이 주석 처리됩니다.</p>
    </details>
    <div class="card"><b>🛡️ 방어:</b> 문자열 연결 대신 <b>파라미터 바인딩(prepared statement)</b>을 쓰세요.
      <pre>con.execute("SELECT ... WHERE username=? AND password=?", (u, p))</pre>
    </div>
    """
    return page("SQL Injection", body)


# 2) Reflected XSS ----------------------------------------------------------
def view_greet(params):
    name = params.get("name", [""])[0]
    greeting = ""
    if name:
        # 취약: 입력을 이스케이프 없이 HTML에 그대로 삽입
        greeting = f"<div class='card'>안녕하세요, {name}님!</div>"
    body = f"""
    <h1>2. Reflected XSS — 반사형 XSS</h1>
    <div class="card">
      <form method="get">
        <label>이름</label><input name="name" value="{html.escape(name)}">
        <button>인사받기</button>
      </form>
    </div>
    {greeting}
    <p><b>🎯 목표:</b> 이름 입력으로 JavaScript를 실행시키세요 (경고창 대신 콘솔 로그 권장).</p>
    <div class="warn">주의: 브라우저 자동화 세션에서는 <code>alert()</code> 대신
      <code>console.log</code> 나 DOM 변경으로 확인하는 게 안전합니다.</div>
    <div class="hint">💡 힌트: 입력이 <code>&lt;div&gt;</code> 안에 그대로 들어갑니다. <code>&lt;img&gt;</code>나
      <code>&lt;svg&gt;</code>의 이벤트 핸들러를 이용하면 스크립트가 실행됩니다.</div>
    <details><summary>정답 보기</summary>
      <p>이름 칸에: <code>&lt;img src=x onerror="document.body.style.background='red'"&gt;</code><br>
      또는: <code>&lt;svg onload="console.log('XSS')"&gt;</code></p>
    </details>
    <div class="card"><b>🛡️ 방어:</b> 출력 시 HTML 이스케이프(<code>html.escape</code>)하거나,
      템플릿 엔진의 자동 이스케이프를 켜세요.</div>
    """
    return page("Reflected XSS", body)


# 3) Stored XSS -------------------------------------------------------------
def view_comments(method, body_params):
    if method == "POST":
        author = body_params.get("author", ["익명"])[0] or "익명"
        text = body_params.get("body", [""])[0]
        if text:
            con = db()
            con.execute("INSERT INTO comments (author, body) VALUES (?,?)", (author, text))
            con.commit()
            con.close()
    con = db()
    rows = con.execute("SELECT author, body FROM comments ORDER BY id").fetchall()
    con.close()
    # 취약: 저장된 값을 이스케이프 없이 렌더 → 저장형 XSS
    items = "".join(f"<div class='card'><b>{a}</b><br>{b}</div>" for a, b in rows)
    body = f"""
    <h1>3. Stored XSS — 저장형 XSS</h1>
    <div class="card">
      <form method="post">
        <label>이름</label><input name="author">
        <label>댓글</label><textarea name="body" rows="3"></textarea>
        <button>등록</button>
      </form>
    </div>
    <h2>댓글 목록</h2>
    {items}
    <p><b>🎯 목표:</b> 댓글에 스크립트를 심어, 이 페이지를 여는 <b>모든 사람</b>에게 실행되게 하세요.</p>
    <div class="hint">💡 힌트: 반사형 XSS와 같은 payload지만, 이번엔 DB에 저장되어 새로고침해도 남아 있습니다.</div>
    <details><summary>정답 보기</summary>
      <p>댓글 칸에: <code>&lt;img src=x onerror="console.log('stored XSS by '+document.cookie)"&gt;</code></p>
      <p>등록 후 페이지를 새로고침하면 매번 실행됩니다. (실제 공격에선 세션 쿠키 탈취에 쓰입니다)</p>
    </details>
    <div class="card"><b>🛡️ 방어:</b> 저장은 원본 그대로 하되 <b>출력할 때 이스케이프</b>하고,
      <code>Content-Security-Policy</code> 헤더로 인라인 스크립트를 차단하세요.</div>
    """
    return page("Stored XSS", body)


# 4) Command Injection ------------------------------------------------------
def view_ping(method, body_params):
    out = ""
    if method == "POST":
        host = body_params.get("host", [""])[0]
        # 취약: 사용자 입력을 shell 명령에 그대로 결합
        cmd = f"ping -n 1 {host}" if os.name == "nt" else f"ping -c 1 {host}"
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            out = result.stdout + result.stderr
        except Exception as e:
            out = str(e)
        out = f"<p>실행: <code>{html.escape(cmd)}</code></p><pre>{html.escape(out)}</pre>"
    body = f"""
    <h1>4. Command Injection — 명령어 주입</h1>
    <div class="card">
      <form method="post">
        <label>ping 할 호스트</label><input name="host" placeholder="127.0.0.1">
        <button>Ping</button>
      </form>
      {out}
    </div>
    <p><b>🎯 목표:</b> ping 외의 시스템 명령을 실행시키세요 (예: <code>whoami</code>, 디렉토리 목록).</p>
    <div class="hint">💡 힌트: 셸은 <code>&amp;</code>, <code>&amp;&amp;</code>, <code>|</code>, <code>;</code> 같은 문자로
      명령을 이어붙일 수 있습니다. (Windows cmd 에서는 <code>&amp;</code> / <code>&amp;&amp;</code>)</div>
    <details><summary>정답 보기</summary>
      <p>호스트 칸에 (Windows): <code>127.0.0.1 &amp; whoami</code><br>
      또는: <code>127.0.0.1 &amp; dir</code></p>
      <p>ping 결과 뒤에 <code>whoami</code> 출력이 함께 나오면 성공입니다.</p>
    </details>
    <div class="card"><b>🛡️ 방어:</b> <code>shell=True</code>를 쓰지 말고 인자를 리스트로 전달하세요.
      <pre>subprocess.run(["ping", "-n", "1", host])  # 셸 해석 없음</pre>
      입력값은 화이트리스트(호스트명/IP 형식)로 검증하세요.</div>
    """
    return page("Command Injection", body)


# 5) Path Traversal ---------------------------------------------------------
def view_read(params):
    filename = params.get("file", [""])[0]
    content = ""
    base = os.path.join(os.path.dirname(os.path.abspath(__file__)), "files")
    os.makedirs(base, exist_ok=True)
    # 샘플 파일 준비
    sample = os.path.join(base, "welcome.txt")
    if not os.path.exists(sample):
        with open(sample, "w", encoding="utf-8") as f:
            f.write("공개 파일입니다. 다른 파일도 읽을 수 있을까요?")
    secret_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "SECRET.txt")
    if not os.path.exists(secret_file):
        with open(secret_file, "w", encoding="utf-8") as f:
            f.write("FLAG{path_traversal_success} — files/ 밖의 비밀 파일입니다.")
    if filename:
        # 취약: base와 사용자 입력을 그대로 결합, 정규화/검증 없음
        target = os.path.join(base, filename)
        try:
            with open(target, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            content = f"<p>읽은 파일: <code>{html.escape(target)}</code></p><pre>{html.escape(content)}</pre>"
        except Exception as e:
            content = f'<div class="warn">{html.escape(str(e))}</div>'
    body = f"""
    <h1>5. Path Traversal — 경로 조작</h1>
    <div class="card">
      <form method="get">
        <label>읽을 파일명 (files/ 폴더 기준)</label>
        <input name="file" value="{html.escape(filename)}" placeholder="welcome.txt">
        <button>읽기</button>
      </form>
      {content}
    </div>
    <p><b>🎯 목표:</b> <code>files/</code> 폴더를 벗어나 상위 폴더의 <code>SECRET.txt</code>를 읽으세요.</p>
    <div class="hint">💡 힌트: <code>..</code> 는 상위 디렉토리를 의미합니다. Windows 경로 구분자도 생각해 보세요.</div>
    <details><summary>정답 보기</summary>
      <p>파일명 칸에: <code>..\\SECRET.txt</code> (또는 <code>../SECRET.txt</code>)<br>
      더 나아가 <code>..\\..\\Windows\\win.ini</code> 같은 시스템 파일도 시도해 보세요.</p>
    </details>
    <div class="card"><b>🛡️ 방어:</b> 결합 후 <code>os.path.realpath</code>로 정규화하고,
      결과가 허용된 base 디렉토리 안에 있는지 확인하세요.
      <pre>full = os.path.realpath(os.path.join(base, name))
if not full.startswith(os.path.realpath(base)):
    raise PermissionError</pre>
    </div>
    """
    return page("Path Traversal", body)


# --------------------------------------------------------------------------
# HTTP 핸들러
# --------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    def _send(self, content, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
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
            self._send(view_login(params, method, body_params, self.headers))
        elif path == "/greet":
            self._send(view_greet(params))
        elif path == "/comments":
            self._send(view_comments(method, body_params))
        elif path == "/ping":
            self._send(view_ping(method, body_params))
        elif path == "/read":
            self._send(view_read(params))
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
    print(f"취약 웹앱 실행 중 → http://{HOST}:{PORT}  (Ctrl+C 로 종료)")
    print("경고: localhost 전용. 외부에 노출하지 마세요.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n종료합니다.")
        server.shutdown()


if __name__ == "__main__":
    main()
