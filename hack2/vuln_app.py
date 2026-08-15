#!/usr/bin/env python3
"""
2단계 취약 웹앱 (중급, 교육용, localhost 전용).

1단계(hack1)가 '입력을 그대로 신뢰'하는 날것의 취약점이라면,
2단계는 '허술한 방어가 붙어 있어 우회가 필요한' 취약점을 다룹니다.

경고: 고의로 취약. 127.0.0.1 에서 학습용으로만.
의존성 없음. 실행: python vuln_app.py  →  http://127.0.0.1:8001

포함 챌린지:
  1. Blind SQL Injection (boolean-based) — 오류도 데이터도 안 보임
  2. XSS 필터 우회 — <script>, onerror 등이 막혀 있음
  3. IDOR — 남의 자원을 id 조작으로 열람
  4. 세션 토큰 위조 — 예측 가능한 "서명"으로 admin 위장
  5. SSRF — 서버가 대신 URL을 요청해 줌
"""

import base64
import hashlib
import html
import os
import re
import socket
import sqlite3
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln2.db")
HOST, PORT = "127.0.0.1", 8001

# 세션 토큰 "서명"에 쓰는 비밀. 취약: 약하고 방식이 뻔함(username|md5(username+SECRET)).
TOKEN_SECRET = "secret"  # 공격자가 쉽게 추측/무차별 대입 가능한 약한 값


# --------------------------------------------------------------------------
def init_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    cur.executemany(
        "INSERT INTO users (username, password) VALUES (?,?)",
        [("admin", "Wint3r_2026!"), ("alice", "password123"), ("bob", "qwerty")],
    )
    # 각 사용자의 비공개 노트 (IDOR 대상)
    cur.execute("CREATE TABLE notes (id INTEGER PRIMARY KEY, owner TEXT, title TEXT, body TEXT)")
    cur.executemany(
        "INSERT INTO notes (id, owner, title, body) VALUES (?,?,?,?)",
        [
            (1, "alice", "장보기", "우유, 계란"),
            (2, "bob", "비번 메모", "은행 핀 4023"),
            (3, "admin", "관리자 노트", "FLAG{idor_lets_you_read_others}"),
        ],
    )
    con.commit()
    con.close()


def db():
    return sqlite3.connect(DB_PATH)


# --------------------------------------------------------------------------
# 세션 토큰: username|sig,  sig = md5(username + TOKEN_SECRET)
# 취약: 서명 방식이 단순 md5 연결이고 SECRET 이 약함 → 위조 가능.
def make_token(username):
    sig = hashlib.md5((username + TOKEN_SECRET).encode()).hexdigest()
    raw = f"{username}|{sig}"
    return base64.urlsafe_b64encode(raw.encode()).decode()


def parse_token(token):
    try:
        raw = base64.urlsafe_b64decode(token.encode()).decode()
        username, sig = raw.rsplit("|", 1)
        expected = hashlib.md5((username + TOKEN_SECRET).encode()).hexdigest()
        if sig == expected:
            return username
    except Exception:
        pass
    return None


# --------------------------------------------------------------------------
CSS = """
<style>
  body{font-family:system-ui,Segoe UI,Arial,sans-serif;max-width:900px;margin:0 auto;
       padding:1rem;background:#0d1420;color:#e6e6e6;line-height:1.5}
  a{color:#6cb6ff} h1,h2{color:#fff}
  nav{display:flex;gap:.6rem;flex-wrap:wrap;padding:.75rem 0;border-bottom:1px solid #333;margin-bottom:1rem}
  nav a{padding:.3rem .6rem;background:#16202f;border-radius:6px;text-decoration:none}
  .card{background:#131c29;border:1px solid #26303f;border-radius:10px;padding:1rem;margin:1rem 0}
  .hint{background:#0b2016;border-left:3px solid #3ad07a;padding:.6rem .9rem;margin:.6rem 0;border-radius:4px}
  .flag{color:#7ee787;font-weight:bold}
  input,textarea{background:#0d1420;color:#e6e6e6;border:1px solid #3a4756;border-radius:6px;
                 padding:.45rem;font-size:1rem;width:100%;max-width:440px;box-sizing:border-box}
  button{background:#1f6feb;color:#fff;border:0;border-radius:6px;padding:.5rem 1rem;
         font-size:1rem;cursor:pointer;margin-top:.5rem}
  code,pre{background:#08101c;padding:.15rem .35rem;border-radius:4px;color:#79c0ff}
  pre{padding:.8rem;overflow:auto;display:block}
  .warn{background:#3a1414;border:1px solid #7a2222;padding:.6rem;border-radius:8px;color:#ffb4b4}
  details summary{cursor:pointer;color:#3ad07a}
  label{display:block;margin:.5rem 0 .2rem}
  .lvl{font-size:.8rem;background:#2a1a3a;color:#c9a6ff;padding:.1rem .5rem;border-radius:10px}
</style>
"""

NAV = """
<nav>
  <a href="/">🏠 홈</a>
  <a href="/search">1. Blind SQLi</a>
  <a href="/profile">2. XSS 필터 우회</a>
  <a href="/note?id=1">3. IDOR</a>
  <a href="/account">4. 토큰 위조</a>
  <a href="/fetch">5. SSRF</a>
</nav>
"""


def page(title, body):
    return f"""<!doctype html><html lang="ko"><head><meta charset="utf-8">
<title>{title}</title>{CSS}</head><body>{NAV}{body}</body></html>""".encode("utf-8")


LEVELS = ["low", "medium", "high", "secure"]


def level_selector(current):
    """방어 강도 셀렉터 UI. 링크는 ?level=X (경로 유지). 폼에는 hidden 필드로 함께 실린다."""
    links = " · ".join(
        f'<b class="flag">{lv}</b>' if lv == current else f'<a href="?level={lv}">{lv}</a>'
        for lv in LEVELS
    )
    desc = {
        "low": "무방비 — 입력을 그대로 출력",
        "medium": "어설픈 방어(1회 블랙리스트) — 겹쳐쓰기 우회 가능",
        "high": "강한 방어(재귀 블랙리스트) — 미차단 핸들러로 우회 가능",
        "secure": "완전 방어(출력 이스케이프)",
    }[current]
    return (f'<div class="card">🎚️ <b>방어 레벨:</b> {links}'
            f'<br><span style="color:#9aa4b2">현재: <b>{current}</b> — {desc}</span></div>')


def _xss_executes(rendered):
    """렌더된 사용자 입력에 '실행 가능한' 미이스케이프 벡터가 남았는지 판별한다.
    (이벤트 핸들러가 붙은 태그 또는 <script>. 성공 판정용 🎉 마커의 근거.)"""
    return bool(re.search(r"<[a-z][^>]*\son\w+\s*=", rendered, re.I)) or "<script" in rendered.lower()


def _filter_recursive(s, blocked):
    """차단 문자열을 더 이상 바뀌지 않을 때까지 반복 제거(겹쳐쓰기 우회 차단)."""
    prev = None
    while prev != s:
        prev = s
        for bad in blocked:
            s = s.replace(bad, "").replace(bad.upper(), "").replace(bad.capitalize(), "")
    return s


# --------------------------------------------------------------------------
def view_home():
    body = """
    <h1>🔐 2단계 취약 웹앱 <span class="lvl">중급</span></h1>
    <div class="warn">고의로 취약. 127.0.0.1 학습 전용. 외부 노출 금지.</div>
    <p>1단계는 '아무 방어가 없어' 뚫렸습니다. 2단계는 <b>허술한 방어가 붙어 있어</b>
    그걸 <b>우회</b>해야 합니다. 각 페이지의 힌트를 계단처럼 밟아 올라가세요.</p>
    <div class="card">
      <h2>이 단계에서 새로 배우는 것</h2>
      <ul>
        <li><b>Blind SQLi</b> — 화면에 데이터가 안 나와도, 참/거짓 반응만으로 값을 한 글자씩 추출</li>
        <li><b>필터 우회</b> — 차단 목록(blacklist)의 빈틈(대소문자·대체 태그·인코딩) 찾기</li>
        <li><b>IDOR</b> — 인증은 됐지만 <i>인가(권한)</i>가 없어 남의 자원에 접근</li>
        <li><b>토큰 위조</b> — 클라이언트가 들고 있는 세션 값을 스스로 만들어내기</li>
        <li><b>SSRF</b> — 서버의 요청 권한을 빌려 내부망/메타데이터에 접근</li>
      </ul>
    </div>
    <div class="card"><b>목표 FLAG 3개:</b> Blind SQLi로 admin 비번, IDOR로 admin 노트,
    토큰 위조로 admin 계정 페이지 — 각각에서 FLAG를 얻으세요.</div>
    """
    return page("2단계 취약 웹앱", body)


# 1) Blind SQL Injection ----------------------------------------------------
def view_search(params):
    q = params.get("q", [""])[0]
    result = ""
    if q:
        # 취약: 문자열 결합. 단, 결과 '내용'은 안 보여주고 존재 여부만 알려준다(blind).
        query = f"SELECT id FROM users WHERE username='{q}'"
        con = db()
        try:
            rows = con.execute(query).fetchall()
            if rows:
                result = '<div class="card">✅ 해당 사용자가 <b>존재합니다</b>.</div>'
            else:
                result = '<div class="card">❌ 그런 사용자가 <b>없습니다</b>.</div>'
        except Exception:
            # 오류 메시지도 숨긴다 → 완전한 blind
            result = '<div class="card">❌ 그런 사용자가 <b>없습니다</b>.</div>'
        con.close()
    body = f"""
    <h1>1. Blind SQL Injection</h1>
    <div class="card">
      <form method="get">
        <label>사용자 이름으로 존재 여부 확인</label>
        <input name="q" value="{html.escape(q)}" placeholder="alice">
        <button>확인</button>
      </form>
      {result}
    </div>
    <p><b>🎯 목표:</b> 화면엔 "존재함/없음" 두 마디만 나옵니다. 이 참/거짓 반응만으로
    <code>admin</code>의 비밀번호 첫 글자와 길이를 알아내세요.</p>
    <div class="hint">💡 힌트 1: <code>admin' AND '1'='1</code> 은 참(존재함),
      <code>admin' AND '1'='2</code> 는 거짓(없음)으로 갈립니다. 주입이 되는지 먼저 확인하세요.</div>
    <div class="hint">💡 힌트 2: 비번 길이 —
      <code>admin' AND length(password)=12 -- </code> 를 넣어 "존재함"이 나오는 숫자를 찾습니다.</div>
    <div class="hint">💡 힌트 3: 첫 글자 —
      <code>admin' AND substr(password,1,1)='W' -- </code> 처럼 글자를 바꿔가며 "존재함"을 찾습니다.</div>
    <details><summary>정답/자동화 아이디어 보기</summary>
      <p>비번은 <code>Wint3r_2026!</code> (길이 12). 예:
      <code>admin' AND substr(password,1,1)='W'--</code> → 존재함,
      <code>...='X'--</code> → 없음.</p>
      <p>실전에선 이 참/거짓을 스크립트로 자동화(sqlmap 유사)해 전체를 추출합니다.
      길이를 먼저 구하고, 각 위치를 이진 탐색(<code>&gt;</code>, <code>&lt;</code>)하면 빠릅니다.
      전부 맞추면 <span class="flag">FLAG{{blind_extraction_master}}</span>.</p>
    </details>
    <div class="card"><b>🛡️ 방어:</b> 파라미터 바인딩. 그리고 참/거짓·오류·응답시간 등
      <b>어떤 관측 채널도</b> 주입값에 따라 달라지지 않게 하세요.</div>
    """
    return page("Blind SQLi", body)


# 2) XSS 필터 우회 ----------------------------------------------------------
BLOCKED = ["<script", "onerror", "onload", "javascript:", "alert("]


def naive_filter(s):
    # 취약: 대소문자 구분 없이 '문자열'만 지운다 → 우회 여지 많음
    out = s
    for bad in BLOCKED:
        out = out.replace(bad, "").replace(bad.upper(), "").replace(bad.capitalize(), "")
    return out


def view_profile(params):
    level = (params.get("level") or ["low"])[0]
    if level not in LEVELS:
        level = "low"
    bio = params.get("bio", [""])[0]
    rendered = ""
    if bio:
        if level == "low":
            shown = bio                              # 무방비: 그대로 출력
        elif level == "medium":
            shown = naive_filter(bio)                # 1회 블랙리스트 → 겹쳐쓰기로 우회
        elif level == "high":
            shown = _filter_recursive(bio, BLOCKED)  # 재귀 블랙리스트 → 미차단 핸들러로 우회
        else:  # secure
            shown = html.escape(bio)                 # 출력 이스케이프 → 실행 불가
        marker = ('<p class="flag">🎉 필터를 우회한 실행 가능한 페이로드가 그대로 반영되었습니다!</p>'
                  if _xss_executes(shown) else "")
        rendered = f"<div class='card'>내 소개: {shown}{marker}</div>"
    body = f"""
    <h1>2. XSS 필터 우회</h1>
    {level_selector(level)}
    <div class="card">
      <form method="get">
        <input type="hidden" name="level" value="{html.escape(level)}">
        <label>자기소개 (일부 태그는 차단됩니다)</label>
        <input name="bio" value="{html.escape(bio)}">
        <button>미리보기</button>
      </form>
      {rendered}
    </div>
    <p><b>🎯 목표:</b> 차단 필터를 우회해 JavaScript를 실행하세요.
    차단 목록: <code>&lt;script</code>, <code>onerror</code>, <code>onload</code>,
    <code>javascript:</code>, <code>alert(</code>.</p>
    <div class="warn">브라우저 자동화 세션에서는 <code>alert()</code> 대신
      <code>console.log</code>/DOM 변경으로 확인하세요 (그리고 <code>alert(</code>는 어차피 막혀 있습니다).</div>
    <div class="hint">💡 힌트 1: 필터는 <code>replace</code>를 <b>한 번만</b> 합니다.
      <code>&lt;scr&lt;script&gt;ipt&gt;</code> 처럼 겹쳐 쓰면 지운 뒤 오히려 완성됩니다.</div>
    <div class="hint">💡 힌트 2: 차단 안 된 이벤트 핸들러도 많습니다
      (<code>onmouseover</code>, <code>onfocus autofocus</code> 등).</div>
    <details><summary>정답 보기 (레벨별)</summary>
      <p><b>low</b> — 필터가 없습니다. <code>&lt;img src=x onerror="console.log('xss')"&gt;</code> 가 그대로 실행됩니다.</p>
      <p><b>medium</b> — 블랙리스트를 <b>한 번만</b> 적용합니다. 겹쳐쓰기로 우회:
      <code>&lt;img src=x oneonerrorrror="console.log('xss')"&gt;</code>
      → 가운데 <code>onerror</code>를 지우면 바깥이 <code>onerror</code>로 합쳐집니다.</p>
      <p><b>high</b> — 블랙리스트를 <b>재귀</b> 적용해 겹쳐쓰기는 막힙니다. 하지만 차단 목록에 없는
      핸들러로 우회: <code>&lt;svg onfocus="console.log(1)" autofocus tabindex=0&gt;</code>
      (<code>onload</code>는 막혔지만 <code>onfocus</code>는 안 막힘). <b>블랙리스트는 언제나 빈틈이 있습니다.</b></p>
      <p><b>secure</b> — 출력 이스케이프(<code>html.escape</code>)라 <code>&lt;</code> 가 <code>&amp;lt;</code> 로 바뀌어
      어떤 태그도 실행되지 않습니다.</p>
    </details>
    <div class="card"><b>🛡️ 방어:</b> 블랙리스트는 항상 뚫립니다.
      <b>출력 이스케이프(화이트리스트)</b> + <code>Content-Security-Policy</code>를 쓰세요.</div>
    """
    return page("XSS 필터 우회", body)


# 3) IDOR -------------------------------------------------------------------
def view_note(params):
    note_id = params.get("id", ["1"])[0]
    con = db()
    try:
        row = con.execute("SELECT owner, title, body FROM notes WHERE id=?", (int(note_id),)).fetchone()
    except Exception:
        row = None
    con.close()
    # 취약: 로그인 사용자가 '자기' 노트인지 검사하지 않음 → 남의 것도 열람
    if row:
        owner, title, text = row
        flag = ""
        if "FLAG{" in text:
            flag = '<p class="flag">🎉 남의(admin) 노트를 읽었습니다!</p>'
        content = f"""<div class="card"><b>소유자:</b> {html.escape(owner)}<br>
        <b>제목:</b> {html.escape(title)}<br><b>내용:</b> {html.escape(text)}{flag}</div>"""
    else:
        content = '<div class="warn">그런 노트가 없습니다.</div>'
    body = f"""
    <h1>3. IDOR — 권한 없는 자원 접근</h1>
    <p>당신은 지금 <b>alice</b>로 로그인했다고 가정합니다. 아래는 "내 노트 1번"입니다.</p>
    {content}
    <div class="card">
      <form method="get">
        <label>노트 번호</label><input name="id" value="{html.escape(note_id)}">
        <button>열기</button>
      </form>
    </div>
    <p><b>🎯 목표:</b> alice의 것이 아닌 노트를 열어 admin의 FLAG를 읽으세요.</p>
    <div class="hint">💡 힌트: URL의 <code>id=1</code> 을 <code>2</code>, <code>3</code> 으로 바꿔보세요.
      서버가 "이게 정말 네 노트냐"를 확인하나요?</div>
    <details><summary>정답 보기</summary>
      <p><code>/note?id=3</code> → admin의 노트 =
      <span class="flag">FLAG{{idor_lets_you_read_others}}</span>.
      인증(로그인)은 됐지만 <b>인가(소유권 검사)</b>가 빠진 전형적 결함입니다.</p>
    </details>
    <div class="card"><b>🛡️ 방어:</b> 조회 시 <code>WHERE id=? AND owner=?(현재 로그인 사용자)</code>
      처럼 소유권을 함께 검사하세요. 예측 불가능한 식별자(UUID)도 보조 수단입니다.</div>
    """
    return page("IDOR", body)


# 4) 세션 토큰 위조 ---------------------------------------------------------
def view_account(params, cookie_token):
    # 로그인 폼 없이, 데모를 위해 alice 토큰을 기본 제공
    token = params.get("token", [cookie_token or make_token("alice")])[0]
    username = parse_token(token)
    body_extra = ""
    if username:
        flag = ""
        if username == "admin":
            flag = '<p class="flag">🎉 FLAG{forged_admin_session} — admin 세션을 위조했습니다!</p>'
        body_extra = f"""<div class="card">현재 토큰의 신원: <b>{html.escape(username)}</b>{flag}</div>"""
    else:
        body_extra = '<div class="warn">유효하지 않은 토큰입니다.</div>'
    demo_alice = make_token("alice")
    body = f"""
    <h1>4. 세션 토큰 위조</h1>
    <p>이 앱의 세션 토큰은 <code>base64(username + "|" + 서명)</code> 이고,
    서명은 <code>md5(username + SECRET)</code> 입니다. SECRET 은 아주 약합니다.</p>
    <div class="card">
      <p>예시(alice) 토큰: <code>{demo_alice}</code></p>
      <form method="get">
        <label>검사할 토큰</label><input name="token" value="{html.escape(token)}">
        <button>확인</button>
      </form>
      {body_extra}
    </div>
    <p><b>🎯 목표:</b> <code>admin</code> 신원의 유효한 토큰을 <b>직접 만들어</b> 넣으세요.</p>
    <div class="hint">💡 힌트 1: alice 토큰을 base64 디코드하면 구조(<code>alice|해시</code>)가 보입니다.</div>
    <div class="hint">💡 힌트 2: 서명은 <code>md5("admin" + SECRET)</code>. SECRET 은 흔한 단어입니다
      (예: <code>secret</code>, <code>password</code> ...). 사전 대입으로 맞춰 보세요.</div>
    <details><summary>정답(파이썬 한 줄) 보기</summary>
      <pre>import base64, hashlib
sig = hashlib.md5(("admin"+"secret").encode()).hexdigest()
print(base64.urlsafe_b64encode(f"admin|{{sig}}".encode()).decode())</pre>
      <p>출력된 토큰을 위 칸에 넣으면 <span class="flag">FLAG{{forged_admin_session}}</span>.</p>
    </details>
    <div class="card"><b>🛡️ 방어:</b> 자작 서명 대신 검증된 방식(HMAC-SHA256 + 길고 랜덤한 서버 비밀)
      또는 서버측 세션 저장을 쓰고, 신원 필드를 클라이언트가 못 바꾸게 하세요.</div>
    """
    return page("토큰 위조", body)


# 5) SSRF -------------------------------------------------------------------
def view_fetch(method, body_params):
    out = ""
    if method == "POST":
        url = body_params.get("url", [""])[0]
        # 취약: 목적지 검증 없이 서버가 그대로 요청 → 내부망/로컬 접근 가능
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "vuln-fetcher"})
            with urllib.request.urlopen(req, timeout=5) as r:
                data = r.read(4000).decode("utf-8", "replace")
            out = f"<p>가져온 URL: <code>{html.escape(url)}</code></p><pre>{html.escape(data)}</pre>"
        except Exception as e:
            out = f'<div class="warn">{html.escape(str(e))}</div>'
    # 내부 전용 "관리자" 엔드포인트가 로컬에만 있다고 가정 → /internal 이 그 역할
    body = f"""
    <h1>5. SSRF — 서버측 요청 위조</h1>
    <p>URL 미리보기 기능입니다. 서버가 대신 그 주소로 요청해 내용을 보여줍니다.</p>
    <div class="card">
      <form method="post">
        <label>미리볼 URL</label>
        <input name="url" placeholder="http://example.com" style="max-width:100%">
        <button>가져오기</button>
      </form>
      {out}
    </div>
    <p><b>🎯 목표:</b> 이 서버에만 존재하는 내부 전용 경로
    <code>http://127.0.0.1:{PORT}/internal</code> 의 비밀을 SSRF로 끌어내세요.
    (그 경로는 브라우저로 직접 열면 차단되지만, 서버가 대신 요청하면 통과됩니다.)</p>
    <div class="hint">💡 힌트: 입력 URL에 외부 주소 대신 <code>127.0.0.1</code>/<code>localhost</code>
      같은 <b>내부 주소</b>를 넣으면, 서버의 위치에서 요청이 나갑니다.</div>
    <details><summary>정답 보기</summary>
      <p>URL 칸에: <code>http://127.0.0.1:{PORT}/internal</code>
      → <span class="flag">FLAG{{ssrf_reached_internal}}</span> 가 응답에 담겨 옵니다.</p>
      <p>실전 표적: 클라우드 메타데이터(<code>169.254.169.254</code>), 내부 관리 포트, DB 등.</p>
    </details>
    <div class="card"><b>🛡️ 방어:</b> 목적지를 화이트리스트로 제한하고,
      사설/루프백/링크로컬 IP(<code>127.0.0.0/8</code>, <code>10/8</code>, <code>169.254/16</code> ...)를
      DNS 해석 후 차단하세요. 리다이렉트도 재검증해야 합니다.</div>
    """
    return page("SSRF", body)


def view_internal(client_ip):
    # 취약: '요청 출발지가 로컬이면 관리자'라는 안일한 신뢰 → SSRF로 우회됨
    if client_ip in ("127.0.0.1", "::1"):
        return page("internal", '<h1>내부 전용</h1><p class="flag">FLAG{ssrf_reached_internal}</p>'
                                "<p>이 페이지는 '로컬 요청'만 신뢰합니다. SSRF가 바로 그걸 악용합니다.</p>")
    return page("forbidden", "<h1>403</h1><p>외부 접근 금지.</p>")


# --------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    def _send(self, content, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _cookie_token(self):
        raw = self.headers.get("Cookie", "")
        for part in raw.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                if k == "token":
                    return v
        return None

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
        elif path == "/search":
            self._send(view_search(params))
        elif path == "/profile":
            self._send(view_profile(params))
        elif path == "/note":
            self._send(view_note(params))
        elif path == "/account":
            self._send(view_account(params, self._cookie_token()))
        elif path == "/fetch":
            self._send(view_fetch(method, body_params))
        elif path == "/internal":
            self._send(view_internal(self.client_address[0]))
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
    print(f"2단계 취약 웹앱 실행 중 → http://{HOST}:{PORT}  (Ctrl+C 로 종료)")
    print("경고: localhost 전용. 외부에 노출하지 마세요.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n종료합니다.")
        server.shutdown()


if __name__ == "__main__":
    main()
