#!/usr/bin/env python3
"""
6단계 취약 웹앱 (인젝션 심화, 상급, 교육용, localhost 전용).

1~2단계가 '입력을 그대로 신뢰' 하거나 '허술한 필터' 를 우회하는 것이었다면,
6단계는 데이터가 '안전하게 저장됐다가 나중에' 터지거나(2차 주입), 파서·헤더·
리다이렉트처럼 '평소엔 안 보이는 경로' 로 들어오는 인젝션을 다룹니다.

경고: 이 앱은 '고의로' 취약합니다. 절대 공용 네트워크/서버에 띄우지 마세요.
오직 본인 PC(127.0.0.1)에서 학습용으로만 사용하세요.

의존성 없음 (Python 표준 라이브러리만 사용). 실행 환경: Windows + Python 3.14.
실행:  python vuln_app.py
접속:  http://127.0.0.1:8005

포함 챌린지:
  1. 2차(second-order) SQL Injection — 저장은 안전, 사용 시점에 터진다
  2. XML 엔티티 공격 — 내부 엔티티 확장(billion-laughs / 값 노출)
  3. 오픈 리다이렉트 — next 파라미터 검증 부재
  4. Host 헤더 인젝션 — 비번 재설정 링크 오염

NoSQL 인젝션은 의도적으로 뺐습니다: 표준 라이브러리에 NoSQL 엔진이 없어
'진짜로 뚫리는' 실습을 만들 수 없습니다. 가짜로 흉내내지 않았습니다.
"""

import base64
import html
import os
import secrets as _secrets
import sqlite3
import urllib.parse
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln6.db")
HOST, PORT = "127.0.0.1", 8005

# 서버가 스스로를 부르는 '정상' 호스트. Host 헤더가 이것과 다르면 오염된 것으로 본다.
EXPECTED_HOSTS = {f"{HOST}:{PORT}", f"localhost:{PORT}", HOST, "localhost"}

# 아주 단순한 "세션": 회원가입하면 토큰을 발급하고 토큰 -> username 을 기억한다.
SESSIONS = {}  # token -> 저장된(원본 그대로의) username


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
            # admin 의 secret 이 2차 SQLi 의 최종 전리품이다.
            ("admin", "N0t_Th3_R34l_PW", "FLAG{second_order_sqli}"),
            ("alice", "password123", "alice의 메모"),
            ("bob", "qwerty", "bob의 메모"),
        ],
    )
    con.commit()
    con.close()


def db():
    return sqlite3.connect(DB_PATH)


# --------------------------------------------------------------------------
# HTML 레이아웃 (1·2단계와 동일 계열의 다크 카드 UI)
# --------------------------------------------------------------------------
CSS = """
<style>
  body{font-family:system-ui,Segoe UI,Arial,sans-serif;max-width:900px;margin:0 auto;
       padding:1rem;background:#12101a;color:#e6e6e6;line-height:1.5}
  a{color:#c9a6ff} h1,h2{color:#fff}
  nav{display:flex;gap:.6rem;flex-wrap:wrap;padding:.75rem 0;border-bottom:1px solid #333;margin-bottom:1rem}
  nav a{padding:.3rem .6rem;background:#221a33;border-radius:6px;text-decoration:none}
  .card{background:#1a1626;border:1px solid #322b45;border-radius:10px;padding:1rem;margin:1rem 0}
  .hint{background:#1c1330;border-left:3px solid #a06cff;padding:.6rem .9rem;margin:.6rem 0;border-radius:4px}
  .flag{color:#7ee787;font-weight:bold}
  input,textarea{background:#12101a;color:#e6e6e6;border:1px solid #443a5a;border-radius:6px;
                 padding:.45rem;font-size:1rem;width:100%;max-width:440px;box-sizing:border-box}
  textarea{max-width:100%;font-family:ui-monospace,Consolas,monospace}
  button{background:#7c3aed;color:#fff;border:0;border-radius:6px;padding:.5rem 1rem;
         font-size:1rem;cursor:pointer;margin-top:.5rem}
  code,pre{background:#0c0a12;padding:.15rem .35rem;border-radius:4px;color:#d2a8ff}
  pre{padding:.8rem;overflow:auto;display:block}
  .warn{background:#3a1414;border:1px solid #7a2222;padding:.6rem;border-radius:8px;color:#ffb4b4}
  details summary{cursor:pointer;color:#a06cff}
  label{display:block;margin:.5rem 0 .2rem}
  .lvl{font-size:.8rem;background:#3a1a2a;color:#ffa6d1;padding:.1rem .5rem;border-radius:10px}
</style>
"""

NAV = """
<nav>
  <a href="/">🏠 홈</a>
  <a href="/join">1. 2차 SQLi</a>
  <a href="/xml">2. XML 엔티티</a>
  <a href="/redirect">3. 오픈 리다이렉트</a>
  <a href="/reset">4. Host 헤더 인젝션</a>
</nav>
"""


def page(title, body):
    return f"""<!doctype html><html lang="ko"><head><meta charset="utf-8">
<title>{title}</title>{CSS}</head><body>{NAV}{body}</body></html>""".encode("utf-8")


# --------------------------------------------------------------------------
def view_home():
    body = """
    <h1>🧪 6단계 취약 웹앱 <span class="lvl">인젝션 심화</span></h1>
    <div class="warn">고의로 취약. 127.0.0.1 학습 전용. 외부 노출 금지.</div>
    <p>앞 단계의 인젝션이 '입력 → 즉시 실행' 이었다면, 이 단계는 인젝션이
    <b>시간·경로를 건너뛰어</b> 터집니다. 안전하게 저장됐다가 나중에 쓰일 때,
    XML 파서 안에서, 리다이렉트 목적지에서, HTTP 헤더에서.</p>
    <div class="card">
      <h2>이 단계에서 새로 배우는 것</h2>
      <ul>
        <li><b>2차 SQLi</b> — 파라미터 바인딩으로 '안전하게' 저장한 값이,
        나중에 다른 쿼리에 <i>문자열로 이어붙여질 때</i> 터진다</li>
        <li><b>XML 엔티티</b> — 파서가 DTD 내부 엔티티를 확장한다 (billion-laughs DoS·값 노출)</li>
        <li><b>오픈 리다이렉트</b> — <code>?next=</code> 를 검증 없이 <code>Location</code> 으로</li>
        <li><b>Host 헤더 인젝션</b> — 재설정 링크를 요청의 <code>Host</code> 헤더로 조립</li>
      </ul>
    </div>
    <div class="card"><b>목표 FLAG 4개:</b>
      <code>FLAG{second_order_sqli}</code>,
      <code>FLAG{xml_entity_attack}</code>,
      <code>FLAG{open_redirect}</code>,
      <code>FLAG{host_header_injection}</code>.</div>
    <div class="card"><b>NoSQL 인젝션은 뺐습니다.</b> 표준 라이브러리에 NoSQL 엔진이 없어
      '실제로 뚫리는' 실습을 만들 수 없어서, 가짜로 흉내내는 대신 생략했습니다.</div>
    """
    return page("6단계 취약 웹앱", body)


# 1) 2차(second-order) SQL Injection ----------------------------------------
def view_join(method, body_params):
    """회원가입: username 을 파라미터 바인딩으로 '안전하게' 저장하고 자동 로그인시킨다.
    저장 자체는 안전 — 취약점은 나중에 /me 에서 이 값을 문자열 결합할 때 터진다."""
    msg = ""
    set_cookie = None
    if method == "POST":
        u = body_params.get("username", [""])[0]
        p = body_params.get("password", ["x"])[0]
        if u:
            con = db()
            # 안전: 파라미터 바인딩. 따옴표가 들어와도 여기선 아무 일도 안 일어난다.
            con.execute("INSERT INTO users (username, password, secret) VALUES (?,?,?)", (u, p, ""))
            con.commit()
            con.close()
            token = _secrets.token_urlsafe(12)
            SESSIONS[token] = u  # 원본 그대로 저장 (따옴표·UNION 포함 가능)
            set_cookie = token
            msg = (f'<div class="card">✅ 가입 완료, 자동 로그인됨. 저장된 아이디:'
                   f' <code>{html.escape(u)}</code><br>'
                   f'이제 <a href="/me">내 정보(/me)</a> 를 열어보세요.</div>')
        else:
            msg = '<div class="warn">아이디를 입력하세요.</div>'
    body = f"""
    <h1>1. 2차(second-order) SQL Injection</h1>
    <div class="card">
      <form method="post">
        <label>아이디 (여기 저장은 안전합니다 — 파라미터 바인딩)</label>
        <input name="username" placeholder="원하는 아이디">
        <label>비밀번호</label><input name="password" type="text" value="x">
        <button>가입 + 자동 로그인</button>
      </form>
      {msg}
    </div>
    <p><b>🎯 목표:</b> 가입 폼은 파라미터 바인딩이라 여기선 안 뚫립니다. 그런데
    가입한 아이디는 <a href="/me">/me</a> 의 '내 정보' 쿼리에 <b>문자열로 이어붙여집니다</b>.
    이 시차를 이용해 다른 사용자(<code>admin</code>)의 secret 을 읽어내세요.</p>
    <div class="hint">💡 힌트 1: <code>/me</code> 는 대략
      <code>SELECT username, secret FROM users WHERE username='&lt;내 아이디&gt;'</code>
      를 실행합니다. 내 아이디가 곧 payload 가 됩니다.</div>
    <div class="hint">💡 힌트 2: 컬럼이 2개(username, secret)입니다. <code>UNION SELECT</code> 로
      admin 행을 붙이고, 뒤쪽 따옴표는 템플릿이 닫아 주도록 payload 끝을 열어 두세요.</div>
    <details><summary>정답 보기</summary>
      <p>아이디 칸에 아래를 넣어 가입하세요 (끝에 따옴표를 <b>닫지 마세요</b>):</p>
      <pre>zzz' UNION SELECT username, secret FROM users WHERE username='admin</pre>
      <p>그러면 <code>/me</code> 의 쿼리가
      <code>...WHERE username='zzz' UNION SELECT username, secret FROM users WHERE username='admin'</code>
      로 완성되어 admin 행이 딸려 나오고,
      <span class="flag">FLAG{{second_order_sqli}}</span> 가 secret 으로 노출됩니다.</p>
    </details>
    <div class="card"><b>🛡️ 방어:</b> '한 번 검증했으니 안전' 은 착각입니다. DB에서 꺼낸 값도
      <b>다시 쓸 때마다</b> 파라미터 바인딩하세요. 신뢰 경계는 '입력 시점' 이 아니라
      '사용 시점' 마다 다시 세워야 합니다.</div>
    """
    return page("2차 SQLi", body), set_cookie


def view_me(cookie_token):
    """내 정보: 세션에 저장된 username 을 '문자열로 이어붙여' 조회한다 (취약)."""
    me = SESSIONS.get(cookie_token or "")
    if me is None:
        content = ('<div class="warn">로그인되어 있지 않습니다. 먼저 '
                   '<a href="/join">/join</a> 에서 가입하세요.</div>')
        query = None
    else:
        # 취약: 세션에서 꺼낸 값(저장 시점엔 안전했던)을 그대로 SQL 에 결합 → 2차 주입
        query = f"SELECT username, secret FROM users WHERE username='{me}'"
        con = db()
        try:
            rows = con.execute(query).fetchall()
            sql_err = ""
        except Exception as e:
            rows = []
            sql_err = f'<div class="warn">SQL 오류: {html.escape(str(e))}</div>'
        con.close()
        flag = ""
        shown = []
        for uname, secret in rows:
            shown.append(f"{html.escape(str(uname))}: {html.escape(str(secret))}")
            if secret and "FLAG{" in str(secret):
                flag = ('<p class="flag">🎉 다른 사용자의 secret 을 2차 주입으로 읽었습니다! '
                        f'{html.escape(str(secret))}</p>')
        rendered = "<br>".join(shown) if shown else "(결과 없음)"
        content = (f'{sql_err}<div class="card"><b>내 정보 조회 결과:</b><br>{rendered}{flag}</div>'
                   f'<p>실행된 쿼리:</p><pre>{html.escape(query)}</pre>')
    body = f"""
    <h1>1-2. 내 정보 (/me) — 여기서 2차 주입이 터진다</h1>
    {content}
    <p><a href="/join">← 다시 가입하기</a></p>
    <div class="card"><b>🛡️ 방어:</b>
      <pre>con.execute("SELECT username, secret FROM users WHERE username=?", (me,))</pre>
      저장 시점에 안전했어도, 꺼내서 다시 쿼리에 넣는 순간 또 바인딩해야 합니다.</div>
    """
    return page("내 정보", body)


# 2) XML 엔티티 공격 --------------------------------------------------------
# [현실 점검 / 치환 사유]
# 진짜 XXE(외부 엔티티로 로컬 파일 읽기)는 파이썬 표준 xml.etree.ElementTree(내부 expat)
# 로는 재현되지 않는다 — expat 은 ExternalEntityRefHandler 를 등록하지 않으면 외부 엔티티를
# 로드하지 않고, SYSTEM 엔티티 참조는 그냥 확장되지 않는다(빈 문자열/미해결). 따라서
# '가짜 XXE' 를 흉내내는 대신, 표준 라이브러리가 '실제로 허용하는' 엔티티 취약점으로 치환한다:
#   → DTD 내부 엔티티 확장 (billion-laughs 형 증폭 = DoS 프리미티브, 값 노출).
# expat 은 내부 일반 엔티티를 아무 제한 없이 확장하므로 이 공격은 진짜로 동작한다.
def _expand_ratio(raw, text):
    return len(text) / max(len(raw.encode("utf-8")), 1)


def view_xml(method, raw_body):
    result = ""
    if method == "POST" and raw_body.strip():
        # 취약: 사용자 XML 을 그대로 파싱 → DTD 내부 엔티티가 확장된다.
        try:
            root = ET.fromstring(raw_body)
            # 문서 전체의 텍스트를 이어붙여 '확장 결과' 를 관측한다.
            expanded = "".join(root.itertext())
            ratio = _expand_ratio(raw_body, expanded)
            flag = ""
            # 엔티티 확장이 실제로 일어났는지: 입력보다 결과가 크게 증폭됐거나(billion-laughs)
            # DTD 내부 엔티티가 정의됐는데 그 값이 결과에 노출됐으면 성공으로 본다.
            entity_used = "<!ENTITY" in raw_body
            if entity_used and (ratio >= 3 or len(expanded) >= 200):
                flag = ('<p class="flag">🎉 DTD 내부 엔티티가 확장됐습니다 '
                        f'(입력 {len(raw_body.encode("utf-8"))} bytes → 확장 {len(expanded)} chars, '
                        f'{ratio:.1f}배). FLAG{{xml_entity_attack}}</p>')
            preview = expanded if len(expanded) <= 800 else expanded[:800] + f" ...(총 {len(expanded)}자)"
            result = (f'<div class="card"><b>파싱된 루트 태그:</b> <code>{html.escape(root.tag)}</code><br>'
                      f'<b>확장된 텍스트:</b><pre>{html.escape(preview)}</pre>{flag}</div>')
        except ET.ParseError as e:
            result = f'<div class="warn">XML 파싱 오류: {html.escape(str(e))}</div>'
        except Exception as e:
            result = f'<div class="warn">오류: {html.escape(str(e))}</div>'
    lol = ("&lt;?xml version=\"1.0\"?&gt;\n"
           "&lt;!DOCTYPE lolz [\n"
           "  &lt;!ENTITY a \"aaaaaaaaaa\"&gt;\n"
           "  &lt;!ENTITY b \"&amp;a;&amp;a;&amp;a;&amp;a;&amp;a;&amp;a;&amp;a;&amp;a;&amp;a;&amp;a;\"&gt;\n"
           "  &lt;!ENTITY c \"&amp;b;&amp;b;&amp;b;&amp;b;&amp;b;&amp;b;&amp;b;&amp;b;&amp;b;&amp;b;\"&gt;\n"
           "]&gt;\n"
           "&lt;lolz&gt;&amp;c;&lt;/lolz&gt;")
    body = f"""
    <h1>2. XML 엔티티 공격</h1>
    <div class="card">
      <form method="post">
        <label>XML 문서 (raw body 로 전송됩니다)</label>
        <textarea name="__raw__" rows="10" placeholder="여기에 XML 을 붙여넣으세요"></textarea>
        <button>파싱</button>
      </form>
      <p style="font-size:.85rem;color:#a79bc0">※ 위 폼은 편의용입니다. 실제 공격은 raw XML 을
      body 로 POST 하면 됩니다 (아래 정답 참고).</p>
      {result}
    </div>
    <div class="warn"><b>현실 점검:</b> 진짜 XXE(외부 엔티티로 로컬 파일 읽기)는 파이썬 표준
      <code>xml.etree.ElementTree</code>(내부 expat)로는 <b>재현되지 않습니다</b> — 외부 엔티티
      핸들러가 등록돼 있지 않아 <code>SYSTEM</code> 참조가 로드되지 않습니다. 그래서 가짜 XXE 를
      흉내내는 대신, 표준 라이브러리가 <b>실제로 허용하는</b> 취약점으로 <b>치환</b >했습니다:
      DTD 내부 엔티티 확장(billion-laughs 형 DoS·값 노출). expat 은 내부 엔티티를 제한 없이
      확장하므로 이 공격은 진짜로 동작합니다.</div>
    <p><b>🎯 목표:</b> DTD 에 중첩 엔티티를 정의해, 작은 입력이 거대한 텍스트로 <b>증폭</b>되게
    하세요 (고전적 'billion laughs'). 확장이 실측되면 FLAG 가 나옵니다.</p>
    <div class="hint">💡 힌트 1: <code>&lt;!DOCTYPE x [ &lt;!ENTITY a "..."&gt; ]&gt;</code> 로
      엔티티를 정의하고 <code>&amp;a;</code> 로 참조하면 파서가 그 값으로 치환합니다.</div>
    <div class="hint">💡 힌트 2: 엔티티가 다른 엔티티를 여러 번 참조하도록 층을 쌓으면
      (a→10×, b→10×a, c→10×b) 세 층만으로 1000배가 됩니다.</div>
    <details><summary>정답 보기 (curl 로 raw body 전송)</summary>
      <p>아래 XML 을 <code>/xml</code> 로 그대로 POST 하세요:</p>
      <pre>{lol}</pre>
      <p>세 층짜리 엔티티가 <code>a</code> 10자를 100자(b), 1000자(c)로 확장합니다.
      입력 대비 확장 비율이 크게 나오면
      <span class="flag">FLAG{{xml_entity_attack}}</span> 가 표시됩니다.</p>
    </details>
    <div class="card"><b>🛡️ 방어:</b> 신뢰할 수 없는 XML 파싱엔 <code>defusedxml</code> 를 쓰거나
      DTD/엔티티 처리를 끄세요. 표준 파서라도 내부 엔티티 확장은 막히지 않으니, 파서 앞단에서
      DTD 를 거부하는 것이 확실합니다.</div>
    """
    return page("XML 엔티티", body)


# 3) 오픈 리다이렉트 --------------------------------------------------------
def _is_offsite(next_url):
    """next 가 우리 호스트가 아닌 절대 URL(또는 //host 형태)이면 off-site 로 판정."""
    if not next_url:
        return False
    if next_url.startswith("//"):
        return True
    parsed = urllib.parse.urlparse(next_url)
    if parsed.scheme in ("http", "https") and parsed.netloc:
        return parsed.netloc not in EXPECTED_HOSTS
    return False


def redirect_response(next_url):
    """(location, status, body_bytes) 를 반환. off-site 면 FLAG 를 body 에 담는다."""
    flag_line = ""
    if _is_offsite(next_url):
        flag_line = "<p class=\"flag\">FLAG{open_redirect}</p>"
    body = (f"<!doctype html><meta charset='utf-8'>{CSS}"
            f"<h1>302 Redirecting…</h1>"
            f"<p><code>Location: {html.escape(next_url)}</code> 로 이동합니다.</p>"
            f"{flag_line}").encode("utf-8")
    return next_url, 302, body


def view_redirect_info():
    body = """
    <h1>3. 오픈 리다이렉트</h1>
    <div class="card">
      <p>로그인/이동 편의를 위한 <code>?next=</code> 파라미터입니다. 서버는 이 값을
      그대로 <code>Location</code> 헤더에 넣어 302 리다이렉트합니다 — <b>목적지 검증이 없습니다</b>.</p>
      <form method="get">
        <label>이동할 곳 (next)</label>
        <input name="next" value="/me" style="max-width:100%">
        <button>이동</button>
      </form>
    </div>
    <p><b>🎯 목표:</b> 사용자를 우리 사이트가 아닌 <b>외부 주소</b>로 튕겨 보내세요.
    피싱에서 '믿는 도메인 링크를 눌렀는데 남의 사이트로' 가는 그 수법입니다.</p>
    <div class="hint">💡 힌트: <code>next</code> 에 상대경로(<code>/me</code>) 대신
      <code>https://example.com/</code> 같은 <b>절대 URL</b> 을 넣으면 어디로 갈까요?</div>
    <details><summary>정답 보기</summary>
      <p><code>/redirect?next=https://example.com/</code> 로 접속하면 302 로 외부 사이트로
      리다이렉트되고, off-site 가 감지되어 응답 본문에
      <span class="flag">FLAG{open_redirect}</span> 가 담깁니다.</p>
      <pre>curl -i "http://127.0.0.1:8005/redirect?next=https://example.com/"</pre>
    </details>
    <div class="card"><b>🛡️ 방어:</b> 리다이렉트 목적지는 <b>허용 목록</b> 으로 제한하거나,
      상대경로만 허용(<code>/</code> 로 시작하되 <code>//</code> 는 거부)하세요.
      절대 URL 을 받아야 하면 host 를 우리 도메인으로 강제하세요.</div>
    """
    return page("오픈 리다이렉트", body)


# 4) Host 헤더 인젝션 -------------------------------------------------------
def view_reset(method, body_params, host_header):
    """비번 재설정: 재설정 링크를 요청의 Host 헤더로 조립한다 (취약)."""
    result = ""
    if method == "POST":
        email = body_params.get("email", [""])[0] or "user@example.com"
        token = "reset-" + _secrets.token_hex(6)
        # 취약: 링크의 host 를 '들어온 Host 헤더' 로 만든다 → 헤더를 위조하면 링크가 오염된다.
        reset_link = f"http://{host_header}/reset/confirm?token={token}&email={urllib.parse.quote(email)}"
        poisoned = host_header not in EXPECTED_HOSTS
        flag = ""
        if poisoned:
            flag = ('<p class="flag">🎉 Host 헤더가 재설정 링크에 그대로 반영됐습니다. '
                    'FLAG{host_header_injection}</p>')
        result = (f'<div class="card"><b>받은 Host 헤더:</b> <code>{html.escape(host_header)}</code><br>'
                  f'<b>{html.escape(email)} 에게 보낼 재설정 링크:</b><br>'
                  f'<pre>{html.escape(reset_link)}</pre>{flag}</div>')
    body = f"""
    <h1>4. Host 헤더 인젝션 — 비번 재설정 링크 오염</h1>
    <div class="card">
      <form method="post">
        <label>가입한 이메일</label>
        <input name="email" placeholder="you@example.com">
        <button>재설정 링크 보내기</button>
      </form>
      {result}
    </div>
    <p><b>🎯 목표:</b> 서버는 재설정 링크의 도메인을 요청의 <code>Host</code> 헤더에서 가져옵니다.
    <code>Host</code> 를 공격자 도메인으로 위조해, 링크가 <b>공격자 사이트</b>를 가리키게 하세요.
    (피해자가 그 링크를 누르면 토큰이 공격자에게 넘어갑니다.)</p>
    <div class="hint">💡 힌트: 브라우저 폼으로는 Host 를 못 바꿉니다. <code>curl -H "Host: evil.com"</code>
      처럼 요청 헤더를 직접 지정해서 POST 하세요.</div>
    <details><summary>정답 보기 (curl 로 Host 위조)</summary>
      <pre>curl -s -X POST "http://127.0.0.1:8005/reset" \\
     -H "Host: evil.attacker.com" \\
     --data "email=victim@example.com"</pre>
      <p>응답의 재설정 링크가 <code>http://evil.attacker.com/reset/confirm?...</code> 로 나오고,
      오염이 감지되어 <span class="flag">FLAG{{host_header_injection}}</span> 가 표시됩니다.</p>
    </details>
    <div class="card"><b>🛡️ 방어:</b> 절대 URL 이 필요한 링크(재설정 메일 등)는 <code>Host</code>
      헤더를 신뢰하지 말고 <b>서버에 설정된 정식 도메인</b> 상수로 만드세요. 프록시 앞단에서
      허용된 Host 만 통과시키는 것도 필요합니다.</div>
    """
    return page("Host 헤더 인젝션", body)


# --------------------------------------------------------------------------
# HTTP 핸들러
# --------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    def _send(self, content, status=200, set_cookie=None):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        if set_cookie:
            self.send_header("Set-Cookie", f"token={set_cookie}; Path=/")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _send_redirect(self, location, body, status=302):
        self.send_response(status)
        self.send_header("Location", location)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

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
        raw_body = ""
        if method == "POST":
            length = int(self.headers.get("Content-Length", 0))
            raw_body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
            body_params = urllib.parse.parse_qs(raw_body)

        if path == "/":
            self._send(view_home())
        elif path == "/join":
            content, set_cookie = view_join(method, body_params)
            self._send(content, set_cookie=set_cookie)
        elif path == "/me":
            self._send(view_me(self._cookie_token()))
        elif path == "/xml":
            self._send(view_xml(method, raw_body))
        elif path == "/redirect":
            next_url = params.get("next", [""])[0]
            if next_url:
                location, status, body = redirect_response(next_url)
                self._send_redirect(location, body, status)
            else:
                self._send(view_redirect_info())
        elif path == "/reset":
            host_header = self.headers.get("Host", "")
            self._send(view_reset(method, body_params, host_header))
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
    print(f"6단계 취약 웹앱 실행 중 → http://{HOST}:{PORT}  (Ctrl+C 로 종료)")
    print("경고: localhost 전용. 외부에 노출하지 마세요.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n종료합니다.")
        server.shutdown()


if __name__ == "__main__":
    main()
