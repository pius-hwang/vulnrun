#!/usr/bin/env python3
"""
vulnrun 통합 런처 — 8개 취약 웹앱을 한 프로세스로 띄우고, 단일 포트(:8080)에서
경로(/hack1 ~ /hack8)로 브라우징한다.

경고: 모든 앱은 '고의로' 취약하다. 절대 공용 네트워크/서버에 노출하지 마라.
오직 본인 PC(127.0.0.1)에서 학습용으로만 사용하라.

구조: 각 앱은 원본 코드 그대로 내부 loopback 포트(8000~8007)에 뜬다. 이 파일은
사용자向 :8080 에서 리버스 프록시로 요청을 내부 포트에 전달하며, 경로·링크·쿠키·
리다이렉트를 /hackN prefix 기준으로 재작성한다. 앱 파일은 한 줄도 수정하지 않는다.

실행:  python main.py
접속:  http://127.0.0.1:8080
"""

import html
import http.client
import importlib.util
import json
import os
import re
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PUBLIC_HOST, PUBLIC_PORT = "127.0.0.1", 8080

MARK_BYTES = "\U0001F389".encode("utf-8")  # 🎉 — 익스플로잇 성공 시에만 렌더되는 마커

# 단계별 메타 (허브 카드용). 포트는 각 앱 모듈에서 실측한다.
STAGES = [
    (1, "입문",      "SQLi · Reflected/Stored XSS · Command Injection · Path Traversal"),
    (2, "중급",      "Blind SQLi · XSS 필터 우회 · IDOR · 세션 토큰 위조 · SSRF"),
    (3, "중상",      "인증/세션 — JWT alg:none · 약한 JWT 서명 · CSRF · 예측가능 재설정 토큰"),
    (4, "중상~상",   "템플릿/역직렬화 RCE — SSTI(eval) · pickle 역직렬화 · format-string 유출"),
    (5, "상",        "접근제어/로직 — mass-assignment 권한상승 · 결제단계 건너뛰기 · 음수 가격"),
    (6, "상",        "인젝션 심화 — 2차 SQLi · XML 엔티티 · 오픈 리다이렉트 · Host 헤더 인젝션"),
    (7, "상",        "타이밍/경합 — 레이스 컨디션 이중지불 · 타이밍 사이드채널 · TOCTOU"),
    (8, "최상",      "연쇄 킬체인 — XSS→토큰탈취→권한상승→SSRF→완전장악"),
]

# prefix("hack3") -> 내부 포트(8002). 앱 로드 시 채운다.
PREFIX_PORT = {}


# --------------------------------------------------------------------------
# 진행 상태 (스코어보드) — 🎉 마커 자동 감지로 완료 기록. JSON 영속(.gitignore).
# --------------------------------------------------------------------------
STATE_PATH = os.path.join(BASE_DIR, ".progress.json")
_state_lock = threading.Lock()


def load_progress():
    try:
        with open(STATE_PATH, encoding="utf-8") as f:
            return {k: bool(v) for k, v in json.load(f).items()}
    except Exception:
        return {}


PROGRESS = load_progress()


def mark_done(prefix):
    """익스플로잇 성공(🎉)이 감지된 stage 를 완료로 기록하고 영속화한다."""
    if PROGRESS.get(prefix):
        return
    with _state_lock:
        PROGRESS[prefix] = True
        try:
            with open(STATE_PATH, "w", encoding="utf-8") as f:
                json.dump(PROGRESS, f)
        except Exception:
            pass


def reset_progress():
    with _state_lock:
        PROGRESS.clear()
        try:
            if os.path.exists(STATE_PATH):
                os.remove(STATE_PATH)
        except Exception:
            pass


# --------------------------------------------------------------------------
# 앱 로드 + 내부 포트 기동
# --------------------------------------------------------------------------
def load_and_start(n):
    """hackN/vuln_app.py 를 임포트해, 그 앱의 main()(초기화+serve)을 데몬 스레드로 띄운다."""
    path = os.path.join(BASE_DIR, f"hack{n}", "vuln_app.py")
    spec = importlib.util.spec_from_file_location(f"vulnrun_hack{n}", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)

    # 프록시(:8080)를 거치면 정상 브라우저 Host 가 127.0.0.1:8080 이 된다. hack6 의
    # Host-인젝션 판정이 이를 오염으로 오탐하지 않도록, 정상 Host 목록에 :8080 을 더한다.
    if hasattr(mod, "EXPECTED_HOSTS"):
        mod.EXPECTED_HOSTS = set(mod.EXPECTED_HOSTS) | {
            f"{PUBLIC_HOST}:{PUBLIC_PORT}", f"localhost:{PUBLIC_PORT}",
        }

    # 내부 앱의 시작 배너·접속 로그는 구현 세부사항이므로 감춘다. 모듈 전역에 print 를
    # 덮어쓰면 그 모듈의 print() 호출이 no-op 이 된다(파이썬은 전역을 빌트인보다 먼저 찾음).
    mod.print = lambda *a, **k: None
    mod.Handler.log_message = lambda *a, **k: None

    threading.Thread(target=mod.main, daemon=True).start()
    PREFIX_PORT[f"hack{n}"] = mod.PORT
    return mod.PORT


# --------------------------------------------------------------------------
# 응답 재작성 (prefix 인식)
# --------------------------------------------------------------------------
_ATTR_URL = re.compile(r'(href|src|action|formaction)="(/(?!/)[^"]*)"')


def rewrite_html(raw, prefix, iport):
    """HTML 본문의 절대링크·내부포트 URL 을 /prefix 기준으로 고치고, 허브 배너를 얹는다."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw
    # 앱이 노출하는 자기 절대 URL(SSRF/Host 힌트 등) → 통합 주소
    for hostname in ("127.0.0.1", "localhost"):
        text = text.replace(
            f"http://{hostname}:{iport}", f"http://{PUBLIC_HOST}:{PUBLIC_PORT}/{prefix}"
        )
    # 루트 상대 링크(/login, /) → /prefix/login, /prefix/
    text = _ATTR_URL.sub(lambda m: f'{m.group(1)}="/{prefix}{m.group(2)}"', text)
    # 상단 허브 배너 주입
    n = prefix[-1]
    banner = (
        '<div style="position:sticky;top:0;z-index:9999;background:#12151c;'
        'border-bottom:1px solid #2a2f3a;padding:8px 14px;font:13px system-ui,sans-serif;'
        'color:#9aa4b2">🎯 <b style="color:#e6edf3">vulnrun</b> · '
        f'{n}단계 &nbsp;<a href="/" style="color:#6cb6ff;text-decoration:none">← 허브로</a></div>'
    )
    text = re.sub(r'(<body[^>]*>)', lambda m: m.group(1) + banner, text, count=1)
    return text.encode("utf-8")


def rewrite_location(loc, prefix, iport):
    for hostname in ("127.0.0.1", "localhost"):
        loc = loc.replace(
            f"http://{hostname}:{iport}", f"http://{PUBLIC_HOST}:{PUBLIC_PORT}/{prefix}"
        )
    if loc.startswith("/") and not loc.startswith("//") and not loc.startswith(f"/{prefix}"):
        loc = f"/{prefix}{loc}"
    return loc


def rewrite_setcookie(val, prefix):
    """쿠키 Path 를 /prefix 로 좁혀 단계 간 세션이 섞이지 않게 한다."""
    if re.search(r";\s*Path=", val, re.I):
        return re.sub(r"(;\s*Path=)[^;]*", rf"\g<1>/{prefix}", val, flags=re.I)
    return val + f"; Path=/{prefix}"


# --------------------------------------------------------------------------
# 프록시 + 허브
# --------------------------------------------------------------------------
HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "accept-encoding",
    "content-length",
}


class Proxy(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):    self._route()
    def do_POST(self):   self._route()
    def do_PUT(self):    self._route()
    def do_DELETE(self): self._route()
    def do_HEAD(self):   self._route()

    def log_message(self, *a):  # 조용히
        pass

    def _route(self):
        parsed = urllib.parse.urlparse(self.path)
        segs = parsed.path.lstrip("/").split("/", 1)
        first = segs[0]
        if first == "":
            return self._hub()
        if first == "reset-progress":
            reset_progress()
            self.send_response(302)
            self.send_header("Location", "/")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if first not in PREFIX_PORT:
            self.send_error(404, "Not Found")
            return
        self._proxy(first, PREFIX_PORT[first], "/" + (segs[1] if len(segs) > 1 else ""),
                    parsed.query)

    def _proxy(self, prefix, iport, subpath, query):
        if query:
            subpath += "?" + query
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else None

        fwd = {k: self.headers[k] for k in self.headers.keys()
               if k.lower() not in HOP_BY_HOP}  # 원본 Host 유지 → Host 인젝션 보존

        try:
            conn = http.client.HTTPConnection("127.0.0.1", iport, timeout=30)
            conn.request(self.command, subpath, body=body, headers=fwd)
            resp = conn.getresponse()
            raw = resp.read()
            status, resp_headers = resp.status, resp.getheaders()
            conn.close()
        except Exception as e:
            self.send_error(502, f"proxy error: {e}")
            return

        ctype = next((v for k, v in resp_headers if k.lower() == "content-type"), "")
        if "html" in ctype.lower():
            # 🎉 마커가 응답에 있으면 = 익스플로잇 성공. 정적 FLAG 리터럴 오탐을 피하려
            # 반드시 마커 기준으로만 완료를 기록한다. (rewrite 는 마커에 영향 없음)
            if MARK_BYTES in raw:
                mark_done(prefix)
            raw = rewrite_html(raw, prefix, iport)

        self.send_response(status)
        for k, v in resp_headers:
            lk = k.lower()
            if lk in ("content-length", "transfer-encoding", "connection"):
                continue
            if lk == "set-cookie":
                v = rewrite_setcookie(v, prefix)
            elif lk == "location":
                v = rewrite_location(v, prefix, iport)
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(raw)

    def _hub(self):
        done_count = sum(1 for n, _, _ in STAGES if PROGRESS.get(f"hack{n}"))
        total = len(STAGES)
        pct = int(done_count / total * 100) if total else 0
        cards = ""
        for n, level, topics in STAGES:
            done = PROGRESS.get(f"hack{n}")
            mark = "✅" if done else "⬜"
            cards += (
                f'<a class="card{" done" if done else ""}" href="/hack{n}/">'
                f'<div class="row"><span class="check">{mark}</span>'
                f'<span class="badge">{n}단계</span>'
                f'<span class="level">{html.escape(level)}</span>'
                f'<span class="port">:{PREFIX_PORT.get(f"hack{n}", "?")}</span></div>'
                f'<div class="topics">{html.escape(topics)}</div></a>'
            )
        scoreboard = (
            f'<div class="score"><div class="score-top">'
            f'<b>진행 상황</b> <span class="score-n">{done_count} / {total} 완료</span>'
            f'<a class="reset" href="/reset-progress">진행 초기화</a></div>'
            f'<div class="bar"><div class="bar-fill" style="width:{pct}%"></div></div></div>'
        )
        page = f"""<!doctype html><html lang="ko"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>vulnrun — 웹 취약점 연습장</title>
<style>
 :root{{color-scheme:dark}}
 body{{margin:0;background:#0d1117;color:#e6edf3;font:15px/1.6 system-ui,-apple-system,sans-serif}}
 .wrap{{max-width:860px;margin:0 auto;padding:40px 20px 60px}}
 h1{{font-size:28px;margin:0 0 6px}}
 .sub{{color:#9aa4b2;margin:0 0 8px}}
 .warn{{color:#ffb454;background:#1c1710;border:1px solid #3a2f14;border-radius:8px;
        padding:10px 14px;margin:16px 0 28px;font-size:13px}}
 .card{{display:block;text-decoration:none;color:inherit;background:#161b22;
        border:1px solid #21262d;border-radius:12px;padding:16px 18px;margin:12px 0;
        transition:border-color .15s,transform .15s}}
 .card:hover{{border-color:#6cb6ff;transform:translateY(-1px)}}
 .row{{display:flex;align-items:center;gap:10px;margin-bottom:6px}}
 .check{{font-size:15px}}
 .badge{{background:#1f6feb;color:#fff;border-radius:6px;padding:2px 10px;font-size:13px;font-weight:600}}
 .level{{color:#e6edf3;font-weight:600}}
 .port{{margin-left:auto;color:#6e7681;font-size:12px;font-family:ui-monospace,monospace}}
 .topics{{color:#9aa4b2;font-size:13.5px}}
 .card.done{{border-color:#2ea043;background:#12211a}}
 .score{{background:#161b22;border:1px solid #21262d;border-radius:12px;padding:14px 18px;margin:8px 0 20px}}
 .score-top{{display:flex;align-items:center;gap:12px;margin-bottom:10px}}
 .score-n{{color:#7ee787;font-weight:600}}
 .reset{{margin-left:auto;color:#6e7681;font-size:12.5px;text-decoration:none;border:1px solid #30363d;
         border-radius:6px;padding:3px 10px}}
 .reset:hover{{color:#e6edf3;border-color:#6e7681}}
 .bar{{height:8px;background:#0d1117;border-radius:99px;overflow:hidden}}
 .bar-fill{{height:100%;background:linear-gradient(90deg,#1f6feb,#2ea043);transition:width .3s}}
</style></head><body><div class="wrap">
 <h1>🎯 vulnrun</h1>
 <p class="sub">DVWA 스타일 웹 취약점 연습장 · 단계별 챌린지</p>
 <div class="warn">⚠️ 모든 앱은 <b>고의로 취약</b>합니다. 오직 localhost(127.0.0.1)에서
   학습용으로만 실행하세요. 절대 공용 네트워크/서버에 노출하지 마세요.</div>
 {scoreboard}
 {cards}
</div></body></html>"""
        raw = page.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def main():
    for stream in (sys.stdout, sys.stderr):  # Windows 콘솔 cp949 → 한글/기호 출력 보장
        try:
            stream.reconfigure(encoding="utf-8")
        except Exception:
            pass
    for n, _, _ in STAGES:
        load_and_start(n)
    server = ThreadingHTTPServer((PUBLIC_HOST, PUBLIC_PORT), Proxy)
    print("vulnrun — 8단계 통합 실행 (hack1~hack8 준비됨)")
    print(f"접속: http://{PUBLIC_HOST}:{PUBLIC_PORT}   (Ctrl+C 로 종료)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n종료합니다.")


if __name__ == "__main__":
    main()
