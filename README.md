# hack — 웹 취약점 연습장

DVWA 스타일의 **고의로 취약한** 웹앱 모음. 각 단계는 의존성 없는 순수 Python 표준
라이브러리로 작성되어 있고, **오직 localhost(127.0.0.1)에서 학습용으로만** 실행합니다.

> ⚠️ 경고: 절대 공용 네트워크/서버에 노출하지 마세요.

## 단계

| 폴더 | 포트 | 난이도 | 주제 |
|------|------|--------|------|
| `hack1/` | 8000 | 입문 | SQLi, Reflected/Stored XSS, Command Injection, Path Traversal |
| `hack2/` | 8001 | 중급 | Blind SQLi, XSS 필터 우회, IDOR, 세션 토큰 위조, SSRF |
| `hack3/` | 8002 | 중상 | 인증/세션 — JWT `alg:none`, 약한 JWT 서명, CSRF, 예측가능 재설정 토큰 |
| `hack4/` | 8003 | 중상~상 | 템플릿/역직렬화 RCE — SSTI(eval), pickle 역직렬화, format-string 유출 |
| `hack5/` | 8004 | 상 | 접근제어/로직 — mass-assignment 권한상승, 결제단계 건너뛰기, 음수 가격 |
| `hack6/` | 8005 | 상 | 인젝션 심화 — 2차 SQLi, XML 엔티티, 오픈 리다이렉트, Host 헤더 인젝션 |
| `hack7/` | 8006 | 상 | 타이밍/경합 — 레이스 컨디션 이중지불, 타이밍 사이드채널, TOCTOU |
| `hack8/` | 8007 | 최상 | 연쇄 킬체인 — XSS→토큰탈취→권한상승→SSRF→완전장악 (4단계 체인) |

## 실행

```powershell
python hack1/vuln_app.py   # http://127.0.0.1:8000
python hack2/vuln_app.py   # http://127.0.0.1:8001
python hack3/vuln_app.py   # http://127.0.0.1:8002
python hack4/vuln_app.py   # http://127.0.0.1:8003
python hack5/vuln_app.py   # http://127.0.0.1:8004
python hack6/vuln_app.py   # http://127.0.0.1:8005
python hack7/vuln_app.py   # http://127.0.0.1:8006
python hack8/vuln_app.py   # http://127.0.0.1:8007
```

각 페이지에 **목표 · 힌트 · 정답(펼치기) · 방어법**이 포함되어 있습니다.
낮은 단계부터 순서대로 진행하세요 — 2단계부터는 허술한 방어의 우회가, 8단계는
여러 취약점을 사슬로 엮는 연쇄 공격이 필요합니다.

### 참고
- `hack6` 의 XML 엔티티는 Python 표준 라이브러리 파서가 외부 엔티티(XXE)를 막아,
  실제로 동작하는 **DTD 내부 엔티티 확장(billion-laughs형 DoS)** 으로 대체했습니다
  (페이지·주석에 사유 명시).
- 모든 단계는 실제로 익스플로잇 가능함을 확인했습니다(각 성공 시 🎉 + FLAG 노출).
