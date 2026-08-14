# hack — 웹 취약점 연습장

DVWA 스타일의 **고의로 취약한** 웹앱 모음. 각 단계는 의존성 없는 순수 Python 표준
라이브러리로 작성되어 있고, **오직 localhost(127.0.0.1)에서 학습용으로만** 실행합니다.

> ⚠️ 경고: 절대 공용 네트워크/서버에 노출하지 마세요.

## 단계

| 폴더 | 포트 | 난이도 | 주제 |
|------|------|--------|------|
| `hack1/` | 8000 | 입문 | SQLi, Reflected/Stored XSS, Command Injection, Path Traversal |
| `hack2/` | 8001 | 중급 | Blind SQLi, XSS 필터 우회, IDOR, 세션 토큰 위조, SSRF |

## 실행

```powershell
python hack1/vuln_app.py   # http://127.0.0.1:8000
python hack2/vuln_app.py   # http://127.0.0.1:8001
```

각 페이지에 **목표 · 힌트 · 정답(펼치기) · 방어법**이 포함되어 있습니다.
1단계를 먼저 끝낸 뒤 2단계로 넘어가세요 — 2단계는 필터/우회가 필요합니다.
