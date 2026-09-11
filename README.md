# Mini Notes App (OpenHands 데모용)

아주 작은 메모 공유 Flask 웹앱입니다. `/login`으로 로그인하고, `/notes`로 메모를 남기고,
`/ping`으로 서버 상태를 점검할 수 있습니다.

> ⚠️ 이 저장소는 OpenHands "보안 취약점 자동 수정" 데모를 위해 일부러 취약점을
> 심어 놓은 예제입니다. 실제 서비스에 쓰지 마세요.

## 실행 방법

```bash
pip install -r requirements.txt
python app.py
```

## OpenHands 데모 프롬프트 예시

```
이 프로젝트 코드를 스캔해서 보안 취약점(예: SQL 인젝션, 하드코딩된 시크릿,
안전하지 않은 subprocess/eval/os.system 사용 등)을 찾아줘.
문제를 찾으면 각각 어떤 파일의 몇 번째 줄인지 설명하고, 바로 코드를 고쳐줘.
고친 후에는 다시 한번 스캔해서 문제가 해결됐는지 확인해줘.
```
