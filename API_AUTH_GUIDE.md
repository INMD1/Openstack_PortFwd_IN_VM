# API 인증 설정 가이드

## ✅ 완료된 작업

API_SECRET_KEY 기반 인증이 성공적으로 구성되었습니다.

### 1. 환경 변수 설정 (.env)

`API_SECRET_KEY`가 `.env` 파일에 추가되었습니다:
```bash
API_SECRET_KEY=19zj8m6tQJed00T5EPVvyhrPBnAUbOUuR5cRZ8fN9OaevpPr8g
```

### 2. 인증 동작 방식

- **API_SECRET_KEY가 설정된 경우**: 모든 API 요청에 올바른 키가 필요합니다
- **키가 일치하지 않는 경우**: HTTP 401 Unauthorized 오류 반환
- **키가 없는 경우**: HTTP 401 Unauthorized 오류 반환

### 3. 보안 기능

- ✅ **타이밍 공격 방지**: `secrets.compare_digest()` 사용
- ✅ **Bearer Token 인증**: 표준 HTTP Authorization 헤더 사용
- ✅ **강력한 키**: 32바이트 암호학적으로 안전한 랜덤 토큰

## 📋 사용 방법

### API 호출 예시

```bash
# 올바른 방법 (인증 포함)
curl -H "Authorization: Bearer 19zj8m6tQJed00T5EPVvyhrPBnAUbOUuR5cRZ8fN9OaevpPr8g" \
  http://localhost:8080/api/v1/status

# 잘못된 방법 (인증 없음) - 401 오류 발생
curl http://localhost:8080/api/v1/status
```

### Python에서 사용

```python
import requests

API_KEY = "19zj8m6tQJed00T5EPVvyhrPBnAUbOUuR5cRZ8fN9OaevpPr8g"
BASE_URL = "http://localhost:8080/api/v1"

headers = {
    "Authorization": f"Bearer {API_KEY}"
}

# 상태 조회
response = requests.get(f"{BASE_URL}/status", headers=headers)
print(response.json())

# 포트포워딩 규칙 생성
data = {
    "rule_name": "My Rule",
    "user_vm_id": "uuid-here",
    # ... 기타 필드
}
response = requests.post(f"{BASE_URL}/rules", headers=headers, json=data)
print(response.json())
```

## 🧪 인증 테스트

테스트 스크립트를 실행하여 인증이 제대로 작동하는지 확인할 수 있습니다:

```bash
./test_api_auth.sh
```

테스트 내용:
1. ❌ 키 없이 접근 → 401 Unauthorized
2. ❌ 잘못된 키로 접근 → 401 Unauthorized  
3. ✅ 올바른 키로 접근 → 200 OK

## 🔒 보안 권장사항

### API 키 변경 (프로덕션 환경)

새로운 강력한 키 생성:
```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

생성된 키를 `.env` 파일의 `API_SECRET_KEY`에 복사합니다.

### 키 보안 관리

- ✅ `.env` 파일을 git에 커밋하지 마세요 (`.gitignore`에 추가)
- ✅ 프로덕션과 개발 환경에서 다른 키 사용
- ✅ 정기적으로 키를 교체
- ✅ 키를 코드에 하드코딩하지 마세요
- ✅ 키를 로그에 출력하지 마세요

### API 서버 재시작

`.env` 파일을 수정한 후에는 API 서버를 재시작해야 합니다:

```bash
# 현재 실행 중인 프로세스 종료
pkill -f portfwd_api.py

# 서버 재시작
python3 portfwd_api.py
```

또는 systemd를 사용하는 경우:
```bash
sudo systemctl restart portfwd-api
```

## 📊 모니터링

인증 실패 시도는 로그에 기록됩니다:

```
2026-02-04 18:50:30 - __main__ - WARNING - API 인증 실패: 잘못된 키 시도
```

정기적으로 로그를 확인하여 무단 접근 시도를 모니터링하세요.

## ⚙️ 환경별 설정

### 개발 환경 (인증 비활성화)

개발 중 인증을 비활성화하려면 `.env`에서:
```bash
# API_SECRET_KEY를 비우거나 주석 처리
API_SECRET_KEY=
```

**⚠️ 주의**: 프로덕션 환경에서는 절대로 비활성화하지 마세요!

### 프로덕션 환경 (인증 필수)

`.env` 파일에서:
```bash
ENV=production
API_SECRET_KEY=<강력한-랜덤-키>
```

## 🔧 트러블슈팅

### 401 Unauthorized 오류

**원인**: API 키가 없거나 잘못되었습니다.

**해결방법**:
1. `.env` 파일에서 `API_SECRET_KEY` 확인
2. 요청 헤더에 `Authorization: Bearer <키>` 포함 확인
3. 키에 공백이나 특수문자가 없는지 확인
4. API 서버를 재시작했는지 확인

### 환경 변수가 로드되지 않음

**원인**: `.env` 파일이 올바른 위치에 없거나 서버가 재시작되지 않았습니다.

**해결방법**:
1. `.env` 파일이 `portfwd_api.py`와 같은 디렉토리에 있는지 확인
2. API 서버 재시작
3. 로그에서 "API_SECRET_KEY가 설정되지 않음" 경고 메시지 확인
