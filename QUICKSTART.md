# QUICKSTART.md - 빠른 시작 가이드

## 🚀 5분 안에 시작하기

### 1️⃣ 설치 (1분)

```bash
# 저장소 복제
git clone <repo-url>
cd portfwd-api

# 가상환경 생성 및 활성화
python3 -m venv venv
source venv/bin/activate

# 의존성 설치
pip install -r requirements.txt

# .env 파일 생성
cp .env.example .env
```

### 2️⃣ API 시작 (1분)

```bash
# 개발 서버 실행
python3 portfwd_api.py

# 출력:
# INFO:     Uvicorn running on http://0.0.0.0:8080
# INFO:     Application startup complete
```

### 3️⃣ API 확인 (1분)

브라우저 열기:
- **API 문서**: http://localhost:8080/api/v1/docs
- **ReDoc**: http://localhost:8080/api/v1/redoc

또는 터미널에서:
```bash
curl http://localhost:8080/api/v1/health
```

### 4️⃣ 첫 규칙 생성 (1분)

```bash
curl -X POST http://localhost:8080/api/v1/portforward \
  -H "Content-Type: application/json" \
  -d '{
    "rule_name": "my-web-server",
    "user_vm_id": "550e8400-e29b-41d4-a716-446655440000",
    "user_vm_name": "web-01",
    "user_vm_internal_ip": "10.0.0.6",
    "user_vm_internal_port": 80,
    "protocol": "tcp"
  }'
```

**응답:**
```json
{
  "rule_id": "abc123...",
  "rule_name": "my-web-server",
  "proxy_external_ip": "172.24.4.11",
  "proxy_external_port": 10001,
  "status": "active",
  ...
}
```

### 5️⃣ 규칙 조회 (1분)

```bash
# 모든 규칙
curl http://localhost:8080/api/v1/portforward

# 시스템 상태
curl http://localhost:8080/api/v1/status
```

---

## 🎯 CLI 사용 (선택사항)

```bash
# 설치
pip install requests tabulate

# 사용 예시
python3 portfwd_client.py create my-rule uuid-xxxx vm-name 10.0.0.6 80
python3 portfwd_client.py list
python3 portfwd_client.py status
python3 portfwd_client.py delete <rule-id>
```

---

## 🐳 Docker로 실행 (2분)

```bash
# docker-compose 실행
docker-compose up -d

# API 확인
curl http://localhost:8080/api/v1/health

# 로그 확인
docker-compose logs -f api
```

---

## 📚 다음 단계

1. **README.md** - 자세한 설정 및 배포 가이드
2. **API 문서** - http://localhost:8080/api/v1/docs
3. **프로덕션 배포** - README.md의 "프로덕션 환경" 섹션

---

## 🆘 문제 해결

### 포트 이미 사용 중
```bash
# 다른 포트 사용
python3 -m uvicorn portfwd_api:app --port 8081
```

### 데이터베이스 오류
```bash
# SQLite 파일 삭제 후 재생성
rm portfwd_rules.db
python3 portfwd_api.py
```

### 모듈 찾을 수 없음
```bash
# 가상환경 활성화 확인
source venv/bin/activate
pip install -r requirements.txt
```

---

## 💡 주요 기능

✅ **자동 포트 할당** - 10000-20000 범위에서 자동 선택
✅ **부하 분산** - 여러 Floating IP에 균등 분배
✅ **포트 충돌 방지** - 중복 할당 불가
✅ **실시간 모니터링** - 용량 및 상태 조회
✅ **자동 iptables 적용** - Proxy VM에 규칙 자동 배포
✅ **OpenAPI 문서** - Swagger UI로 자동 생성

---

## 🔗 유용한 링크

- [OpenStack Neutron Port Forwarding](https://docs.openstack.org/neutron/latest/admin/config-fip-port-forwardings.html)
- [FastAPI 문서](https://fastapi.tiangolo.com/)
- [SQLAlchemy 문서](https://docs.sqlalchemy.org/)

---

좋은 개발되세요! 🚀
