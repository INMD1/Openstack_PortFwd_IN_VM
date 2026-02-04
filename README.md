# README - OpenStack Proxy VM Port Forwarding API

## 개요

OpenStack에 있는 내부 네트워크를 외부로 포트포워딩 하기 위한 Api 시스템 입니다.

---

## 설치

### 1. 사전 요구사항

```bash
# Python 3.9+
python3 --version

# pip
pip3 --version

# 개발 환경에서 SQLite 사용 가능, 프로덕션은 PostgreSQL 권장
```

### 2. 의존성 설치

```bash
# 가상환경 생성 (권장)
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# 또는
venv\Scripts\activate  # Windows

# 패키지 설치
pip install -r requirements.txt
```

### 3. 환경 설정

```bash
# .env 파일 생성
cp .env.example .env

# .env 파일 수정 (필수)
```

#### 주요 환경 변수

**보안 설정 (필수)**
```bash
# API 인증 키 - 프로덕션 환경에서 반드시 설정
API_SECRET_KEY=your-secret-key-here

# 강력한 키 생성 방법:
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

**Floating IP 설정**
```bash
# SSH 전용 IP (랜덤 포트 할당)
SSH_FLOATING_IP=192.168.10.179
SSH_FLOATING_IP_GET=113.198.230.17  # 외부 표시용 IP

# 일반 포트포워딩 IP (부하 분산)
PORTFWD_FLOATING_IP_1=192.168.10.3
PORTFWD_FLOATING_IP_1_GET=113.198.230.18

PORTFWD_FLOATING_IP_2=192.168.10.16
PORTFWD_FLOATING_IP_2_GET=113.198.230.20
```

**프록시 모드 설정**
```bash
# local: Proxy VM 내부에서 직접 실행
# remote: SSH로 원격 Proxy VM 제어
PROXY_MODE=local

# production: 실제 iptables 적용
# development: 시뮬레이션만 수행
ENV=production
```

**포트 범위 및 제한**
```bash
# SSH 포트 범위
SSH_PORT_MIN=1
SSH_PORT_MAX=1000

# 일반 포트포워딩 범위
PORTFWD_PORT_MIN=1
PORTFWD_PORT_MAX=1000

# 제외할 포트 (쉼표로 구분)
PORTFWD_EXCLUDED_PORTS=220,80,443,1420,8080

# IP당 최대 규칙 수
MAX_RULES_PER_IP=600
```

---

## 실행

### 개발 환경

```bash
# 자동 리로드를 활성화한 개발 서버
python3 portfwd_api.py

# 또는 Uvicorn 직접 실행
uvicorn portfwd_api:app --reload --host 0.0.0.0 --port 8080
```

API는 `http://localhost:8080`에서 실행됩니다.

### 프로덕션 환경

```bash
# Gunicorn + Uvicorn (권장)
pip install gunicorn

gunicorn portfwd_api:app \
  --workers 1 \
  --worker-class uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:8080 \
  --log-level info

# 또는 Systemd 서비스로 등록
# (deploy/portfwd-api.service 참조)
```

### Docker 배포

```bash
# Dockerfile 작성 (아래 제공)
docker build -t openstack-portfwd-api .

# 컨테이너 실행
docker run -d \
  -p 8080:8080 \
  -e DATABASE_URL="postgresql://user:pass@db:5432/skyline" \
  -e PROXY_VM_IP="172.24.4.10" \
  -e ENV="production" \
  openstack-portfwd-api
```

---

## API 사용 가이드

### 1. 자동 생성 문서

API 실행 후 브라우저에서 접속:
- **Swagger UI**: http://localhost:8080/api/v1/docs
- **ReDoc**: http://localhost:8080/api/v1/redoc

### 2. 헬스 체크

```bash
curl http://localhost:8080/api/v1/health
```

응답:
```json
{
  "status": "healthy",
  "timestamp": "2026-01-22T01:44:00.000000",
  "version": "1.0.0"
}
```

### 3. 포트포워딩 규칙 생성

**⚠️ 인증 필수**: 모든 요청에 `Authorization` 헤더를 포함해야 합니다.

```bash
curl -X POST http://localhost:8080/api/v1/portforward \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_SECRET_KEY" \
  -d '{
    "rule_name": "web-server-80",
    "user_vm_id": "550e8400-e29b-41d4-a716-446655440000",
    "user_vm_name": "web-server-01",
    "user_vm_internal_ip": "10.0.0.6",
    "user_vm_internal_port": 80,
    "service_type": "other",
    "protocol": "tcp",
    "description": "웹 서버 포트포워딩"
  }'
```

응답 (자동 할당):
```json
{
  "id": 1,
  "rule_id": "uuid-xxxx-xxxx",
  "rule_name": "web-server-80",
  "user_vm_id": "550e8400-e29b-41d4-a716-446655440000",
  "user_vm_name": "web-server-01",
  "user_vm_internal_ip": "10.0.0.6",
  "user_vm_internal_port": 80,
  "proxy_external_ip": "172.24.4.11",
  "proxy_external_port": 10001,
  "protocol": "tcp",
  "status": "active",
  "created_at": "2026-01-22T01:44:00",
  "updated_at": "2026-01-22T01:44:00",
  "created_by": "anonymous",
  "description": "웹 서버 SSH 접속"
}
```

### 4. 규칙 목록 조회

```bash
# 모든 규칙
curl -H "Authorization: Bearer YOUR_API_SECRET_KEY" \
  http://localhost:8080/api/v1/portforward

# 활성 규칙만
curl -H "Authorization: Bearer YOUR_API_SECRET_KEY" \
  http://localhost:8080/api/v1/portforward?status=active

# 특정 Floating IP 규칙
curl -H "Authorization: Bearer YOUR_API_SECRET_KEY" \
  http://localhost:8080/api/v1/portforward?floating_ip=113.198.230.18
```

### 5. 특정 규칙 조회

```bash
curl -H "Authorization: Bearer YOUR_API_SECRET_KEY" \
  http://localhost:8080/api/v1/portforward/{rule_id}
```

### 6. 규칙 업데이트

```bash
curl -X PATCH http://localhost:8080/api/v1/portforward/{rule_id} \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_SECRET_KEY" \
  -d '{
    "status": "inactive",
    "description": "임시 비활성화"
  }'
```

### 7. 규칙 삭제

```bash
curl -X DELETE \
  -H "Authorization: Bearer YOUR_API_SECRET_KEY" \
  http://localhost:8080/api/v1/portforward/{rule_id}
```

### 8. 시스템 상태 조회

```bash
curl -H "Authorization: Bearer YOUR_API_SECRET_KEY" \
  http://localhost:8080/api/v1/status
```

응답:
```json
{
  "total_rules": 5,
  "active_rules": 4,
  "inactive_rules": 1,
  "pending_rules": 0,
  "used_ports": 4,
  "available_ports": 29996,
  "floating_ips": {
    "172.24.4.11": {
      "active_rules": 2,
      "total_rules": 2,
      "max_rules": 10,
      "usage_percent": 20.0,
      "ports": [10001, 10002]
    },
    "172.24.4.12": {
      "active_rules": 2,
      "total_rules": 2,
      "max_rules": 10,
      "usage_percent": 20.0,
      "ports": [10003, 10004]
    }
  }
}
```

### 9. Floating IP 상태

```bash
curl -H "Authorization: Bearer YOUR_API_SECRET_KEY" \
  http://localhost:8080/api/v1/floating-ips
```

### 10. 서비스 유형에 따른 IP 할당

**SSH 서비스** (service_type: "ssh")
- SSH 전용 IP (SSH_FLOATING_IP) 사용
- 랜덤 포트 자동 할당
- SSH 포트 범위 내에서 선택

```bash
curl -X POST http://localhost:8080/api/v1/portforward \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_SECRET_KEY" \
  -d '{
    "rule_name": "ssh-to-vm1",
    "user_vm_id": "uuid-here",
    "user_vm_name": "vm-1",
    "user_vm_internal_ip": "10.0.0.5",
    "user_vm_internal_port": 22,
    "service_type": "ssh",
    "protocol": "tcp"
  }'
```

**일반 포트포워딩** (service_type: "other")
- 2개의 포트포워딩 IP 중 부하가 적은 IP 자동 선택
- 순차적 포트 할당

```bash
curl -X POST http://localhost:8080/api/v1/portforward \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_SECRET_KEY" \
  -d '{
    "rule_name": "web-service",
    "user_vm_id": "uuid-here",
    "user_vm_name": "web-vm",
    "user_vm_internal_ip": "10.0.0.10",
    "user_vm_internal_port": 80,
    "service_type": "other",
    "protocol": "tcp"
  }'
```

---

## 🔒 API 인증 (필수)

### API_SECRET_KEY 설정

`.env` 파일에 `API_SECRET_KEY`가 설정되어 있으면 모든 API 요청에 인증이 필요합니다.

**1. 강력한 키 생성**
```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

**2. .env 파일에 추가**
```bash
API_SECRET_KEY=KgIwKUsbnTmNNlsX51F_yhKmM_yPzAvxnE4LNjw4exk
```

**3. API 호출 시 모든 요청에 Authorization 헤더 포함**
```bash
curl -H "Authorization: Bearer KgIwKUsbnTmNNlsX51F_yhKmM_yPzAvxnE4LNjw4exk" \
  http://localhost:8080/api/v1/status
```

### 인증 동작 방식

- ✅ **올바른 키**: API 정상 작동
- ❌ **키 없음**: HTTP 401 Unauthorized
- ❌ **잘못된 키**: HTTP 401 Unauthorized

### Python에서 사용

```python
import requests

API_KEY = "KgIwKUsbnTmNNlsX51F_yhKmM_yPzAvxnE4LNjw4exk"
BASE_URL = "http://localhost:8080/api/v1"

headers = {"Authorization": f"Bearer {API_KEY}"}

# 모든 요청에 headers 포함
response = requests.get(f"{BASE_URL}/status", headers=headers)
print(response.json())
```

### 보안 권장사항

⚠️ **중요**: 프로덕션 환경에서는 반드시 `API_SECRET_KEY`를 설정하세요!

- `.env` 파일을 git에 커밋하지 마세요
- 정기적으로 키를 교체하세요
- 키를 로그에 출력하지 마세요
- HTTPS를 사용하여 키 노출을 방지하세요

> 📖 자세한 내용은 [`API_AUTH_GUIDE.md`](./API_AUTH_GUIDE.md) 참조

---

## Proxy VM 설정

### SSH 키 기반 인증 설정

Proxy VM에서 Skyline API가 iptables 규칙을 자동으로 적용하려면:

```bash
# Proxy VM (root)
ssh-keygen -t rsa -N "" -f ~/.ssh/id_rsa

# Skyline API 서버에서
# ~/.ssh/authorized_keys에 공개키 추가
scp ~/.ssh/id_rsa.pub root@172.24.4.10:/tmp/
ssh root@172.24.4.10 'cat /tmp/id_rsa.pub >> ~/.ssh/authorized_keys'
```

### iptables 규칙 수동 확인

```bash
# Proxy VM에서
sudo iptables -t nat -L -n -v

# 특정 포트 규칙 확인
sudo iptables -t nat -L -n -v | grep 172.24.4.11
```

### iptables 규칙 저장 (Debian/Ubuntu)

```bash
# API에서 규칙을 생성하고 저장하려면
sudo iptables-save > /etc/iptables/rules.v4
sudo ip6tables-save > /etc/iptables/rules.v6

# 부팅 시 자동 복구
apt install iptables-persistent
dpkg-reconfigure iptables-persistent
```

---

## 데이터베이스 마이그레이션

### SQLite → PostgreSQL

```bash
# 기존 SQLite 데이터 내보내기
sqlite3 portfwd_rules.db ".dump" > dump.sql

# PostgreSQL에 가져오기
psql -U postgres -d skyline_portfwd < dump.sql
```

---

## 트러블슈팅

### 1. 포트 충돌 오류

```
409 CONFLICT: 포트는 이미 사용 중입니다
```

**해결:**
```bash
# 사용 중인 포트 확인
curl http://localhost:8080/api/v1/status

# 기존 규칙 삭제 후 재생성
curl -X DELETE http://localhost:8080/api/v1/portforward/{rule_id}
```

### 2. Floating IP 용량 초과

```
503 SERVICE UNAVAILABLE: 모든 Floating IP가 용량을 초과했습니다
```

**해결:**
- 사용하지 않는 규칙 삭제
- Floating IP 추가 (MAX_RULES_PER_IP = 10)

### 3. iptables 규칙 적용 실패

```
ENV=development에서는 시뮬레이션만 수행됩니다.
ENV=production으로 설정하면 실제 iptables 규칙이 적용됩니다.
```

**확인:**
```bash
tail -f /var/log/syslog | grep iptables
```

---

## 성능 최적화

### 1. 동시성 처리

```bash
# Gunicorn 워커 수 증가
gunicorn portfwd_api:app --workers 8
```

### 2. 데이터베이스 인덱싱

PostgreSQL 사용 시:
```sql
CREATE INDEX idx_rule_name ON port_forwarding_rules(rule_name);
CREATE INDEX idx_floating_ip ON port_forwarding_rules(proxy_external_ip);
CREATE INDEX idx_status ON port_forwarding_rules(status);
```

### 3. 캐싱

Redis 추가 (선택사항):
```python
from fastapi_cache2 import FastAPICache2
from fastapi_cache2.backends.redis import RedisBackend

FastAPICache2.init(RedisBackend(url="redis://localhost"), prefix="fastapi-cache")
```

---

## 배포 예시 (Systemd)

`/etc/systemd/system/portfwd-api.service`:

```ini
[Unit]
Description=OpenStack Port Forwarding API
After=network.target

[Service]
Type=notify
User=www-data
WorkingDirectory=/opt/portfwd-api
ExecStart=/opt/portfwd-api/venv/bin/gunicorn \
  portfwd_api:app \
  --workers 4 \
  --worker-class uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:8080

Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

**시작:**
```bash
sudo systemctl start portfwd-api
sudo systemctl enable portfwd-api
sudo systemctl status portfwd-api
```

---

## 모니터링

### 로그 확인

```bash
# 실시간 로그
tail -f /var/log/portfwd-api.log

# 특정 오류 검색
grep "ERROR" /var/log/portfwd-api.log
```

### 메트릭 (Prometheus)

Prometheus 통합을 위해 `prometheus-client` 추가:

```bash
pip install prometheus-client
```

그 후 엔드포인트 추가:

```python
from prometheus_client import Counter, Histogram, generate_latest

rule_created = Counter('portfwd_rules_created', 'Created rules')
rule_deleted = Counter('portfwd_rules_deleted', 'Deleted rules')
```

---

## 라이선스

OpenStack 호환 오픈소스 라이선스

---

## 지원

문제 발생 시:
1. 로그 확인: `tail -f portfwd-api.log`
2. API 문서: http://localhost:8080/api/v1/docs
3. 상태 조회: `curl http://localhost:8080/api/v1/status`
