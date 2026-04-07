# ============================================================================
# OpenStack Skyline Proxy VM 포트포워딩 관리 API
# FastAPI 기반 프로덕션급 REST API
# ============================================================================

import os
from dotenv import load_dotenv

# .env 파일 로드
load_dotenv()

import subprocess
import uuid
import random
import re
import secrets
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional, List, Tuple
from enum import Enum
from ipaddress import IPv4Address, AddressValueError
from netplan_manager import add_vm_route, remove_vm_route, sync_routes_from_vm_ips, sync_routes_from_db

from fastapi import FastAPI, HTTPException, status, Header, Depends, Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import BaseModel, Field, field_validator, ConfigDict
from sqlalchemy import create_engine, Column, String, Integer, DateTime, Boolean
from sqlalchemy.orm import DeclarativeBase, sessionmaker, Session
import logging

# Rate Limiting (선택적 - 설치되지 않은 경우 비활성화)
try:
    from slowapi import Limiter, _rate_limit_exceeded_handler
    from slowapi.util import get_remote_address
    from slowapi.errors import RateLimitExceeded
    RATE_LIMITING_ENABLED = True
except ImportError:
    RATE_LIMITING_ENABLED = False
    logger_init = logging.getLogger(__name__)
    logger_init.warning("slowapi가 설치되지 않음 - Rate Limiting 비활성화 (pip install slowapi)")

# ============================================================================
# 로깅 설정
# ============================================================================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ============================================================================
# 보안 설정
# ============================================================================
# API 인증 키 (환경변수로 설정, 없으면 anonymous 허용)
API_SECRET_KEY = os.getenv('API_SECRET_KEY', '')
API_AUTH_ENABLED = bool(API_SECRET_KEY.strip())

if not API_AUTH_ENABLED:
    logger.warning("⚠️ API_SECRET_KEY가 설정되지 않음 - 인증 없이 접근 허용됨 (프로덕션에서는 설정 권장)")

# Rate Limit 설정
RATE_LIMIT_REQUESTS = os.getenv('RATE_LIMIT_REQUESTS', '60/minute')
RATE_LIMIT_BURST = os.getenv('RATE_LIMIT_BURST', '10/second')

# ============================================================================
# 스캐너/봇 차단 미들웨어
# ============================================================================
# 즉시 밴할 경로 패턴 (/api/v1/ 제외)
_BLOCKED_PATH_RE = re.compile(
    r'^('
    r'/\.env[^/]*'          # /.env, /.env.local, /.env.prod 등
    r'|/\.git/'             # /.git/ 하위 전체
    r'|/\.aws/'             # /.aws/ 하위 전체
    r'|.*\.php$'            # .php 로 끝나는 모든 경로
    r'|/wp-[^/]+'           # /wp-* (WordPress)
    r'|/backup[^/]*'        # /backup*
    r'|/config\.json'       # /config.json
    r'|/docker-compose[^/]*' # /docker-compose*
    r')'
)

_BAN_404_WINDOW = 60    # seconds
_BAN_404_THRESHOLD = 10 # 60초 내 404 횟수 임계값

_banned_ips: set = set()
_violation_times: dict = defaultdict(deque)  # ip → deque of timestamps


def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get('X-Forwarded-For')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.client.host if request.client else '0.0.0.0'


def _ban_ip(ip: str, reason: str) -> None:
    _banned_ips.add(ip)
    logger.warning(f"[BAN] {ip} - {reason}")
    if os.getenv('ENV') == 'production':
        subprocess.run(
            f"sudo iptables -I INPUT -s {ip} -j DROP",
            shell=True, capture_output=True
        )


def _unban_ip(ip: str) -> None:
    _banned_ips.discard(ip)
    if os.getenv('ENV') == 'production':
        subprocess.run(
            f"sudo iptables -D INPUT -s {ip} -j DROP",
            shell=True, capture_output=True
        )


class SecurityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        ip = _get_client_ip(request)
        path = request.url.path

        # 1. 밴된 IP → 즉시 차단
        if ip in _banned_ips:
            return JSONResponse(status_code=403, content={"detail": "접근이 거부되었습니다"})

        # 2. 차단 경로 패턴 (정상 API 경로 /api/v1/ 제외)
        if not path.startswith('/api/v1/') and _BLOCKED_PATH_RE.match(path):
            _ban_ip(ip, f"차단 경로 접근: {path}")
            return JSONResponse(status_code=403, content={"detail": "접근이 거부되었습니다"})

        # 3. 정상 요청 통과
        response = await call_next(request)

        # 4. 404 위반 횟수 기록 → 임계값 초과 시 밴
        if response.status_code == 404:
            now = time.time()
            times = _violation_times[ip]
            times.append(now)
            while times and times[0] < now - _BAN_404_WINDOW:
                times.popleft()
            if len(times) > _BAN_404_THRESHOLD:
                _ban_ip(ip, f"60초 내 404 {len(times)}회 초과")

        return response

# ============================================================================
# 입력값 검증 함수 (명령 인젝션 방지)
# ============================================================================
def sanitize_ip(ip: str) -> str:
    if not ip:
        raise ValueError("IP 주소가 비어있습니다")
    if not re.match(r'^[0-9.]+$', ip):
        raise ValueError(f"유효하지 않은 IP 주소 형식: {ip}")
    try:
        validated = IPv4Address(ip)
        return str(validated)
    except AddressValueError:
        raise ValueError(f"유효하지 않은 IPv4 주소: {ip}")

def sanitize_port(port: int) -> int:
    if not isinstance(port, int):
        raise ValueError(f"포트는 정수여야 합니다: {port}")
    if port < 1 or port > 999:
        raise ValueError(f"포트 범위 초과 (1-999): {port}")
    return port

def sanitize_protocol(protocol: str) -> str:
    protocol = protocol.lower().strip()
    if protocol not in ('tcp', 'udp'):
        raise ValueError(f"유효하지 않은 프로토콜: {protocol}")
    return protocol

def validate_rule_name(name: str) -> str:
    if not name or len(name) > 255:
        raise ValueError("규칙 이름은 1-255자여야 합니다")
    if not re.match(r'^[\w\s가-힣\-]+$', name, re.UNICODE):
        raise ValueError(f"규칙 이름에 허용되지 않은 문자 포함: {name}")
    return name.strip()

# ============================================================================
# 데이터베이스 설정
# ============================================================================
DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///./portfwd_rules.db')
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

class Base(DeclarativeBase):
    pass

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ============================================================================
# Floating IP 설정 (역할별 분리)
# ============================================================================
class FloatingIPConfig:
    SSH_FLOATING_IP = os.getenv('SSH_FLOATING_IP', '10.0.0.11')
    SSH_FLOATING_IP_GET = os.getenv('SSH_FLOATING_IP_GET', SSH_FLOATING_IP)
    
    PORTFWD_FLOATING_IP_1 = os.getenv('PORTFWD_FLOATING_IP_1', '10.0.0.12')
    PORTFWD_FLOATING_IP_1_GET = os.getenv('PORTFWD_FLOATING_IP_1_GET', PORTFWD_FLOATING_IP_1)

    PORTFWD_FLOATING_IP_2 = os.getenv('PORTFWD_FLOATING_IP_2', '10.0.0.13')
    PORTFWD_FLOATING_IP_2_GET = os.getenv('PORTFWD_FLOATING_IP_2_GET', PORTFWD_FLOATING_IP_2)

    PORTFWD_FLOATING_IPS = [
        PORTFWD_FLOATING_IP_1,
        PORTFWD_FLOATING_IP_2
    ]
    
    IP_MAP = {
        SSH_FLOATING_IP: SSH_FLOATING_IP_GET,
        PORTFWD_FLOATING_IP_1: PORTFWD_FLOATING_IP_1_GET,
        PORTFWD_FLOATING_IP_2: PORTFWD_FLOATING_IP_2_GET
    }
    
    REVERSE_IP_MAP = {v: k for k, v in IP_MAP.items()}

    @classmethod
    def get_external_ip(cls, internal_ip: str) -> str:
        return cls.IP_MAP.get(internal_ip, internal_ip)

    @classmethod
    def get_internal_ip(cls, external_ip: str) -> str:
        if external_ip in cls.IP_MAP:
            return external_ip
        return cls.REVERSE_IP_MAP.get(external_ip, external_ip)
    
    ALL_FLOATING_IPS = [SSH_FLOATING_IP] + PORTFWD_FLOATING_IPS
    
    SSH_PORT_RANGE = (
        int(os.getenv('SSH_PORT_MIN', 100)),
        int(os.getenv('SSH_PORT_MAX', 999))
    )
    PORTFWD_PORT_RANGE = (
        int(os.getenv('PORTFWD_PORT_MIN', 100)),
        int(os.getenv('PORTFWD_PORT_MAX', 999))
    )
    
    @staticmethod
    def _parse_excluded_ports(env_var: str) -> set:
        ports_str = os.getenv(env_var, '')
        if not ports_str.strip():
            return set()
        try:
            return {int(p.strip()) for p in ports_str.split(',') if p.strip()}
        except ValueError:
            return set()
    
    SSH_EXCLUDED_PORTS = _parse_excluded_ports.__func__('SSH_EXCLUDED_PORTS')
    PORTFWD_EXCLUDED_PORTS = _parse_excluded_ports.__func__('PORTFWD_EXCLUDED_PORTS')
    MAX_RULES_PER_IP = int(os.getenv('MAX_RULES_PER_IP', 100))

# 기존 설정과의 호환성 유지
FLOATING_IPS = FloatingIPConfig.ALL_FLOATING_IPS
PROXY_EXTERNAL_PORT_RANGE = FloatingIPConfig.PORTFWD_PORT_RANGE
MAX_RULES_PER_IP = FloatingIPConfig.MAX_RULES_PER_IP
PROXY_VM_IP = os.getenv('PROXY_VM_IP', '172.24.4.10')
PROXY_VM_SSH_PORT = int(os.getenv('PROXY_VM_SSH_PORT', 22))
PROXY_VM_SSH_USER = os.getenv('PROXY_VM_SSH_USER', 'root')
PROXY_VM_SSH_KEY_PATH = os.getenv('PROXY_VM_SSH_KEY_PATH', '')

# ============================================================================
# 데이터베이스 모델
# ============================================================================
class PortForwardingRule(Base):
    __tablename__ = "port_forwarding_rules"
    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(String, unique=True, index=True, default=lambda: str(uuid.uuid4()))
    rule_name = Column(String, index=True)
    user_vm_id = Column(String, index=True)
    user_vm_name = Column(String)
    user_vm_internal_ip = Column(String)
    user_vm_internal_port = Column(Integer)
    proxy_external_ip = Column(String, index=True)
    proxy_external_port = Column(Integer)
    protocol = Column(String, default="tcp")
    service_type = Column(String, default="other", index=True)
    status = Column(String, default="active")
    is_persistent = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = Column(String, nullable=True)
    description = Column(String, nullable=True)

Base.metadata.create_all(bind=engine)

# ============================================================================
# Pydantic 모델 (요청/응답)
# ============================================================================
class ProtocolEnum(str, Enum):
    TCP = "tcp"
    UDP = "udp"

class ServiceTypeEnum(str, Enum):
    SSH = "ssh"
    OTHER = "other"

class StatusEnum(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"
    PENDING = "pending"

class PortForwardingCreate(BaseModel):
    rule_name: str = Field(..., min_length=1, max_length=255)
    user_vm_id: str
    user_vm_name: str = Field(..., min_length=1, max_length=255)
    user_vm_internal_ip: str
    user_vm_internal_port: int = Field(..., ge=1, le=999)
    service_type: ServiceTypeEnum = Field(default=ServiceTypeEnum.OTHER)
    proxy_external_ip: Optional[str] = Field(None)
    proxy_external_port: Optional[int] = Field(None, ge=1, le=999)
    protocol: ProtocolEnum = Field(default=ProtocolEnum.TCP)
    description: Optional[str] = Field(None, max_length=500)

    @field_validator('user_vm_id')
    @classmethod
    def validate_uuid(cls, v: str) -> str:
        try:
            uuid.UUID(v)
            return v
        except ValueError:
            raise ValueError('유효한 UUID 형식이 아닙니다')

    @field_validator('user_vm_internal_ip')
    @classmethod
    def validate_ipv4(cls, v: str) -> str:
        try:
            IPv4Address(v)
            return v
        except AddressValueError:
            raise ValueError('유효한 IPv4 주소 형식이 아닙니다')

class PortForwardingUpdate(BaseModel):
    rule_name: Optional[str] = None
    user_vm_name: Optional[str] = None
    user_vm_internal_port: Optional[int] = Field(None, ge=1, le=999)
    proxy_external_port: Optional[int] = Field(None, ge=1, le=999)
    protocol: Optional[ProtocolEnum] = None
    status: Optional[StatusEnum] = None
    description: Optional[str] = None

class PortForwardingResponse(BaseModel):
    id: int
    rule_id: str
    rule_name: str
    user_vm_id: str
    user_vm_name: str
    user_vm_internal_ip: str
    user_vm_internal_port: int
    proxy_external_ip: str
    proxy_external_port: int
    protocol: str
    service_type: str
    status: str
    is_persistent: bool
    created_at: datetime
    updated_at: datetime
    created_by: Optional[str]
    description: Optional[str]

    model_config = ConfigDict(from_attributes=True)

    @field_validator('proxy_external_ip', mode='before')
    @classmethod
    def map_to_external_ip(cls, v: str) -> str:
        return FloatingIPConfig.get_external_ip(v)

class StatusResponse(BaseModel):
    total_rules: int
    active_rules: int
    inactive_rules: int
    pending_rules: int
    used_ports: int
    available_ports: int
    floating_ips: dict

class FloatingIPStatus(BaseModel):
    ip: str
    role: str
    active_rules: int
    max_rules: int
    usage_percent: float
    available_ports: int
    ports: List[int]
    
    @field_validator('ip', mode='before')
    @classmethod
    def map_to_external_ip(cls, v: str) -> str:
        return FloatingIPConfig.get_external_ip(v)

class PortAllocationResponse(BaseModel):
    floating_ip: str
    external_port: int
    role: str

    @field_validator('floating_ip', mode='before')
    @classmethod
    def map_to_external_ip(cls, v: str) -> str:
        return FloatingIPConfig.get_external_ip(v)

# ============================================================================
# FastAPI 애플리케이션
# ============================================================================
# lifespan은 아래 sync_iptables_from_db 등이 정의된 이후에 선언되므로,
# app 생성을 지연시킵니다 (파일 하단의 _create_app 패턴 대신 전방 선언 사용)
app = FastAPI(
    title="OpenStack Proxy VM Port Forwarding API",
    description="Skyline 통합 포트포워딩 규칙 관리 API - 인터페이스 무관 부하 분산 지원",
    version="1.4.0",
    docs_url="/api/v1/docs",
    redoc_url="/api/v1/redoc",
    openapi_url="/api/v1/openapi.json"
)

app.add_middleware(SecurityMiddleware)

if RATE_LIMITING_ENABLED:
    limiter = Limiter(key_func=get_remote_address, default_limits=[RATE_LIMIT_REQUESTS])
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

async def verify_token(authorization: Optional[str] = Header(None)) -> str:
    if not API_AUTH_ENABLED:
        if authorization:
            if authorization.startswith("Bearer "):
                return authorization.replace("Bearer ", "")
            return authorization
        return "anonymous"
    
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="유효하지 않은 토큰입니다")
    
    token = authorization.replace("Bearer ", "").strip()
    if not secrets.compare_digest(token, API_SECRET_KEY):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="유효하지 않은 API 키입니다")
    
    return token


def get_used_ports(db: Session, floating_ip: str) -> set:
    used_ports = db.query(PortForwardingRule.proxy_external_port).filter(
        PortForwardingRule.proxy_external_ip == floating_ip,
        PortForwardingRule.status.in_([StatusEnum.ACTIVE.value, StatusEnum.PENDING.value])
    ).all()
    return {port[0] for port in used_ports}

def select_floating_ip_for_ssh(db: Session) -> Tuple[Optional[str], Optional[int]]:
    ssh_ip = FloatingIPConfig.SSH_FLOATING_IP
    used_port_set = get_used_ports(db, ssh_ip)
    excluded_ports = FloatingIPConfig.SSH_EXCLUDED_PORTS
    port_range = FloatingIPConfig.SSH_PORT_RANGE
    
    available_ports = [
        p for p in range(port_range[0], port_range[1] + 1) 
        if p not in used_port_set and p not in excluded_ports
    ]
    if not available_ports:
        return None, None
    return ssh_ip, random.choice(available_ports)

def select_floating_ip_for_portfwd(db: Session) -> Tuple[Optional[str], Optional[int]]:
    best_ip = None
    best_port = None
    min_usage = float('inf')
    max_available = 0
    port_range = FloatingIPConfig.PORTFWD_PORT_RANGE
    excluded_ports = FloatingIPConfig.PORTFWD_EXCLUDED_PORTS
    all_ports = set(range(port_range[0], port_range[1] + 1)) - excluded_ports
    
    for ip in FloatingIPConfig.PORTFWD_FLOATING_IPS:
        used_port_set = get_used_ports(db, ip)
        available_ports = all_ports - used_port_set
        available_count = len(available_ports)
        usage_count = len(used_port_set)
        
        if available_count > max_available or (available_count == max_available and usage_count < min_usage):
            if available_ports:
                best_ip = ip
                best_port = random.choice(list(available_ports))
                min_usage = usage_count
                max_available = available_count
    return best_ip, best_port

def find_available_port(db: Session, floating_ip: str, service_type: str = "other") -> Optional[int]:
    used_port_set = get_used_ports(db, floating_ip)
    if service_type == ServiceTypeEnum.SSH.value:
        port_range = FloatingIPConfig.SSH_PORT_RANGE
        excluded_ports = FloatingIPConfig.SSH_EXCLUDED_PORTS
    else:
        port_range = FloatingIPConfig.PORTFWD_PORT_RANGE
        excluded_ports = FloatingIPConfig.PORTFWD_EXCLUDED_PORTS
        
    available_ports = [
        p for p in range(port_range[0], port_range[1] + 1)
        if p not in used_port_set and p not in excluded_ports
    ]
    if available_ports:
        return random.choice(available_ports)
    return None

def check_port_conflict(db: Session, floating_ip: str, external_port: int) -> bool:
    conflict = db.query(PortForwardingRule).filter(
        PortForwardingRule.proxy_external_ip == floating_ip,
        PortForwardingRule.proxy_external_port == external_port,
        PortForwardingRule.status.in_([StatusEnum.ACTIVE.value, StatusEnum.PENDING.value])
    ).first()
    return conflict is not None

def validate_ip_for_service_type(floating_ip: str, service_type: str) -> bool:
    if service_type == ServiceTypeEnum.SSH.value:
        return floating_ip == FloatingIPConfig.SSH_FLOATING_IP
    return floating_ip in FloatingIPConfig.PORTFWD_FLOATING_IPS

# ============================================================================
# iptables 관리 함수
# ============================================================================
PROXY_MODE = os.getenv('PROXY_MODE', 'local')

def _run_cmd(cmd: str, timeout: int = 30) -> subprocess.CompletedProcess:
    """local/remote 모드에 따라 명령어를 실행하는 공통 헬퍼"""
    if PROXY_MODE == 'local':
        return subprocess.run(
            f"sudo {cmd}", shell=True,
            capture_output=True, text=True, timeout=timeout
        )
    else:
        ssh_base = (
            f"ssh -o StrictHostKeyChecking=no "
            f"-p {PROXY_VM_SSH_PORT} {PROXY_VM_SSH_USER}@{PROXY_VM_IP}"
        )
        return subprocess.run(
            f"{ssh_base} 'sudo {cmd}'", shell=True,
            capture_output=True, text=True, timeout=timeout
        )


def check_iptables_rule_exists(
    floating_ip: str,
    external_port: int,
    internal_ip: str,
    internal_port: int,
    protocol: str = "tcp",
    chain: str = "PREROUTING"
) -> bool:
    if os.getenv('ENV') != 'production':
        return False
    
    try:
        if chain == "PREROUTING":
            check_cmd = f"sudo iptables -w -t nat -C PREROUTING -p {protocol} -d {floating_ip} --dport {external_port} -j DNAT --to-destination {internal_ip}:{internal_port}"
        else:  
            # 다중 인터페이스를 위해 특정 인터페이스 조건을 제거한 범용 MASQUERADE 확인
            check_cmd = f"sudo iptables -w -t nat -C POSTROUTING -j MASQUERADE"
        
        if PROXY_MODE == 'local':
            result = subprocess.run(check_cmd, shell=True, capture_output=True, text=True, timeout=10)
        else:
            ssh_base = f"ssh -o StrictHostKeyChecking=no -p {PROXY_VM_SSH_PORT} {PROXY_VM_SSH_USER}@{PROXY_VM_IP}"
            result = subprocess.run(f"{ssh_base} '{check_cmd}'", shell=True, capture_output=True, text=True, timeout=10)
        
        return result.returncode == 0
    except Exception as e:
        logger.warning(f"iptables 규칙 확인 중 오류 ({chain}): {str(e)}")
        return False

def get_interface_by_ip(ip: str) -> Optional[str]:
    """특정 IP가 할당된 네트워크 인터페이스 이름(예: ens5)을 자동으로 찾습니다."""
    if os.getenv('ENV') != 'production':
        return 'ens5'  # 개발 환경용 모의 반환
        
    try:
        # ip addr show 명령어로 해당 IP를 가진 인터페이스 검색
        cmd = f"ip -o addr show | grep ' {ip}/'"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.stdout:
            # 출력 예시: "4: ens5    inet 192.168.10.179/24 brd ..."
            parts = result.stdout.strip().split()
            if len(parts) >= 2:
                return parts[1]
    except Exception as e:
        logger.error(f"인터페이스 자동 탐색 실패 ({ip}): {str(e)}")
    
    return None

def apply_iptables_rule(
    floating_ip: str,
    external_port: int,
    internal_ip: str,
    internal_port: int,
    protocol: str = "tcp",
    add: bool = True
) -> Tuple[bool, str]:
    try:
        # 1. 입력값 검증
        floating_ip = sanitize_ip(floating_ip)
        internal_ip = sanitize_ip(internal_ip)
        external_port = sanitize_port(external_port)
        internal_port = sanitize_port(internal_port)
        protocol = sanitize_protocol(protocol)

        action = "-A" if add else "-D"
        action_text = "추가" if add else "삭제"

        # iptables 규칙 정의
        # [1] DNAT: 외부 포트 → 내부 VM으로 목적지 변환
        nat_rule = (
            f"iptables -t nat {action} PREROUTING "
            f"-p {protocol} -d {floating_ip} --dport {external_port} "
            f"-j DNAT --to-destination {internal_ip}:{internal_port}"
        )

        # [2] FORWARD: 변환된 패킷을 내부 VM으로 전달 허용 (핵심 - 없으면 DROP됨)
        forward_rule = (
            f"iptables -t filter {action} FORWARD "
            f"-p {protocol} -d {internal_ip} --dport {internal_port} -j ACCEPT"
        )

        # [3] FORWARD 역방향: 내부 VM → 외부 응답 패킷 허용
        forward_return_rule = (
            f"iptables -t filter {action} FORWARD "
            f"-p {protocol} -s {internal_ip} --sport {internal_port} -j ACCEPT"
        )

        # [4] MASQUERADE: 특정 인터페이스로 한정 (광범위 적용 방지)
        interface = get_interface_by_ip(floating_ip)
        if interface:
            masq_rule = (
                f"iptables -t nat -A POSTROUTING "
                f"-o {interface} -j MASQUERADE"
            )
            masq_check_cmd = (
                f"sudo iptables -w -t nat -C POSTROUTING "
                f"-o {interface} -j MASQUERADE"
            )
        else:
            # 인터페이스를 못 찾은 경우 fallback (광범위 규칙)
            logger.warning(f"IP {floating_ip}에 대한 인터페이스를 찾지 못해 범용 MASQUERADE 사용")
            masq_rule = "iptables -t nat -A POSTROUTING -j MASQUERADE"
            masq_check_cmd = "sudo iptables -w -t nat -C POSTROUTING -j MASQUERADE"

        # 추가 시 중복 확인
        if add and check_iptables_rule_exists(
            floating_ip, external_port, internal_ip, internal_port, protocol, "PREROUTING"
        ):
            logger.info(f"이미 존재하는 PREROUTING 규칙 - 스킵: {floating_ip}:{external_port} → {internal_ip}:{internal_port}")
            return True, "이미 존재하는 규칙 (스킵)"

        # ── 시뮬레이션 모드 ──────────────────────────────────────────
        if os.getenv('ENV') != 'production':
            logger.info(f"[SIM-{action_text}] NAT    : {nat_rule}")
            logger.info(f"[SIM-{action_text}] FORWARD: {forward_rule}")
            logger.info(f"[SIM-{action_text}] FORWARD: {forward_return_rule}")
            if add:
                logger.info(f"[SIM-추가] MASQ   : {masq_rule}")
            return True, "시뮬레이션 성공"

        # ── 통합 실행 (local/remote 공통) ────────────────────────────
        def _handle_result(result: subprocess.CompletedProcess, label: str, critical: bool = False) -> Optional[Tuple[bool, str]]:
            """명령 결과 공통 처리. critical=True이면 실패 시 즉시 반환값 생성."""
            if result.returncode != 0:
                if not add and "No chain/target/match" in result.stderr:
                    return None  # 삭제 시 규칙 없음 → 무시
                if critical:
                    return False, f"{label} 적용 실패: {result.stderr}"
                logger.warning(f"{label} 적용 실패 (무시하고 계속): {result.stderr}")
            return None

        # [1] DNAT 규칙
        result = _run_cmd(nat_rule)
        err = _handle_result(result, "PREROUTING", critical=True)
        if err:
            return err

        # [2] FORWARD 허용 규칙
        result = _run_cmd(forward_rule)
        _handle_result(result, "FORWARD 규칙")

        # [3] FORWARD 역방향 허용 규칙
        result = _run_cmd(forward_return_rule)
        _handle_result(result, "FORWARD 역방향 규칙")

        # [4] MASQUERADE (추가 시, 중복 방지)
        if add:
            masq_check = _run_cmd(masq_check_cmd.replace('sudo ', ''), timeout=10)
            if masq_check.returncode != 0:
                result = _run_cmd(masq_rule)
                if result.returncode != 0:
                    logger.warning(f"MASQUERADE 규칙 적용 실패: {result.stderr}")

        # [5] 다중 NIC 라우팅 고정
        if add:
            if PROXY_MODE == 'local' and interface:
                route_result = _run_cmd(
                    f"ip route replace {internal_ip} dev {interface} src {floating_ip}",
                    timeout=10
                )
                if route_result.returncode == 0:
                    logger.info(f"다중 NIC 라우팅 추가 성공: {internal_ip} → {interface} (src {floating_ip})")
                else:
                    logger.warning(f"다중 NIC 라우팅 추가 실패: {route_result.stderr}")
            elif PROXY_MODE != 'local':
                ssh_base = (
                    f"ssh -o StrictHostKeyChecking=no "
                    f"-p {PROXY_VM_SSH_PORT} {PROXY_VM_SSH_USER}@{PROXY_VM_IP}"
                )
                route_script = (
                    f"IFACE=$(ip -o addr show | grep ' {floating_ip}/' | awk '{{print $2}}'); "
                    f"if [ ! -z \"$IFACE\" ]; then "
                    f"sudo ip route replace {internal_ip} dev $IFACE src {floating_ip}; "
                    f"echo \"ROUTE_OK:$IFACE\"; "
                    f"else echo \"IFACE_NOT_FOUND\"; fi"
                )
                route_result = subprocess.run(
                    f"{ssh_base} '{route_script}'", shell=True,
                    capture_output=True, text=True, timeout=30
                )
                if "ROUTE_OK" in route_result.stdout:
                    logger.info(f"원격 다중 NIC 라우팅 추가 성공: {route_result.stdout.strip()}")
                else:
                    logger.warning(f"원격 다중 NIC 라우팅 추가 실패: {route_result.stdout} / {route_result.stderr}")

        return True, "성공"

    except subprocess.TimeoutExpired:
        return False, "타임아웃"
    except ValueError as e:
        return False, f"입력값 오류: {str(e)}"
    except Exception as e:
        logger.error(f"apply_iptables_rule 예외 발생: {str(e)}", exc_info=True)
        return False, str(e)

def save_iptables_persistent() -> bool:
    if os.getenv('ENV') != 'production':
        return True
    try:
        result = _run_cmd("sh -c 'iptables-save > /etc/iptables/rules.v4'")
        return result.returncode == 0
    except Exception:
        return False

def sync_iptables_from_db(db: Session) -> int:
    if os.getenv('ENV') != 'production':
        return 0
    active_rules = db.query(PortForwardingRule).filter(
        PortForwardingRule.status == StatusEnum.ACTIVE.value,
        PortForwardingRule.is_persistent == True
    ).all()
    synced_count = 0
    for rule in active_rules:
        success, _ = apply_iptables_rule(
            rule.proxy_external_ip, rule.proxy_external_port,
            rule.user_vm_internal_ip, rule.user_vm_internal_port,
            rule.protocol, add=True
        )
        if success: synced_count += 1
    if synced_count > 0: save_iptables_persistent()
    return synced_count

@asynccontextmanager
async def lifespan(app: FastAPI):
    """서버 시작 시 커널 튜닝 및 iptables 동기화"""
    logger.info("포트포워딩 API 서버 시작")
    
    # 커널 네트워크 파라미터 자동 설정 (재부팅 대비)
    if os.getenv('ENV') == 'production' and PROXY_MODE == 'local':
        try:
            subprocess.run("sudo sysctl -w net.ipv4.ip_forward=1", shell=True, check=True)
            subprocess.run('for i in /proc/sys/net/ipv4/conf/*/rp_filter; do sudo sh -c "echo 2 > $i"; done', shell=True, check=True)
            logger.info("커널 라우팅 및 보안 필터 자동 튜닝 완료 (ip_forward=1, rp_filter=2)")
        except Exception as e:
            logger.error(f"커널 파라미터 튜닝 중 오류 발생: {e}")

    db = SessionLocal()
    try:
        sync_iptables_from_db(db)
        active_rules = [
            (row.user_vm_internal_ip, row.proxy_external_ip)
            for row in db.query(PortForwardingRule)
                .filter(PortForwardingRule.status == StatusEnum.ACTIVE.value).all()
        ]
        added, removed = sync_routes_from_db(active_rules)
        logger.info(f"netplan 동기화 완료: +{added} / -{removed}")
    finally:
        db.close()
    
    yield  # 서버 실행
    logger.info("포트포워딩 API 서버 종료")

app.router.lifespan_context = lifespan

# API 엔드포인트 라우팅 (생략 없이 모두 유지)
@app.get("/api/v1/health", tags=["Health"])
async def health_check():
    return {"status": "healthy", "version": "1.4.0"}

@app.post("/api/v1/portforward", response_model=PortForwardingResponse, status_code=status.HTTP_201_CREATED, tags=["Port Forwarding"])
async def create_port_forwarding(request: PortForwardingCreate, db: Session = Depends(get_db), token: str = Depends(verify_token)):
    assigned_ip, assigned_port = None, None
    if request.proxy_external_ip:
        request_ip = FloatingIPConfig.get_internal_ip(request.proxy_external_ip)
        assigned_ip = request_ip
        if request.proxy_external_port:
            if check_port_conflict(db, assigned_ip, request.proxy_external_port):
                raise HTTPException(status_code=409, detail="포트 충돌")
            assigned_port = request.proxy_external_port
        else:
            assigned_port = find_available_port(db, assigned_ip, request.service_type.value)
    else:
        if request.service_type == ServiceTypeEnum.SSH: assigned_ip, assigned_port = select_floating_ip_for_ssh(db)
        else: assigned_ip, assigned_port = select_floating_ip_for_portfwd(db)
    
    if not assigned_ip or not assigned_port:
        raise HTTPException(status_code=503, detail="사용 가능한 IP/포트 없음")
    
    success, message = apply_iptables_rule(assigned_ip, assigned_port, request.user_vm_internal_ip, request.user_vm_internal_port, request.protocol.value, add=True)
    if not success and os.getenv('ENV') == 'production':
        raise HTTPException(status_code=500, detail=f"적용 실패: {message}")
        
    db_rule = PortForwardingRule(
        rule_name=request.rule_name, user_vm_id=request.user_vm_id, user_vm_name=request.user_vm_name,
        user_vm_internal_ip=request.user_vm_internal_ip, user_vm_internal_port=request.user_vm_internal_port,
        proxy_external_ip=assigned_ip, proxy_external_port=assigned_port, protocol=request.protocol.value,
        service_type=request.service_type.value, status=StatusEnum.ACTIVE.value if success else StatusEnum.PENDING.value,
        is_persistent=True, created_by=token, description=request.description
    )
    db.add(db_rule)
    db.commit()
    db.refresh(db_rule)
    save_iptables_persistent()

    iface = get_interface_by_ip(assigned_ip)
    add_vm_route(request.user_vm_internal_ip, primary_iface=iface)
    return db_rule

@app.get("/api/v1/portforward", response_model=List[PortForwardingResponse], tags=["Port Forwarding"])
async def list_port_forwardings(status_filter: Optional[str] = None, floating_ip: Optional[str] = None, service_type: Optional[str] = None, vm_id: Optional[str] = None, db: Session = Depends(get_db), token: str = Depends(verify_token)):
    query = db.query(PortForwardingRule)
    if status_filter: query = query.filter(PortForwardingRule.status == status_filter)
    if floating_ip: query = query.filter(PortForwardingRule.proxy_external_ip == FloatingIPConfig.get_internal_ip(floating_ip))
    if service_type: query = query.filter(PortForwardingRule.service_type == service_type)
    if vm_id: query = query.filter(PortForwardingRule.user_vm_id == vm_id)
    return query.order_by(PortForwardingRule.created_at.desc()).all()

@app.get("/api/v1/portforward/vm/{vm_id}", response_model=List[PortForwardingResponse], tags=["Port Forwarding"])
async def get_port_forwardings_by_vm(vm_id: str, db: Session = Depends(get_db), token: str = Depends(verify_token)):
    return db.query(PortForwardingRule).filter(PortForwardingRule.user_vm_id == vm_id).order_by(PortForwardingRule.created_at.desc()).all()

@app.get("/api/v1/portforward/{rule_id}", response_model=PortForwardingResponse, tags=["Port Forwarding"])
async def get_port_forwarding(rule_id: str, db: Session = Depends(get_db), token: str = Depends(verify_token)):
    rule = db.query(PortForwardingRule).filter(PortForwardingRule.rule_id == rule_id).first()
    if not rule: raise HTTPException(status_code=404, detail="규칙 없음")
    return rule

@app.patch("/api/v1/portforward/{rule_id}", response_model=PortForwardingResponse, tags=["Port Forwarding"])
async def update_port_forwarding(rule_id: str, request: PortForwardingUpdate, db: Session = Depends(get_db), token: str = Depends(verify_token)):
    rule = db.query(PortForwardingRule).filter(PortForwardingRule.rule_id == rule_id).first()
    if not rule: raise HTTPException(status_code=404, detail="규칙 없음")
    if request.status:
        if rule.status == StatusEnum.ACTIVE.value and request.status.value == StatusEnum.INACTIVE.value:
            apply_iptables_rule(rule.proxy_external_ip, rule.proxy_external_port, rule.user_vm_internal_ip, rule.user_vm_internal_port, rule.protocol, add=False)
        elif rule.status == StatusEnum.INACTIVE.value and request.status.value == StatusEnum.ACTIVE.value:
            apply_iptables_rule(rule.proxy_external_ip, rule.proxy_external_port, rule.user_vm_internal_ip, rule.user_vm_internal_port, rule.protocol, add=True)
        save_iptables_persistent()
    if request.rule_name: rule.rule_name = request.rule_name
    if request.user_vm_name: rule.user_vm_name = request.user_vm_name
    if request.user_vm_internal_port: rule.user_vm_internal_port = request.user_vm_internal_port
    if request.protocol: rule.protocol = request.protocol.value
    if request.status: rule.status = request.status.value
    if request.description is not None: rule.description = request.description
    rule.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(rule)
    return rule

@app.delete("/api/v1/portforward/{rule_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["Port Forwarding"])
async def delete_port_forwarding(rule_id: str, db: Session = Depends(get_db), token: str = Depends(verify_token)):
    rule = db.query(PortForwardingRule).filter(PortForwardingRule.rule_id == rule_id).first()
    if not rule: raise HTTPException(status_code=404, detail="규칙 없음")

    deleted_vm_ip = rule.user_vm_internal_ip

    apply_iptables_rule(rule.proxy_external_ip, rule.proxy_external_port, rule.user_vm_internal_ip, rule.user_vm_internal_port, rule.protocol, add=False)
    save_iptables_persistent()
    db.delete(rule)
    db.commit()

    remaining_ips = {
        row[0] for row in
        db.query(PortForwardingRule.user_vm_internal_ip)
          .filter(PortForwardingRule.status == StatusEnum.ACTIVE.value)
          .all()
    }
    remove_vm_route(deleted_vm_ip, remaining_ips)
    return None

@app.get("/api/v1/status", response_model=StatusResponse, tags=["Status"])
async def get_status(db: Session = Depends(get_db), token: str = Depends(verify_token)):
    total = db.query(PortForwardingRule).count()
    active = db.query(PortForwardingRule).filter(PortForwardingRule.status == StatusEnum.ACTIVE.value).count()
    inactive = db.query(PortForwardingRule).filter(PortForwardingRule.status == StatusEnum.INACTIVE.value).count()
    pending = db.query(PortForwardingRule).filter(PortForwardingRule.status == StatusEnum.PENDING.value).count()
    used_ports = db.query(PortForwardingRule.proxy_external_port).filter(PortForwardingRule.status.in_([StatusEnum.ACTIVE.value, StatusEnum.PENDING.value])).distinct().count()
    
    ssh_range = FloatingIPConfig.SSH_PORT_RANGE[1] - FloatingIPConfig.SSH_PORT_RANGE[0] + 1
    portfwd_range = (FloatingIPConfig.PORTFWD_PORT_RANGE[1] - FloatingIPConfig.PORTFWD_PORT_RANGE[0] + 1) * len(FloatingIPConfig.PORTFWD_FLOATING_IPS)
    available_ports = (ssh_range + portfwd_range) - used_ports
    
    floating_ip_status = {}
    ssh_ip = FloatingIPConfig.SSH_FLOATING_IP
    ssh_rules = db.query(PortForwardingRule).filter(PortForwardingRule.proxy_external_ip == ssh_ip).all()
    ssh_active = [r for r in ssh_rules if r.status == StatusEnum.ACTIVE.value]
    
    floating_ip_status[FloatingIPConfig.get_external_ip(ssh_ip)] = {
        "role": "ssh", "active_rules": len(ssh_active), "total_rules": len(ssh_rules),
        "max_rules": FloatingIPConfig.MAX_RULES_PER_IP, "usage_percent": (len(ssh_active) / FloatingIPConfig.MAX_RULES_PER_IP) * 100 if FloatingIPConfig.MAX_RULES_PER_IP > 0 else 0,
        "port_range": list(FloatingIPConfig.SSH_PORT_RANGE), "ports": [r.proxy_external_port for r in ssh_active]
    }
    
    for ip in FloatingIPConfig.PORTFWD_FLOATING_IPS:
        rules = db.query(PortForwardingRule).filter(PortForwardingRule.proxy_external_ip == ip).all()
        active_rules = [r for r in rules if r.status == StatusEnum.ACTIVE.value]
        floating_ip_status[FloatingIPConfig.get_external_ip(ip)] = {
            "role": "portfwd", "active_rules": len(active_rules), "total_rules": len(rules),
            "max_rules": FloatingIPConfig.MAX_RULES_PER_IP, "usage_percent": (len(active_rules) / FloatingIPConfig.MAX_RULES_PER_IP) * 100 if FloatingIPConfig.MAX_RULES_PER_IP > 0 else 0,
            "port_range": list(FloatingIPConfig.PORTFWD_PORT_RANGE), "ports": [r.proxy_external_port for r in active_rules]
        }
    
    return StatusResponse(total_rules=total, active_rules=active, inactive_rules=inactive, pending_rules=pending, used_ports=used_ports, available_ports=available_ports, floating_ips=floating_ip_status)

@app.get("/api/v1/floating-ips", response_model=List[FloatingIPStatus], tags=["Status"])
async def get_floating_ip_status(db: Session = Depends(get_db), token: str = Depends(verify_token)):
    result = []
    ssh_ip = FloatingIPConfig.SSH_FLOATING_IP
    ssh_used = get_used_ports(db, ssh_ip)
    ssh_range = FloatingIPConfig.SSH_PORT_RANGE
    
    result.append(FloatingIPStatus(
        ip=ssh_ip, role="ssh", active_rules=len(ssh_used), max_rules=FloatingIPConfig.MAX_RULES_PER_IP,
        usage_percent=(len(ssh_used) / FloatingIPConfig.MAX_RULES_PER_IP) * 100 if FloatingIPConfig.MAX_RULES_PER_IP > 0 else 0,
        available_ports=(ssh_range[1] - ssh_range[0] + 1) - len(ssh_used), ports=sorted(list(ssh_used))
    ))
    
    for ip in FloatingIPConfig.PORTFWD_FLOATING_IPS:
        used = get_used_ports(db, ip)
        port_range = FloatingIPConfig.PORTFWD_PORT_RANGE
        result.append(FloatingIPStatus(
            ip=ip, role="portfwd", active_rules=len(used), max_rules=FloatingIPConfig.MAX_RULES_PER_IP,
            usage_percent=(len(used) / FloatingIPConfig.MAX_RULES_PER_IP) * 100 if FloatingIPConfig.MAX_RULES_PER_IP > 0 else 0,
            available_ports=(port_range[1] - port_range[0] + 1) - len(used), ports=sorted(list(used))
        ))
    return result

@app.get("/api/v1/port-allocation/preview", response_model=PortAllocationResponse, tags=["Status"])
async def preview_port_allocation(service_type: ServiceTypeEnum = ServiceTypeEnum.OTHER, db: Session = Depends(get_db), token: str = Depends(verify_token)):
    ip, port = select_floating_ip_for_ssh(db) if service_type == ServiceTypeEnum.SSH else select_floating_ip_for_portfwd(db)
    if not ip or not port: raise HTTPException(status_code=503, detail="사용 가능한 IP/포트 없음")
    return PortAllocationResponse(floating_ip=ip, external_port=port, role="ssh" if service_type == ServiceTypeEnum.SSH else "portfwd")

@app.get("/api/v1/security/banned-ips", tags=["Security"])
async def list_banned_ips(token: str = Depends(verify_token)):
    return {"banned_ips": sorted(_banned_ips), "count": len(_banned_ips)}

@app.delete("/api/v1/security/banned-ips/{ip}", status_code=status.HTTP_204_NO_CONTENT, tags=["Security"])
async def unban_ip_endpoint(ip: str, token: str = Depends(verify_token)):
    if ip not in _banned_ips:
        raise HTTPException(status_code=404, detail="밴된 IP 없음")
    _unban_ip(ip)
    _violation_times.pop(ip, None)
    return None

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=os.getenv('API_HOST', '0.0.0.0'), port=int(os.getenv('API_PORT', 8080)), log_level=os.getenv('LOG_LEVEL', 'info').lower())
