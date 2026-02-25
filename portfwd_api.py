# ============================================================================
# OpenStack Skyline Proxy VM 포트포워딩 관리 API
# FastAPI 기반 프로덕션급 REST API
# ============================================================================

import os
from dotenv import load_dotenv

# .env 파일 로드
load_dotenv()

import subprocess
import json
import uuid
import re
import shlex
import hashlib
import secrets
from datetime import datetime
from typing import Optional, List, Tuple
from enum import Enum
from ipaddress import IPv4Address, AddressValueError

from fastapi import FastAPI, HTTPException, status, Header, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator
from sqlalchemy import create_engine, Column, String, Integer, DateTime, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
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
# 입력값 검증 함수 (명령 인젝션 방지)
# ============================================================================
def sanitize_ip(ip: str) -> str:
    """
    IP 주소 검증 및 정제
    - IPv4 형식만 허용
    - 특수문자, 쉘 메타문자 차단
    """
    if not ip:
        raise ValueError("IP 주소가 비어있습니다")
    
    # 허용 문자: 숫자와 점만
    if not re.match(r'^[0-9.]+$', ip):
        raise ValueError(f"유효하지 않은 IP 주소 형식: {ip}")
    
    # IPv4 형식 검증
    try:
        validated = IPv4Address(ip)
        return str(validated)
    except AddressValueError:
        raise ValueError(f"유효하지 않은 IPv4 주소: {ip}")


def sanitize_port(port: int) -> int:
    """
    포트 번호 검증
    - 1-65535 범위만 허용
    - 정수형만 허용
    """
    if not isinstance(port, int):
        raise ValueError(f"포트는 정수여야 합니다: {port}")
    
    if port < 1 or port > 65535:
        raise ValueError(f"포트 범위 초과 (1-65535): {port}")
    
    return port


def sanitize_protocol(protocol: str) -> str:
    """프로토콜 검증 - tcp/udp만 허용"""
    protocol = protocol.lower().strip()
    if protocol not in ('tcp', 'udp'):
        raise ValueError(f"유효하지 않은 프로토콜: {protocol}")
    return protocol


def validate_rule_name(name: str) -> str:
    """
    규칙 이름 검증
    - 영문, 숫자, 한글, 하이픈, 언더스코어만 허용
    - 최대 255자
    """
    if not name or len(name) > 255:
        raise ValueError("규칙 이름은 1-255자여야 합니다")
    
    # 허용 패턴: 영문, 숫자, 한글, 하이픈, 언더스코어, 공백
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
Base = declarative_base()

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
    """
    Floating IP 역할별 설정
    
    ⚠️ 중요: 여기에는 Proxy VM에서 iptables가 인식하는 IP를 입력합니다.
    - 외부 Floating IP가 아닌, 1:1 NAT으로 매핑된 Proxy VM의 내부 IP
    - 예: 외부 203.0.113.11 → 내부 10.0.0.11 이면, 10.0.0.11 사용
    - Proxy VM에서 'ip addr' 명령으로 확인 가능
    """
    # 1번 IP: SSH 전용 - 랜덤 포트 할당 (1:1 NAT 내부 IP)
    SSH_FLOATING_IP = os.getenv('SSH_FLOATING_IP', '10.0.0.11')
    SSH_FLOATING_IP_GET = os.getenv('SSH_FLOATING_IP_GET', SSH_FLOATING_IP)
    
    # 2번/3번 IP: 일반 포트포워딩용 - 두 IP 비교해서 여유있는 쪽 선택
    PORTFWD_FLOATING_IP_1 = os.getenv('PORTFWD_FLOATING_IP_1', '10.0.0.12')
    PORTFWD_FLOATING_IP_1_GET = os.getenv('PORTFWD_FLOATING_IP_1_GET', PORTFWD_FLOATING_IP_1)

    PORTFWD_FLOATING_IP_2 = os.getenv('PORTFWD_FLOATING_IP_2', '10.0.0.13')
    PORTFWD_FLOATING_IP_2_GET = os.getenv('PORTFWD_FLOATING_IP_2_GET', PORTFWD_FLOATING_IP_2)

    PORTFWD_FLOATING_IPS = [
        PORTFWD_FLOATING_IP_1,
        PORTFWD_FLOATING_IP_2
    ]
    
    # Internal(System) -> External(Display) Mapping
    IP_MAP = {
        SSH_FLOATING_IP: SSH_FLOATING_IP_GET,
        PORTFWD_FLOATING_IP_1: PORTFWD_FLOATING_IP_1_GET,
        PORTFWD_FLOATING_IP_2: PORTFWD_FLOATING_IP_2_GET
    }
    
    # External(Display) -> Internal(System) Mapping
    REVERSE_IP_MAP = {v: k for k, v in IP_MAP.items()}

    @classmethod
    def get_external_ip(cls, internal_ip: str) -> str:
        """내부 IP를 외부 표시용 IP로 변환"""
        return cls.IP_MAP.get(internal_ip, internal_ip)

    @classmethod
    def get_internal_ip(cls, external_ip: str) -> str:
        """외부 표시용 IP를 내부 시스템용 IP로 변환"""
        # 이미 내부 IP인 경우 그대로 반환 (사용자가 내부 IP 사용 시도 시)
        if external_ip in cls.IP_MAP:
            return external_ip
        return cls.REVERSE_IP_MAP.get(external_ip, external_ip)
    
    # 전체 IP 목록 (시스템용 Internal IP 기준)
    ALL_FLOATING_IPS = [SSH_FLOATING_IP] + PORTFWD_FLOATING_IPS
    
    # 포트 범위 설정
    SSH_PORT_RANGE = (
        int(os.getenv('SSH_PORT_MIN', 10000)),
        int(os.getenv('SSH_PORT_MAX', 30000))
    )
    PORTFWD_PORT_RANGE = (
        int(os.getenv('PORTFWD_PORT_MIN', 10000)),
        int(os.getenv('PORTFWD_PORT_MAX', 20000))
    )
    
    # 제외 포트 설정 (쉼표로 구분된 포트 번호)
    @staticmethod
    def _parse_excluded_ports(env_var: str) -> set:
        """환경변수에서 제외 포트 목록 파싱"""
        ports_str = os.getenv(env_var, '')
        if not ports_str.strip():
            return set()
        try:
            return {int(p.strip()) for p in ports_str.split(',') if p.strip()}
        except ValueError:
            return set()
    
    SSH_EXCLUDED_PORTS = _parse_excluded_ports.__func__('SSH_EXCLUDED_PORTS')
    PORTFWD_EXCLUDED_PORTS = _parse_excluded_ports.__func__('PORTFWD_EXCLUDED_PORTS')
    
    # IP당 최대 규칙 수
    MAX_RULES_PER_IP = int(os.getenv('MAX_RULES_PER_IP', 100))


# 기존 설정과의 호환성 유지
FLOATING_IPS = FloatingIPConfig.ALL_FLOATING_IPS
PROXY_EXTERNAL_PORT_RANGE = FloatingIPConfig.PORTFWD_PORT_RANGE
MAX_RULES_PER_IP = FloatingIPConfig.MAX_RULES_PER_IP
PROXY_VM_IP = os.getenv('PROXY_VM_IP', '172.24.4.10')
PROXY_VM_SSH_PORT = int(os.getenv('PROXY_VM_SSH_PORT', 22))
PROXY_VM_SSH_USER = os.getenv('PROXY_VM_SSH_USER', 'root')
PROXY_VM_SSH_KEY_PATH = os.getenv('PROXY_VM_SSH_KEY_PATH', '')

def _validate_ssh_config() -> None:
    """SSH 연결 환경변수 검증 (명령 인젝션 방지)"""
    if PROXY_VM_IP:
        try:
            IPv4Address(PROXY_VM_IP)
        except AddressValueError:
            # 호스트명: 영문자, 숫자, 하이픈, 점만 허용
            if not re.match(r'^[a-zA-Z0-9.\-]+$', PROXY_VM_IP):
                raise ValueError(f"유효하지 않은 PROXY_VM_IP: {PROXY_VM_IP!r}")

    if PROXY_VM_SSH_USER:
        if not re.match(r'^[a-zA-Z0-9_\-\.]+$', PROXY_VM_SSH_USER):
            raise ValueError(f"유효하지 않은 PROXY_VM_SSH_USER: {PROXY_VM_SSH_USER!r}")

    if PROXY_VM_SSH_KEY_PATH:
        # 쉘 메타문자 및 경로 조작 방지
        if not re.match(r'^[a-zA-Z0-9_\-\./~]+$', PROXY_VM_SSH_KEY_PATH):
            raise ValueError(f"유효하지 않은 PROXY_VM_SSH_KEY_PATH: {PROXY_VM_SSH_KEY_PATH!r}")

_validate_ssh_config()


def _build_ssh_base_args() -> list:
    """SSH 기본 명령 인수 목록 반환 (shell=False 전용)"""
    args = [
        "ssh",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "BatchMode=yes",
        "-p", str(PROXY_VM_SSH_PORT),
    ]
    if PROXY_VM_SSH_KEY_PATH:
        args.extend(["-i", PROXY_VM_SSH_KEY_PATH])
    args.append(f"{PROXY_VM_SSH_USER}@{PROXY_VM_IP}")
    return args

# ============================================================================
# 데이터베이스 모델
# ============================================================================
class PortForwardingRule(Base):
    """포트포워딩 규칙 데이터베이스 모델"""
    __tablename__ = "port_forwarding_rules"

    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(String, unique=True, index=True, default=lambda: str(uuid.uuid4()))
    rule_name = Column(String, index=True)
    
    # 사용자 VM 정보
    user_vm_id = Column(String, index=True)  # OpenStack Instance ID
    user_vm_name = Column(String)
    user_vm_internal_ip = Column(String)
    user_vm_internal_port = Column(Integer)
    
    # Proxy VM (외부) 정보
    proxy_external_ip = Column(String, index=True)
    proxy_external_port = Column(Integer)
    
    # 프로토콜 및 서비스 유형
    protocol = Column(String, default="tcp")
    service_type = Column(String, default="other", index=True)  # ssh 또는 other
    
    # 상태
    status = Column(String, default="active")  # active, inactive, error, pending
    is_persistent = Column(Boolean, default=True)  # 재시작 시 복구 여부
    
    # 메타데이터
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
    SSH = "ssh"      # SSH 전용 → 1번 IP 사용
    OTHER = "other"  # 일반 포트포워딩 → 2번/3번 IP 비교 후 선택

class StatusEnum(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"
    PENDING = "pending"

class PortForwardingCreate(BaseModel):
    """포트포워딩 규칙 생성 요청"""
    rule_name: str = Field(..., min_length=1, max_length=255, description="규칙 이름")
    user_vm_id: str = Field(..., description="OpenStack Instance UUID")
    user_vm_name: str = Field(..., min_length=1, max_length=255, description="사용자 VM 이름")
    user_vm_internal_ip: str = Field(..., description="내부 VM IP 주소 (10.0.0.0/24)")
    user_vm_internal_port: int = Field(..., ge=1, le=65535, description="내부 포트 (1-65535)")
    service_type: ServiceTypeEnum = Field(
        default=ServiceTypeEnum.OTHER, 
        description="서비스 유형: ssh(1번 IP) 또는 other(2번/3번 IP 비교 선택)"
    )
    proxy_external_ip: Optional[str] = Field(None, description="Floating IP (선택사항, 자동 선택, External/Internal 모두 가능)")
    proxy_external_port: Optional[int] = Field(None, ge=1, le=65535, description="외부 포트 (선택, 자동 할당)")
    protocol: ProtocolEnum = Field(default=ProtocolEnum.TCP, description="TCP 또는 UDP")
    description: Optional[str] = Field(None, max_length=500, description="규칙 설명")

    @validator('user_vm_id')
    def validate_uuid(cls, v):
        try:
            uuid.UUID(v)
            return v
        except ValueError:
            raise ValueError('유효한 UUID 형식이 아닙니다')

    @validator('user_vm_internal_ip')
    def validate_ipv4(cls, v):
        try:
            IPv4Address(v)
            return v
        except AddressValueError:
            raise ValueError('유효한 IPv4 주소 형식이 아닙니다')

class PortForwardingUpdate(BaseModel):
    """포트포워딩 규칙 업데이트 요청"""
    rule_name: Optional[str] = None
    user_vm_name: Optional[str] = None
    user_vm_internal_port: Optional[int] = Field(None, ge=1, le=65535)
    proxy_external_port: Optional[int] = Field(None, ge=1, le=65535)
    protocol: Optional[ProtocolEnum] = None
    status: Optional[StatusEnum] = None
    description: Optional[str] = None

class PortForwardingResponse(BaseModel):
    """포트포워딩 규칙 응답"""
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

    class Config:
        from_attributes = True

    @validator('proxy_external_ip', pre=True)
    def map_to_external_ip(cls, v):
        """Internal IP를 External IP로 변환하여 응답"""
        return FloatingIPConfig.get_external_ip(v)

class StatusResponse(BaseModel):
    """상태 응답"""
    total_rules: int
    active_rules: int
    inactive_rules: int
    pending_rules: int
    used_ports: int
    available_ports: int
    floating_ips: dict

class FloatingIPStatus(BaseModel):
    """Floating IP 상태"""
    ip: str
    role: str  # ssh 또는 portfwd
    active_rules: int
    max_rules: int
    usage_percent: float
    available_ports: int
    ports: List[int]
    
    @validator('ip', pre=True)
    def map_to_external_ip(cls, v):
        """Internal IP를 External IP로 변환하여 응답"""
        return FloatingIPConfig.get_external_ip(v)

class PortAllocationResponse(BaseModel):
    """포트 할당 결과"""
    floating_ip: str
    external_port: int
    role: str

    @validator('floating_ip', pre=True)
    def map_to_external_ip(cls, v):
        """Internal IP를 External IP로 변환하여 응답"""
        return FloatingIPConfig.get_external_ip(v)

# ============================================================================
# FastAPI 애플리케이션
# ============================================================================
app = FastAPI(
    title="OpenStack Proxy VM Port Forwarding API",
    description="Skyline 통합 포트포워딩 규칙 관리 API - SSH 전용 IP 분리 및 부하 분산 지원",
    version="1.2.0",
    docs_url=None,        # 자동 문서 비활성화 (보안)
    redoc_url=None,       # ReDoc 비활성화
    openapi_url=None      # OpenAPI 스키마 비활성화
)

# Rate Limiting 설정
if RATE_LIMITING_ENABLED:
    limiter = Limiter(key_func=get_remote_address, default_limits=[RATE_LIMIT_REQUESTS])
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    logger.info(f"Rate Limiting 활성화: {RATE_LIMIT_REQUESTS}")

# ============================================================================
# 인증 (Bearer Token / API Key)
# ============================================================================
async def verify_token(authorization: Optional[str] = Header(None)) -> str:
    """
    API 토큰 검증
    
    - API_SECRET_KEY가 설정된 경우: Bearer 토큰 필수
    - API_SECRET_KEY가 없는 경우: anonymous 허용 (개발 환경)
    
    사용 예시:
        curl -H "Authorization: Bearer YOUR_API_KEY" http://localhost:8080/api/v1/...
    """
    # API 인증이 비활성화된 경우 (개발 환경)
    if not API_AUTH_ENABLED:
        if authorization:
            # 토큰이 제공되면 그대로 사용 (ID 용도)
            if authorization.startswith("Bearer "):
                return authorization.replace("Bearer ", "")
            return authorization
        return "anonymous"
    
    # API 인증이 활성화된 경우 (프로덕션)
    if authorization is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization 헤더가 필요합니다. 형식: 'Bearer YOUR_API_KEY'",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="유효하지 않은 토큰 형식입니다. 형식: 'Bearer YOUR_API_KEY'",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    token = authorization.replace("Bearer ", "").strip()
    
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API 키가 비어있습니다",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    # API Key 검증 (타이밍 공격 방지를 위한 상수 시간 비교)
    if not secrets.compare_digest(token, API_SECRET_KEY):
        logger.warning(f"API 인증 실패: 잘못된 키 시도")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="유효하지 않은 API 키입니다",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    logger.debug("API 인증 성공")
    return token

# ============================================================================
# 포트 관리 함수 (역할별 분리)
# ============================================================================
def get_used_ports(db: Session, floating_ip: str) -> set:
    """특정 Floating IP의 사용 중인 포트 조회"""
    used_ports = db.query(PortForwardingRule.proxy_external_port).filter(
        PortForwardingRule.proxy_external_ip == floating_ip,
        PortForwardingRule.status.in_([StatusEnum.ACTIVE.value, StatusEnum.PENDING.value])
    ).all()
    return {port[0] for port in used_ports}


def select_floating_ip_for_ssh(db: Session) -> Tuple[Optional[str], Optional[int]]:
    """
    SSH 전용 Floating IP (1번)에서 랜덤 포트 할당
    
    Returns:
        (floating_ip, available_port) 또는 (None, None)
    """
    ssh_ip = FloatingIPConfig.SSH_FLOATING_IP
    used_port_set = get_used_ports(db, ssh_ip)
    excluded_ports = FloatingIPConfig.SSH_EXCLUDED_PORTS
    
    port_range = FloatingIPConfig.SSH_PORT_RANGE
    available_ports = [
        p for p in range(port_range[0], port_range[1] + 1) 
        if p not in used_port_set and p not in excluded_ports
    ]
    
    if not available_ports:
        logger.warning(f"SSH IP {ssh_ip}에 사용 가능한 포트 없음 (제외: {len(excluded_ports)}개)")
        return None, None
    
    # 랜덤 포트 선택 (암호학적으로 안전한 랜덤 사용)
    selected_port = secrets.choice(available_ports)
    logger.info(f"SSH 포트 할당: {ssh_ip}:{selected_port} (랜덤, 제외 포트 {len(excluded_ports)}개)")
    
    return ssh_ip, selected_port


def select_floating_ip_for_portfwd(db: Session) -> Tuple[Optional[str], Optional[int]]:
    """
    2번/3번 IP를 비교하여 가장 여유 있는 IP와 포트 반환

    로직:
    - 두 IP의 사용량을 비교
    - 가장 적게 사용된 IP 선택
    - 해당 IP에서 랜덤 포트 할당 (예측 불가)

    Returns:
        (floating_ip, available_port) 또는 (None, None)
    """
    best_ip = None
    best_available_ports: list = []
    min_usage = float('inf')
    max_available = 0

    port_range = FloatingIPConfig.PORTFWD_PORT_RANGE
    excluded_ports = FloatingIPConfig.PORTFWD_EXCLUDED_PORTS

    for ip in FloatingIPConfig.PORTFWD_FLOATING_IPS:
        used_port_set = get_used_ports(db, ip)
        usage_count = len(used_port_set)
        available_ports = [
            p for p in range(port_range[0], port_range[1] + 1)
            if p not in used_port_set and p not in excluded_ports
        ]
        available_count = len(available_ports)

        logger.debug(f"IP {ip}: 사용중 {usage_count}, 여유 {available_count}")

        # 가장 여유있는 IP 선택 (사용량이 가장 적은 IP)
        if available_count > max_available or (available_count == max_available and usage_count < min_usage):
            best_ip = ip
            best_available_ports = available_ports
            min_usage = usage_count
            max_available = available_count

    if best_ip and best_available_ports:
        selected_port = secrets.choice(best_available_ports)
        logger.info(f"포트포워딩 할당: {best_ip}:{selected_port} (랜덤 선택, 사용량: {min_usage})")
        return best_ip, selected_port

    logger.warning("모든 포트포워딩 IP가 가득 참")
    return None, None


def find_available_port(db: Session, floating_ip: str, service_type: str = "other") -> Optional[int]:
    """
    특정 Floating IP에서 사용 가능한 포트를 랜덤으로 반환
    (사용자가 IP를 직접 지정한 경우)
    """
    used_port_set = get_used_ports(db, floating_ip)

    # 서비스 유형에 따른 포트 범위 및 제외 포트 결정
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

    if not available_ports:
        return None

    return secrets.choice(available_ports)


def check_port_conflict(db: Session, floating_ip: str, external_port: int) -> bool:
    """포트 충돌 검사"""
    conflict = db.query(PortForwardingRule).filter(
        PortForwardingRule.proxy_external_ip == floating_ip,
        PortForwardingRule.proxy_external_port == external_port,
        PortForwardingRule.status.in_([StatusEnum.ACTIVE.value, StatusEnum.PENDING.value])
    ).first()
    
    return conflict is not None


def validate_ip_for_service_type(floating_ip: str, service_type: str) -> bool:
    """IP가 서비스 유형에 적합한지 검증"""
    if service_type == ServiceTypeEnum.SSH.value:
        return floating_ip == FloatingIPConfig.SSH_FLOATING_IP
    else:
        return floating_ip in FloatingIPConfig.PORTFWD_FLOATING_IPS


# ============================================================================
# iptables 관리 함수
# ============================================================================
# 실행 모드: local(Proxy VM 내부) 또는 remote(SSH로 원격 전달)
PROXY_MODE = os.getenv('PROXY_MODE', 'local')


def check_iptables_rule_exists(
    floating_ip: str,
    external_port: int,
    internal_ip: str,
    internal_port: int,
    protocol: str = "tcp",
    chain: str = "PREROUTING"
) -> bool:
    """
    iptables에 해당 규칙이 이미 존재하는지 확인
    
    Args:
        chain: "PREROUTING" (DNAT) 또는 "POSTROUTING" (MASQUERADE)
    
    Returns:
        True: 규칙이 이미 존재함
        False: 규칙이 존재하지 않음
    """
    if os.getenv('ENV') != 'production':
        return False  # 개발 환경에서는 항상 새로 추가
    
    try:
        # 체인에 따라 다른 규칙 확인 (인수 목록으로 구성 - 명령 인젝션 방지)
        if chain == "PREROUTING":
            check_args = [
                "sudo", "iptables", "-t", "nat", "-C", "PREROUTING",
                "-p", protocol, "-d", floating_ip, "--dport", str(external_port),
                "-j", "DNAT", "--to-destination", f"{internal_ip}:{internal_port}"
            ]
        else:  # POSTROUTING
            check_args = [
                "sudo", "iptables", "-t", "nat", "-C", "POSTROUTING",
                "-p", protocol, "-d", internal_ip, "--dport", str(internal_port),
                "-j", "MASQUERADE"
            ]

        if PROXY_MODE == 'local':
            result = subprocess.run(check_args, capture_output=True, text=True, timeout=10)
        else:
            ssh_args = _build_ssh_base_args()
            ssh_args.append(shlex.join(check_args))
            result = subprocess.run(ssh_args, capture_output=True, text=True, timeout=10)

        # returncode 0 = 규칙 존재, 1 = 규칙 없음
        return result.returncode == 0
        
    except Exception as e:
        logger.warning(f"iptables 규칙 확인 중 오류 ({chain}): {str(e)}")
        return False


def apply_iptables_rule(
    floating_ip: str,
    external_port: int,
    internal_ip: str,
    internal_port: int,
    protocol: str = "tcp",
    add: bool = True
) -> Tuple[bool, str]:
    """
    iptables 규칙 적용
    
    PROXY_MODE에 따라:
    - local: Proxy VM 내부에서 직접 sudo iptables 실행
    - remote: SSH로 Proxy VM에 명령 전달
    - development: 시뮬레이션만 (로그 출력)
    
    보안:
    - 모든 입력값 검증 (명령 인젝션 방지)
    - 중복 규칙 자동 스킵 (DNAT + MASQUERADE 모두)
    """
    try:
        # ========== 입력값 검증 (명령 인젝션 방지) ==========
        try:
            floating_ip = sanitize_ip(floating_ip)
            internal_ip = sanitize_ip(internal_ip)
            external_port = sanitize_port(external_port)
            internal_port = sanitize_port(internal_port)
            protocol = sanitize_protocol(protocol)
        except ValueError as e:
            logger.error(f"iptables 입력값 검증 실패: {str(e)}")
            return False, f"입력값 검증 실패: {str(e)}"
        
        action = "-A" if add else "-D"
        action_text = "추가" if add else "삭제"

        # 추가 시 DNAT 중복 체크
        if add and check_iptables_rule_exists(floating_ip, external_port, internal_ip, internal_port, protocol, "PREROUTING"):
            logger.info(f"iptables DNAT 규칙 이미 존재 (스킵): {floating_ip}:{external_port} → {internal_ip}:{internal_port}")
            return True, "이미 존재하는 규칙 (스킵)"

        # 1. DNAT 규칙 인수 목록 (외부 → 내부 변환)
        nat_args = [
            "sudo", "iptables", "-t", "nat", action, "PREROUTING",
            "-p", protocol, "-d", floating_ip, "--dport", str(external_port),
            "-j", "DNAT", "--to-destination", f"{internal_ip}:{internal_port}"
        ]

        # 2. MASQUERADE 규칙 인수 목록 (응답 패킷 처리) - 중복 체크 포함
        masq_exists = check_iptables_rule_exists(floating_ip, external_port, internal_ip, internal_port, protocol, "POSTROUTING") if add else False
        masq_args = [
            "sudo", "iptables", "-t", "nat", action, "POSTROUTING",
            "-p", protocol, "-d", internal_ip, "--dport", str(internal_port),
            "-j", "MASQUERADE"
        ]

        if os.getenv('ENV') != 'production':
            # 개발 환경: 시뮬레이션
            logger.info(f"[SIM-{action_text}] {shlex.join(nat_args)}")
            if not masq_exists:
                logger.info(f"[SIM-{action_text}] {shlex.join(masq_args)}")
            else:
                logger.info("[SIM-스킵] MASQUERADE 이미 존재")
            return True, "시뮬레이션 성공"

        # 프로덕션 환경
        if PROXY_MODE == 'local':
            # 로컬 모드: Proxy VM 내부에서 직접 실행 (shell=False)
            result = subprocess.run(nat_args, capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                if add or "No chain/target/match" not in result.stderr:
                    logger.error(f"iptables DNAT 규칙 {action_text} 실패: {result.stderr}")
                    return False, result.stderr

            # MASQUERADE 규칙 적용 (중복이 아닌 경우만)
            if not masq_exists:
                result = subprocess.run(masq_args, capture_output=True, text=True, timeout=30)
                if result.returncode != 0:
                    if add or "No chain/target/match" not in result.stderr:
                        logger.error(f"iptables MASQUERADE 규칙 {action_text} 실패: {result.stderr}")
                        return False, result.stderr
            else:
                logger.info(f"MASQUERADE 규칙 이미 존재 (스킵): {internal_ip}:{internal_port}")

            logger.info(f"iptables 규칙 {action_text} 성공 [로컬]: {floating_ip}:{external_port} → {internal_ip}:{internal_port}")

        else:
            # 원격 모드: SSH로 Proxy VM에 명령 전달 (shell=False)
            ssh_base = _build_ssh_base_args()

            for cmd_args in [nat_args, masq_args]:
                ssh_args = ssh_base + [shlex.join(cmd_args)]
                result = subprocess.run(ssh_args, capture_output=True, text=True, timeout=30)

                if result.returncode != 0:
                    if add or "No chain/target/match" not in result.stderr:
                        logger.error(f"iptables 규칙 {action_text} 실패: {result.stderr}")
                        return False, result.stderr

            logger.info(f"iptables 규칙 {action_text} 성공 [원격]: {floating_ip}:{external_port} → {internal_ip}:{internal_port}")

        return True, "성공"
        
    except subprocess.TimeoutExpired:
        logger.error("iptables 규칙 적용 타임아웃 (30초)")
        return False, "타임아웃"
    except Exception as e:
        logger.error(f"iptables 규칙 적용 중 오류: {str(e)}")
        return False, str(e)


def save_iptables_persistent() -> bool:
    """iptables 규칙을 영구 저장 (재시작 후에도 유지)"""
    if os.getenv('ENV') != 'production':
        logger.info("[SIM] iptables 규칙 영구 저장")
        return True
    
    try:
        # 리다이렉션이 필요하므로 sh -c 사용 (단, 인수는 고정값이므로 안전)
        save_args = ["sudo", "sh", "-c", "iptables-save > /etc/iptables/rules.v4"]

        if PROXY_MODE == 'local':
            # 로컬 모드: 직접 실행 (shell=False)
            result = subprocess.run(save_args, capture_output=True, text=True, timeout=30)
        else:
            # 원격 모드: SSH로 실행 (shell=False)
            ssh_args = _build_ssh_base_args()
            ssh_args.append(shlex.join(save_args))
            result = subprocess.run(ssh_args, capture_output=True, text=True, timeout=30)
        
        if result.returncode != 0:
            logger.error(f"iptables 저장 실패: {result.stderr}")
            return False
        
        logger.info(f"iptables 규칙 영구 저장 완료 [{PROXY_MODE}]")
        return True
        
    except Exception as e:
        logger.error(f"iptables 저장 중 오류: {str(e)}")
        return False


def sync_iptables_from_db(db: Session) -> int:
    """DB의 활성 규칙을 기반으로 iptables 동기화 (서버 시작 시 호출)"""
    if os.getenv('ENV') != 'production':
        logger.info("[개발 환경] iptables 동기화 건너뜀")
        return 0
    
    active_rules = db.query(PortForwardingRule).filter(
        PortForwardingRule.status == StatusEnum.ACTIVE.value,
        PortForwardingRule.is_persistent == True
    ).all()
    
    synced_count = 0
    for rule in active_rules:
        success, _ = apply_iptables_rule(
            rule.proxy_external_ip,
            rule.proxy_external_port,
            rule.user_vm_internal_ip,
            rule.user_vm_internal_port,
            rule.protocol,
            add=True
        )
        if success:
            synced_count += 1
    
    if synced_count > 0:
        save_iptables_persistent()
    
    logger.info(f"iptables 동기화 완료: {synced_count}/{len(active_rules)} 규칙")
    return synced_count


# ============================================================================
# 시작/종료 이벤트
# ============================================================================
@app.on_event("startup")
async def startup_event():
    """서버 시작 시 iptables 동기화"""
    logger.info("포트포워딩 API 서버 시작")
    logger.info(f"SSH 전용 IP: {FloatingIPConfig.SSH_FLOATING_IP}")
    logger.info(f"포트포워딩 IP: {FloatingIPConfig.PORTFWD_FLOATING_IPS}")
    
    db = SessionLocal()
    try:
        sync_iptables_from_db(db)
    finally:
        db.close()


@app.on_event("shutdown")
async def shutdown_event():
    """서버 종료 시 처리"""
    logger.info("포트포워딩 API 서버 종료")


# ============================================================================
# API 엔드포인트
# ============================================================================

@app.get("/api/v1/health", tags=["Health"])
async def health_check(token: str = Depends(verify_token)):
    """헬스 체크 (인증 필요)"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.1.0",
    }


@app.post(
    "/api/v1/portforward",
    response_model=PortForwardingResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Port Forwarding"],
    summary="포트포워딩 규칙 생성",
    description="""
새로운 포트포워딩 규칙을 생성합니다.

**서비스 유형별 동작:**
- `ssh`: 1번 IP(SSH 전용)에서 랜덤 포트 할당
- `other`: 2번/3번 IP를 비교하여 여유있는 IP와 포트 자동 선택
"""
)
async def create_port_forwarding(
    request: PortForwardingCreate,
    db: Session = Depends(get_db),
    token: str = Depends(verify_token)
):
    try:
        assigned_ip = None
        assigned_port = None
        
        # 사용자가 IP를 직접 지정한 경우
        if request.proxy_external_ip:
            # External IP 입력 시 Internal IP로 변환
            request_ip = FloatingIPConfig.get_internal_ip(request.proxy_external_ip)
            
            # IP가 서비스 유형에 맞는지 검증 (경고만, 차단하지 않음)
            if not validate_ip_for_service_type(request_ip, request.service_type.value):
                logger.warning(
                    f"서비스 유형 {request.service_type.value}에 권장되지 않는 IP: {request.proxy_external_ip} (Internal: {request_ip})"
                )
            
            assigned_ip = request_ip
            
            if request.proxy_external_port:
                # 포트도 지정된 경우 충돌 검사 → 중복 시 자동 대체
                if check_port_conflict(db, assigned_ip, request.proxy_external_port):
                    logger.warning(
                        f"요청 포트 {assigned_ip}:{request.proxy_external_port}이 이미 사용 중 "
                        f"- 사용 가능한 포트로 자동 대체"
                    )
                    assigned_port = find_available_port(db, assigned_ip, request.service_type.value)
                    if assigned_port is None:
                        raise HTTPException(
                            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail="요청 포트가 사용 중이며 대체 가능한 포트도 없습니다"
                        )
                else:
                    assigned_port = request.proxy_external_port
            else:
                # 포트만 자동 할당
                assigned_port = find_available_port(db, assigned_ip, request.service_type.value)
        
        # 자동 선택 (서비스 유형에 따라)
        else:
            if request.service_type == ServiceTypeEnum.SSH:
                # SSH: 1번 IP에서 랜덤 포트
                assigned_ip, assigned_port = select_floating_ip_for_ssh(db)
            else:
                # 기타: 2번/3번 IP 비교 선택
                assigned_ip, assigned_port = select_floating_ip_for_portfwd(db)
        
        # 할당 실패 체크
        if not assigned_ip or not assigned_port:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="사용 가능한 Floating IP 또는 포트가 없습니다"
            )
        
        # iptables 규칙 적용
        success, message = apply_iptables_rule(
            assigned_ip,
            assigned_port,
            request.user_vm_internal_ip,
            request.user_vm_internal_port,
            request.protocol.value,
            add=True
        )
        
        if not success and os.getenv('ENV') == 'production':
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"iptables 규칙 적용 실패: {message}"
            )
        
        # 데이터베이스에 저장
        db_rule = PortForwardingRule(
            rule_name=request.rule_name,
            user_vm_id=request.user_vm_id,
            user_vm_name=request.user_vm_name,
            user_vm_internal_ip=request.user_vm_internal_ip,
            user_vm_internal_port=request.user_vm_internal_port,
            proxy_external_ip=assigned_ip,
            proxy_external_port=assigned_port,
            protocol=request.protocol.value,
            service_type=request.service_type.value,
            status=StatusEnum.ACTIVE.value if success else StatusEnum.PENDING.value,
            is_persistent=True,
            created_by=hashlib.sha256(token.encode()).hexdigest()[:16] if token != "anonymous" else "anonymous",
            description=request.description
        )
        
        db.add(db_rule)
        db.commit()
        db.refresh(db_rule)
        
        # iptables 영구 저장
        save_iptables_persistent()
        
        logger.info(
            f"포트포워딩 규칙 생성: {request.rule_name} "
            f"[{request.service_type.value}] "
            f"({assigned_ip}:{assigned_port} → "
            f"{request.user_vm_internal_ip}:{request.user_vm_internal_port})"
        )
        
        return db_rule
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"포트포워딩 생성 중 오류: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="내부 서버 오류가 발생했습니다"
        )


@app.get(
    "/api/v1/portforward",
    response_model=List[PortForwardingResponse],
    tags=["Port Forwarding"],
    summary="포트포워딩 규칙 목록",
    description="모든 포트포워딩 규칙을 조회합니다"
)
async def list_port_forwardings(
    status_filter: Optional[str] = None,
    floating_ip: Optional[str] = None,
    service_type: Optional[str] = None,
    vm_id: Optional[str] = None,
    db: Session = Depends(get_db),
    token: str = Depends(verify_token)
):
    """포트포워딩 규칙 목록 조회"""
    try:
        query = db.query(PortForwardingRule)
        
        if status_filter:
            query = query.filter(PortForwardingRule.status == status_filter)
        
        if floating_ip:
            # Internal IP로 변환하여 검색
            internal_ip = FloatingIPConfig.get_internal_ip(floating_ip)
            query = query.filter(PortForwardingRule.proxy_external_ip == internal_ip)
        
        if service_type:
            query = query.filter(PortForwardingRule.service_type == service_type)
        
        if vm_id:
            query = query.filter(PortForwardingRule.user_vm_id == vm_id)
        
        rules = query.order_by(PortForwardingRule.created_at.desc()).all()
        return rules
    
    except Exception as e:
        logger.error(f"규칙 목록 조회 중 오류: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="내부 서버 오류가 발생했습니다"
        )


@app.get(
    "/api/v1/portforward/vm/{vm_id}",
    response_model=List[PortForwardingResponse],
    tags=["Port Forwarding"],
    summary="VM별 포트포워딩 규칙 조회",
    description="특정 VM의 모든 포트포워딩 규칙을 조회합니다"
)
async def get_port_forwardings_by_vm(
    vm_id: str,
    db: Session = Depends(get_db),
    token: str = Depends(verify_token)
):
    """VM ID로 포트포워딩 규칙 조회"""
    try:
        rules = db.query(PortForwardingRule).filter(
            PortForwardingRule.user_vm_id == vm_id
        ).order_by(PortForwardingRule.created_at.desc()).all()
        
        return rules
    
    except Exception as e:
        logger.error(f"VM 규칙 조회 중 오류: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="내부 서버 오류가 발생했습니다"
        )


@app.get(
    "/api/v1/portforward/{rule_id}",
    response_model=PortForwardingResponse,
    tags=["Port Forwarding"],
    summary="포트포워딩 규칙 조회",
    description="특정 포트포워딩 규칙을 조회합니다"
)
async def get_port_forwarding(
    rule_id: str,
    db: Session = Depends(get_db),
    token: str = Depends(verify_token)
):
    """특정 포트포워딩 규칙 조회"""
    try:
        rule = db.query(PortForwardingRule).filter(
            PortForwardingRule.rule_id == rule_id
        ).first()
        
        if not rule:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="규칙을 찾을 수 없습니다"
            )
        
        return rule
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"규칙 조회 중 오류: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="내부 서버 오류가 발생했습니다"
        )


@app.patch(
    "/api/v1/portforward/{rule_id}",
    response_model=PortForwardingResponse,
    tags=["Port Forwarding"],
    summary="포트포워딩 규칙 업데이트",
    description="포트포워딩 규칙을 업데이트합니다"
)
async def update_port_forwarding(
    rule_id: str,
    request: PortForwardingUpdate,
    db: Session = Depends(get_db),
    token: str = Depends(verify_token)
):
    """포트포워딩 규칙 업데이트"""
    try:
        rule = db.query(PortForwardingRule).filter(
            PortForwardingRule.rule_id == rule_id
        ).first()
        
        if not rule:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="규칙을 찾을 수 없습니다"
            )
        
        # 외부 포트 변경 요청 처리 (중복 시 자동 대체)
        if request.proxy_external_port is not None:
            new_port = request.proxy_external_port
            # 자기 자신 포트와 다른 경우에만 충돌 검사
            if new_port != rule.proxy_external_port:
                if check_port_conflict(db, rule.proxy_external_ip, new_port):
                    logger.warning(
                        f"업데이트 요청 포트 {rule.proxy_external_ip}:{new_port}이 이미 사용 중 "
                        f"- 사용 가능한 포트로 자동 대체"
                    )
                    new_port = find_available_port(db, rule.proxy_external_ip, rule.service_type)
                    if new_port is None:
                        raise HTTPException(
                            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail="요청 포트가 사용 중이며 대체 가능한 포트도 없습니다"
                        )

                # 기존 iptables 규칙 삭제 후 새 포트로 재등록
                if rule.status == StatusEnum.ACTIVE.value:
                    apply_iptables_rule(
                        rule.proxy_external_ip,
                        rule.proxy_external_port,
                        rule.user_vm_internal_ip,
                        rule.user_vm_internal_port,
                        rule.protocol,
                        add=False
                    )
                    apply_iptables_rule(
                        rule.proxy_external_ip,
                        new_port,
                        rule.user_vm_internal_ip,
                        rule.user_vm_internal_port,
                        rule.protocol,
                        add=True
                    )
                    save_iptables_persistent()

                logger.info(
                    f"외부 포트 변경: {rule.proxy_external_ip}:{rule.proxy_external_port} "
                    f"→ {rule.proxy_external_ip}:{new_port}"
                )
                rule.proxy_external_port = new_port

        # 상태 변경 시 iptables 규칙도 업데이트
        if request.status:
            old_status = rule.status
            new_status = request.status.value

            if old_status == StatusEnum.ACTIVE.value and new_status == StatusEnum.INACTIVE.value:
                # 비활성화: iptables 규칙 삭제
                apply_iptables_rule(
                    rule.proxy_external_ip,
                    rule.proxy_external_port,
                    rule.user_vm_internal_ip,
                    rule.user_vm_internal_port,
                    rule.protocol,
                    add=False
                )
            elif old_status == StatusEnum.INACTIVE.value and new_status == StatusEnum.ACTIVE.value:
                # 활성화: iptables 규칙 추가
                apply_iptables_rule(
                    rule.proxy_external_ip,
                    rule.proxy_external_port,
                    rule.user_vm_internal_ip,
                    rule.user_vm_internal_port,
                    rule.protocol,
                    add=True
                )

            save_iptables_persistent()

        # 나머지 필드 업데이트
        if request.rule_name:
            rule.rule_name = request.rule_name
        if request.user_vm_name:
            rule.user_vm_name = request.user_vm_name
        if request.user_vm_internal_port:
            rule.user_vm_internal_port = request.user_vm_internal_port
        if request.protocol:
            rule.protocol = request.protocol.value
        if request.status:
            rule.status = request.status.value
        if request.description is not None:
            rule.description = request.description
        
        rule.updated_at = datetime.utcnow()
        
        db.commit()
        db.refresh(rule)
        
        logger.info(f"포트포워딩 규칙 업데이트: {rule_id}")
        
        return rule
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"규칙 업데이트 중 오류: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="내부 서버 오류가 발생했습니다"
        )


@app.delete(
    "/api/v1/portforward/{rule_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["Port Forwarding"],
    summary="포트포워딩 규칙 삭제",
    description="포트포워딩 규칙을 삭제합니다"
)
async def delete_port_forwarding(
    rule_id: str,
    db: Session = Depends(get_db),
    token: str = Depends(verify_token)
):
    """포트포워딩 규칙 삭제"""
    try:
        rule = db.query(PortForwardingRule).filter(
            PortForwardingRule.rule_id == rule_id
        ).first()
        
        if not rule:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="규칙을 찾을 수 없습니다"
            )
        
        # iptables 규칙 제거
        apply_iptables_rule(
            rule.proxy_external_ip,
            rule.proxy_external_port,
            rule.user_vm_internal_ip,
            rule.user_vm_internal_port,
            rule.protocol,
            add=False
        )
        
        save_iptables_persistent()
        
        db.delete(rule)
        db.commit()
        
        logger.info(f"포트포워딩 규칙 삭제: {rule_id}")
        
        return None
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"규칙 삭제 중 오류: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="내부 서버 오류가 발생했습니다"
        )


@app.get(
    "/api/v1/status",
    response_model=StatusResponse,
    tags=["Status"],
    summary="시스템 상태",
    description="포트포워딩 시스템의 전체 상태를 조회합니다"
)
async def get_status(
    db: Session = Depends(get_db),
    token: str = Depends(verify_token)
):
    """시스템 전체 상태 조회"""
    try:
        total = db.query(PortForwardingRule).count()
        active = db.query(PortForwardingRule).filter(
            PortForwardingRule.status == StatusEnum.ACTIVE.value
        ).count()
        inactive = db.query(PortForwardingRule).filter(
            PortForwardingRule.status == StatusEnum.INACTIVE.value
        ).count()
        pending = db.query(PortForwardingRule).filter(
            PortForwardingRule.status == StatusEnum.PENDING.value
        ).count()
        
        used_ports = db.query(PortForwardingRule.proxy_external_port).filter(
            PortForwardingRule.status.in_([StatusEnum.ACTIVE.value, StatusEnum.PENDING.value])
        ).distinct().count()
        
        # 전체 가용 포트 계산
        ssh_range = FloatingIPConfig.SSH_PORT_RANGE[1] - FloatingIPConfig.SSH_PORT_RANGE[0] + 1
        portfwd_range = (FloatingIPConfig.PORTFWD_PORT_RANGE[1] - FloatingIPConfig.PORTFWD_PORT_RANGE[0] + 1) * len(FloatingIPConfig.PORTFWD_FLOATING_IPS)
        total_ports = ssh_range + portfwd_range
        available_ports = total_ports - used_ports
        
        # Floating IP별 상태
        floating_ip_status = {}
        
        # SSH IP 상태
        ssh_ip = FloatingIPConfig.SSH_FLOATING_IP
        ssh_rules = db.query(PortForwardingRule).filter(
            PortForwardingRule.proxy_external_ip == ssh_ip
        ).all()
        ssh_active = [r for r in ssh_rules if r.status == StatusEnum.ACTIVE.value]
        
        floating_ip_status[ssh_ip] = {
            "role": "ssh",
            "active_rules": len(ssh_active),
            "total_rules": len(ssh_rules),
            "max_rules": FloatingIPConfig.MAX_RULES_PER_IP,
            "usage_percent": (len(ssh_active) / FloatingIPConfig.MAX_RULES_PER_IP) * 100 if FloatingIPConfig.MAX_RULES_PER_IP > 0 else 0,
            "port_range": list(FloatingIPConfig.SSH_PORT_RANGE),
            "ports": [r.proxy_external_port for r in ssh_active]
        }
        
        # 키를 External IP로 변경
        floating_ip_status[FloatingIPConfig.get_external_ip(ssh_ip)] = floating_ip_status.pop(ssh_ip)
        
        # 포트포워딩 IP 상태
        for ip in FloatingIPConfig.PORTFWD_FLOATING_IPS:
            rules = db.query(PortForwardingRule).filter(
                PortForwardingRule.proxy_external_ip == ip
            ).all()
            active_rules = [r for r in rules if r.status == StatusEnum.ACTIVE.value]
            
            floating_ip_status[ip] = {
                "role": "portfwd",
                "active_rules": len(active_rules),
                "total_rules": len(rules),
                "max_rules": FloatingIPConfig.MAX_RULES_PER_IP,
                "usage_percent": (len(active_rules) / FloatingIPConfig.MAX_RULES_PER_IP) * 100 if FloatingIPConfig.MAX_RULES_PER_IP > 0 else 0,
                "port_range": list(FloatingIPConfig.PORTFWD_PORT_RANGE),
                "ports": [r.proxy_external_port for r in active_rules]
            }
            # 키를 External IP로 변경
            floating_ip_status[FloatingIPConfig.get_external_ip(ip)] = floating_ip_status.pop(ip)
        
        return StatusResponse(
            total_rules=total,
            active_rules=active,
            inactive_rules=inactive,
            pending_rules=pending,
            used_ports=used_ports,
            available_ports=available_ports,
            floating_ips=floating_ip_status
        )
    
    except Exception as e:
        logger.error(f"상태 조회 중 오류: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="내부 서버 오류가 발생했습니다"
        )


@app.get(
    "/api/v1/floating-ips",
    response_model=List[FloatingIPStatus],
    tags=["Status"],
    summary="Floating IP 상태 목록",
    description="모든 Floating IP의 상태를 조회합니다 (역할별 구분)"
)
async def get_floating_ip_status(
    db: Session = Depends(get_db),
    token: str = Depends(verify_token)
):
    """Floating IP별 상태 조회"""
    try:
        result = []
        
        # SSH IP
        ssh_ip = FloatingIPConfig.SSH_FLOATING_IP
        ssh_used = get_used_ports(db, ssh_ip)
        ssh_range = FloatingIPConfig.SSH_PORT_RANGE
        ssh_available = (ssh_range[1] - ssh_range[0] + 1) - len(ssh_used)
        
        result.append(FloatingIPStatus(
            ip=ssh_ip,
            role="ssh",
            active_rules=len(ssh_used),
            max_rules=FloatingIPConfig.MAX_RULES_PER_IP,
            usage_percent=(len(ssh_used) / FloatingIPConfig.MAX_RULES_PER_IP) * 100 if FloatingIPConfig.MAX_RULES_PER_IP > 0 else 0,
            available_ports=ssh_available,
            ports=sorted(list(ssh_used))
        ))
        
        # 포트포워딩 IPs
        for ip in FloatingIPConfig.PORTFWD_FLOATING_IPS:
            used = get_used_ports(db, ip)
            port_range = FloatingIPConfig.PORTFWD_PORT_RANGE
            available = (port_range[1] - port_range[0] + 1) - len(used)
            
            result.append(FloatingIPStatus(
                ip=ip,
                role="portfwd",
                active_rules=len(used),
                max_rules=FloatingIPConfig.MAX_RULES_PER_IP,
                usage_percent=(len(used) / FloatingIPConfig.MAX_RULES_PER_IP) * 100 if FloatingIPConfig.MAX_RULES_PER_IP > 0 else 0,
                available_ports=available,
                ports=sorted(list(used))
            ))
        
        return result
    
    except Exception as e:
        logger.error(f"Floating IP 상태 조회 중 오류: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="내부 서버 오류가 발생했습니다"
        )


@app.get(
    "/api/v1/port-allocation/preview",
    response_model=PortAllocationResponse,
    tags=["Status"],
    summary="포트 할당 미리보기",
    description="서비스 유형에 따라 다음에 할당될 IP와 포트를 미리보기합니다"
)
async def preview_port_allocation(
    service_type: ServiceTypeEnum = ServiceTypeEnum.OTHER,
    db: Session = Depends(get_db),
    token: str = Depends(verify_token)
):
    """포트 할당 미리보기 (실제 할당 없이 확인)"""
    try:
        if service_type == ServiceTypeEnum.SSH:
            ip, port = select_floating_ip_for_ssh(db)
            role = "ssh"
        else:
            ip, port = select_floating_ip_for_portfwd(db)
            role = "portfwd"
        
        if not ip or not port:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="사용 가능한 IP/포트가 없습니다"
            )
        
        return PortAllocationResponse(
            floating_ip=ip,
            external_port=port,
            role=role
        )
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"포트 할당 미리보기 중 오류: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="내부 서버 오류가 발생했습니다"
        )


# ============================================================================
# 메인
# ============================================================================
if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        app,
        host=os.getenv('API_HOST', '0.0.0.0'),
        port=int(os.getenv('API_PORT', 8080)),
        log_level=os.getenv('LOG_LEVEL', 'info').lower()
    )