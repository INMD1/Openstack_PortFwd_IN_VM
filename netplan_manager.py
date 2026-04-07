import os
import subprocess
import logging
import yaml
from typing import Optional

logger = logging.getLogger(__name__)

NETPLAN_FILE = os.getenv('NETPLAN_FILE', '/etc/netplan/99-multi-nic.yaml')

# 인터페이스 → (테이블 이름, IP) 매핑
# 환경변수 EXT_IFACE_1/EXT_TABLE_1/EXT_IP_1 ~ EXT_IFACE_3/EXT_TABLE_3/EXT_IP_3 로 설정
# proxy_vm_init.sh 실행 후 .env 에 출력된 값을 입력하면 됨
def _build_iface_table_map() -> dict:
    result = {}
    for i in range(1, 4):
        iface = os.getenv(f'EXT_IFACE_{i}', '')
        table = os.getenv(f'EXT_TABLE_{i}', '')
        ip    = os.getenv(f'EXT_IP_{i}', '')
        if iface and table and ip:
            result[iface] = (table, ip)
    if not result:
        # 환경변수 미설정 시 하드코딩 fallback
        # 주의: ens5 테이블명 오타 수정 (ens5_rt → rt_ens5)
        result = {
            'ens3': ('rt_ens3', os.getenv('SSH_FLOATING_IP',      '192.168.10.16')),
            'ens4': ('rt_ens4', os.getenv('PORTFWD_FLOATING_IP_1', '192.168.10.3')),
            'ens5': ('rt_ens5', os.getenv('PORTFWD_FLOATING_IP_2', '192.168.10.179')),
        }
    return result

IFACE_TABLE_MAP = _build_iface_table_map()


def _run_route_cmd(cmd: str) -> subprocess.CompletedProcess:
    """라우팅 명령 실행 공통 헬퍼"""
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)

def _load_netplan() -> dict:
    if not os.path.exists(NETPLAN_FILE):
        return {'network': {'version': 2, 'ethernets': {}}}
    with open(NETPLAN_FILE, 'r') as f:
        return yaml.safe_load(f)


def _save_netplan(config: dict) -> None:
    content = yaml.dump(config, default_flow_style=False, allow_unicode=True)
    result = subprocess.run(
        f"sudo tee {NETPLAN_FILE}",
        input=content, shell=True,
        capture_output=True, text=True
    )
    if result.returncode != 0:
        raise PermissionError(f"netplan 파일 쓰기 실패: {result.stderr}")


def _route_entry(vm_ip: str) -> dict:
    return {'to': f'{vm_ip}/32', 'on-link': True}


def _has_route(routes: list, vm_ip: str) -> bool:
    return any(r.get('to') == f'{vm_ip}/32' for r in routes)


def _iface_by_ip(ip: str) -> Optional[str]:
    """IFACE_TABLE_MAP 역방향 조회: 인터페이스 IP → 인터페이스 이름"""
    for iface, (table, src_ip) in IFACE_TABLE_MAP.items():
        if src_ip == ip:
            return iface
    return None


def add_vm_route(vm_ip: str, primary_iface: str = None) -> tuple:
    """포트포워딩 규칙 생성 시 호출.

    primary_iface 가 주어지면 main 테이블에도 해당 인터페이스로 라우트 추가.
    없으면 main 테이블은 건드리지 않음 (apply_iptables_rule 이 담당).
    """
    if os.getenv('ENV') != 'production':
        logger.info(f"[SIM] 라우트 추가: {vm_ip}/32 (primary_iface={primary_iface})")
        return True, "시뮬레이션 성공"
    try:
        # 전용 라우팅 테이블 3개에 VM 경로 추가
        for iface, (table, src_ip) in IFACE_TABLE_MAP.items():
            result = _run_route_cmd(
                f"sudo ip route replace {vm_ip}/32 dev {iface} src {src_ip} table {table}"
            )
            if result.returncode == 0:
                logger.info(f"ip route 적용 (전용 테이블): {vm_ip}/32 → {iface} table {table} (src {src_ip})")
            else:
                logger.warning(f"ip route 실패 ({iface}, table {table}): {result.stderr}")

        # primary_iface 가 주어진 경우에만 main 테이블에도 추가
        if primary_iface and primary_iface in IFACE_TABLE_MAP:
            _, src_ip = IFACE_TABLE_MAP[primary_iface]
            result = _run_route_cmd(
                f"sudo ip route replace {vm_ip}/32 dev {primary_iface} src {src_ip}"
            )
            if result.returncode == 0:
                logger.info(f"ip route 적용 (main 테이블): {vm_ip}/32 → {primary_iface} (src {src_ip})")
            else:
                logger.warning(f"ip route 실패 (main, {primary_iface}): {result.stderr}")

        # netplan 파일 수정 (재부팅 대비)
        _update_netplan_file(vm_ip, add=True)

        return True, "성공"
    except Exception as e:
        logger.error(f"add_vm_route 오류: {e}")
        return False, str(e)


def remove_vm_route(vm_ip: str, active_vm_ips: set) -> tuple:
    """포트포워딩 규칙 삭제 시 호출"""
    if os.getenv('ENV') != 'production':
        logger.info(f"[SIM] 라우트 제거: {vm_ip}/32")
        return True, "시뮬레이션 성공"

    if vm_ip in active_vm_ips:
        logger.info(f"{vm_ip} 다른 규칙에서 사용 중 - 유지")
        return True, "유지"
    try:
        # main 테이블에서 제거
        _run_route_cmd(f"sudo ip route del {vm_ip}/32")
        # 각 전용 테이블에서도 제거
        for iface, (table, _) in IFACE_TABLE_MAP.items():
            _run_route_cmd(f"sudo ip route del {vm_ip}/32 table {table}")
            logger.info(f"ip route 제거: {vm_ip}/32 table {table}")

        _update_netplan_file(vm_ip, add=False)
        return True, "성공"
    except Exception as e:
        logger.error(f"remove_vm_route 오류: {e}")
        return False, str(e)


def sync_routes_from_vm_ips(active_vm_ips: set) -> tuple:
    """재부팅 후 startup 시 호출 - ip route로 복구"""
    if os.getenv('ENV') != 'production':
        return 0, 0
    try:
        added = 0
        for vm_ip in active_vm_ips:
            # 전용 테이블만 복구
            # main 테이블 경로는 sync_iptables_from_db 의 apply_iptables_rule step[5] 가 담당
            for iface, (table, src_ip) in IFACE_TABLE_MAP.items():
                _run_route_cmd(
                    f"sudo ip route replace {vm_ip}/32 dev {iface} src {src_ip} table {table}"
                )
            logger.info(f"[SYNC] {vm_ip}/32 전용 테이블 라우트 복구 완료")
            added += 1
        return added, 0
    except Exception as e:
        logger.error(f"sync_routes_from_vm_ips 오류: {e}")
        return 0, 0


def sync_routes_from_db(rules: list) -> tuple:
    """재시작 시 DB 기반으로 main 테이블 라우트를 올바르게 복구.

    rules: [(user_vm_internal_ip, proxy_external_ip), ...] 형태 리스트
    proxy_external_ip 로 인터페이스를 찾아서 main 테이블 라우트를 정확하게 설정.
    같은 vm_ip 가 여러 규칙에 있으면 첫 번째 것만 사용.
    전용 테이블 3개에도 모두 추가.
    """
    if os.getenv('ENV') != 'production':
        logger.info(f"[SIM] sync_routes_from_db: {len(rules)}개 규칙 처리")
        return len(rules), 0

    added = 0
    # vm_ip → 첫 번째로 매핑된 인터페이스 (중복 방지)
    seen_vm_ips: dict = {}
    for vm_ip, proxy_ext_ip in rules:
        if vm_ip not in seen_vm_ips:
            iface = _iface_by_ip(proxy_ext_ip)
            seen_vm_ips[vm_ip] = iface  # None 이어도 저장해 두어 중복 처리 방지

    try:
        for vm_ip, primary_iface in seen_vm_ips.items():
            # 전용 테이블 3개 복구
            for iface, (table, src_ip) in IFACE_TABLE_MAP.items():
                result = _run_route_cmd(
                    f"sudo ip route replace {vm_ip}/32 dev {iface} src {src_ip} table {table}"
                )
                if result.returncode != 0:
                    logger.warning(f"[SYNC] ip route 실패 ({iface}, table {table}): {result.stderr}")

            # main 테이블: 인터페이스를 특정할 수 있을 때만 추가
            if primary_iface and primary_iface in IFACE_TABLE_MAP:
                _, src_ip = IFACE_TABLE_MAP[primary_iface]
                result = _run_route_cmd(
                    f"sudo ip route replace {vm_ip}/32 dev {primary_iface} src {src_ip}"
                )
                if result.returncode == 0:
                    logger.info(f"[SYNC] main 테이블 복구: {vm_ip}/32 → {primary_iface} (src {src_ip})")
                else:
                    logger.warning(f"[SYNC] main 테이블 복구 실패 ({primary_iface}): {result.stderr}")
            else:
                logger.warning(f"[SYNC] {vm_ip}: proxy_external_ip 로 인터페이스를 찾지 못해 main 테이블 스킵")

            added += 1

        return added, 0
    except Exception as e:
        logger.error(f"sync_routes_from_db 오류: {e}")
        return 0, 0


def _update_netplan_file(vm_ip: str, add: bool) -> None:
    """netplan 파일만 수정 - apply는 하지 않음"""
    try:
        config = _load_netplan()
        ethernets = config.get('network', {}).get('ethernets', {})
        target = f'{vm_ip}/32'

        for iface in IFACE_TABLE_MAP.keys():
            if iface not in ethernets:
                continue
            routes = ethernets[iface].setdefault('routes', [])
            if add:
                if not _has_route(routes, vm_ip):
                    routes.append(_route_entry(vm_ip))
            else:
                ethernets[iface]['routes'] = [
                    r for r in routes if r.get('to') != target
                ]

        _save_netplan(config)
        logger.info(f"netplan 파일 {'추가' if add else '제거'}: {vm_ip}/32")
    except Exception as e:
        logger.warning(f"netplan 파일 수정 실패 (무시): {e}")