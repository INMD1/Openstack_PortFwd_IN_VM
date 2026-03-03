import os
import subprocess
import logging
import yaml

logger = logging.getLogger(__name__)

NETPLAN_FILE = os.getenv('NETPLAN_FILE', '/etc/netplan/99-multi-nic.yaml')

# 인터페이스 → (테이블 이름, IP) 매핑
IFACE_TABLE_MAP = {
    'ens3': ('rt_ens3', '192.168.10.16'),
    'ens4': ('rt_ens4', '192.168.10.3'),
    'ens5': ('ens5_rt', '192.168.10.179'),
}


def _run_route_cmd(cmd: str) -> subprocess.CompletedProcess:
    """라우팅 명령 실행 공통 헬퍼"""
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)

def _load_netplan() -> dict:
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


def add_vm_route(vm_ip: str) -> tuple:
    """포트포워딩 규칙 생성 시 호출"""
    if os.getenv('ENV') != 'production':
        logger.info(f"[SIM] 라우트 추가: {vm_ip}/32")
        return True, "시뮬레이션 성공"
    try:
        # 1. 각 인터페이스의 전용 라우팅 테이블에 VM 경로 추가
        for iface, (table, src_ip) in IFACE_TABLE_MAP.items():
            # main 테이블에 추가 (즉시 포워딩용)
            _run_route_cmd(
                f"sudo ip route replace {vm_ip}/32 dev {iface} src {src_ip}"
            )
            # 전용 테이블에도 추가 (fwmark 라우팅용) ← 핵심
            result = _run_route_cmd(
                f"sudo ip route replace {vm_ip}/32 dev {iface} src {src_ip} table {table}"
            )
            if result.returncode == 0:
                logger.info(f"ip route 적용: {vm_ip}/32 → {iface} table {table} (src {src_ip})")
            else:
                logger.warning(f"ip route 실패 ({iface}, table {table}): {result.stderr}")

        # 2. netplan 파일 수정 (재부팅 대비)
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
            for iface, (table, src_ip) in IFACE_TABLE_MAP.items():
                # main 테이블
                _run_route_cmd(
                    f"sudo ip route replace {vm_ip}/32 dev {iface} src {src_ip}"
                )
                # 전용 테이블
                _run_route_cmd(
                    f"sudo ip route replace {vm_ip}/32 dev {iface} src {src_ip} table {table}"
                )
            logger.info(f"[SYNC] {vm_ip}/32 라우트 복구 완료")
            added += 1
        return added, 0
    except Exception as e:
        logger.error(f"sync_routes_from_vm_ips 오류: {e}")
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