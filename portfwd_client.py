#!/usr/bin/env python3
# portfwd_client.py - CLI 클라이언트
# SSH 전용 IP와 포트포워딩 IP 분리 지원

import argparse
import json
import requests
import sys
from typing import Optional
from tabulate import tabulate

class PortForwardingClient:
    """포트포워딩 API 클라이언트"""
    
    def __init__(self, base_url: str = "http://localhost:8080", token: Optional[str] = None):
        self.base_url = base_url.rstrip('/')
        self.token = token
        self.session = requests.Session()
        self.session.headers.update({
            "Content-Type": "application/json"
        })
        if token:
            self.session.headers["Authorization"] = f"Bearer {token}"
    
    def _request(self, method: str, endpoint: str, data: dict = None) -> dict:
        """HTTP 요청 실행"""
        url = f"{self.base_url}/api/v1{endpoint}"
        
        try:
            if method == "GET":
                response = self.session.get(url)
            elif method == "POST":
                response = self.session.post(url, json=data)
            elif method == "PATCH":
                response = self.session.patch(url, json=data)
            elif method == "DELETE":
                response = self.session.delete(url)
            else:
                raise ValueError(f"Unsupported method: {method}")
            
            response.raise_for_status()
            
            if response.status_code == 204:
                return {}
            
            return response.json()
        
        except requests.exceptions.RequestException as e:
            print(f"❌ 요청 실패: {str(e)}")
            if hasattr(e, 'response') and e.response is not None:
                try:
                    error_detail = e.response.json()
                    print(f"   상세: {error_detail.get('detail', e.response.text)}")
                except (ValueError, KeyError):
                    print(f"   응답: {e.response.text}")
            sys.exit(1)
    
    def create_rule(
        self, 
        rule_name: str, 
        vm_id: str, 
        vm_name: str, 
        internal_ip: str, 
        internal_port: int,
        service_type: str = "other",
        floating_ip: Optional[str] = None,
        external_port: Optional[int] = None,
        protocol: str = "tcp",
        description: Optional[str] = None
    ) -> dict:
        """포트포워딩 규칙 생성"""
        data = {
            "rule_name": rule_name,
            "user_vm_id": vm_id,
            "user_vm_name": vm_name,
            "user_vm_internal_ip": internal_ip,
            "user_vm_internal_port": internal_port,
            "service_type": service_type,
            "protocol": protocol
        }
        
        if floating_ip:
            data["proxy_external_ip"] = floating_ip
        if external_port:
            data["proxy_external_port"] = external_port
        if description:
            data["description"] = description
        
        return self._request("POST", "/portforward", data)
    
    def list_rules(
        self, 
        status: Optional[str] = None, 
        floating_ip: Optional[str] = None,
        service_type: Optional[str] = None,
        vm_id: Optional[str] = None
    ) -> list:
        """포트포워딩 규칙 목록 조회"""
        params = []
        if status:
            params.append(f"status_filter={status}")
        if floating_ip:
            params.append(f"floating_ip={floating_ip}")
        if service_type:
            params.append(f"service_type={service_type}")
        if vm_id:
            params.append(f"vm_id={vm_id}")
        
        endpoint = "/portforward" + ("?" + "&".join(params) if params else "")
        return self._request("GET", endpoint)
    
    def get_rules_by_vm(self, vm_id: str) -> list:
        """특정 VM의 규칙 조회"""
        return self._request("GET", f"/portforward/vm/{vm_id}")
    
    def get_rule(self, rule_id: str) -> dict:
        """특정 규칙 조회"""
        return self._request("GET", f"/portforward/{rule_id}")
    
    def update_rule(self, rule_id: str, **kwargs) -> dict:
        """규칙 업데이트"""
        return self._request("PATCH", f"/portforward/{rule_id}", kwargs)
    
    def delete_rule(self, rule_id: str) -> dict:
        """규칙 삭제"""
        return self._request("DELETE", f"/portforward/{rule_id}")
    
    def get_status(self) -> dict:
        """시스템 상태 조회"""
        return self._request("GET", "/status")
    
    def get_floating_ips(self) -> list:
        """Floating IP 상태 조회"""
        return self._request("GET", "/floating-ips")
    
    def preview_allocation(self, service_type: str = "other") -> dict:
        """포트 할당 미리보기"""
        return self._request("GET", f"/port-allocation/preview?service_type={service_type}")
    
    def health_check(self) -> dict:
        """헬스 체크"""
        return self._request("GET", "/health")


def print_rule(rule: dict):
    """규칙 출력"""
    print("\n📋 포트포워딩 규칙:")
    print(f"  Rule ID: {rule['rule_id']}")
    print(f"  이름: {rule['rule_name']}")
    print(f"  VM: {rule['user_vm_name']} ({rule['user_vm_id'][:8]}...)")
    print(f"  유형: {rule.get('service_type', 'other').upper()}")
    print(f"  경로: {rule['proxy_external_ip']}:{rule['proxy_external_port']} → {rule['user_vm_internal_ip']}:{rule['user_vm_internal_port']}")
    print(f"  프로토콜: {rule['protocol'].upper()}")
    print(f"  상태: {rule['status']}")
    if rule.get('description'):
        print(f"  설명: {rule['description']}")
    print(f"  생성: {rule['created_at']}")


def print_rules_table(rules: list):
    """규칙 목록을 테이블로 출력"""
    if not rules:
        print("📭 규칙이 없습니다")
        return
    
    data = []
    for rule in rules:
        service_icon = "🔐" if rule.get('service_type') == 'ssh' else "🔗"
        data.append([
            rule['rule_id'][:8],
            rule['rule_name'],
            service_icon,
            rule['user_vm_name'],
            f"{rule['proxy_external_ip']}:{rule['proxy_external_port']}",
            f"{rule['user_vm_internal_ip']}:{rule['user_vm_internal_port']}",
            rule['protocol'].upper(),
            rule['status']
        ])
    
    headers = ["ID", "규칙명", "유형", "VM명", "외부 주소", "내부 주소", "프로토콜", "상태"]
    print("\n" + tabulate(data, headers=headers, tablefmt="grid"))
    print(f"\n총 {len(rules)}개 규칙 (🔐=SSH, 🔗=기타)")


def print_status(status: dict):
    """상태 출력"""
    print("\n📊 시스템 상태:")
    print(f"  총 규칙: {status['total_rules']}")
    print(f"  활성: {status['active_rules']}")
    print(f"  비활성: {status['inactive_rules']}")
    print(f"  대기: {status['pending_rules']}")
    print(f"  사용 중인 포트: {status['used_ports']}")
    print(f"  가용 포트: {status['available_ports']}")
    
    print("\n🌐 Floating IP 상태:")
    data = []
    for ip, info in status['floating_ips'].items():
        role_icon = "🔐" if info.get('role') == 'ssh' else "🔗"
        ports_str = ", ".join(map(str, info.get('ports', [])[:5]))
        if len(info.get('ports', [])) > 5:
            ports_str += f" (+{len(info['ports'])-5})"
        
        data.append([
            ip,
            role_icon,
            info['active_rules'],
            info['max_rules'],
            f"{info['usage_percent']:.1f}%",
            ports_str or "-"
        ])
    
    headers = ["IP", "역할", "활성", "최대", "사용률", "포트"]
    print(tabulate(data, headers=headers, tablefmt="grid"))
    print("\n(🔐=SSH 전용, 🔗=포트포워딩)")


def print_floating_ips(ips: list):
    """Floating IP 상태 출력"""
    print("\n🌐 Floating IP 상세 상태:")
    data = []
    for ip_info in ips:
        role_icon = "🔐 SSH" if ip_info['role'] == 'ssh' else "🔗 포트포워딩"
        ports_str = ", ".join(map(str, ip_info.get('ports', [])[:10]))
        if len(ip_info.get('ports', [])) > 10:
            ports_str += f" (+{len(ip_info['ports'])-10})"
        
        data.append([
            ip_info['ip'],
            role_icon,
            ip_info['active_rules'],
            ip_info['available_ports'],
            f"{ip_info['usage_percent']:.1f}%",
            ports_str or "-"
        ])
    
    headers = ["IP", "역할", "사용중", "여유 포트", "사용률", "할당된 포트"]
    print(tabulate(data, headers=headers, tablefmt="grid"))


def main():
    parser = argparse.ArgumentParser(
        description="OpenStack 포트포워딩 관리 CLI (SSH/포트포워딩 IP 분리 지원)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  # SSH 포트포워딩 생성 (1번 IP에서 랜덤 포트)
  %(prog)s create vm-ssh UUID vm-01 10.0.0.6 22 --service-type ssh
  
  # 일반 포트포워딩 생성 (2번/3번 IP 비교 선택)
  %(prog)s create web-80 UUID vm-01 10.0.0.6 80 --service-type other
  
  # 규칙 목록 조회
  %(prog)s list
  %(prog)s list --service-type ssh
  
  # VM별 규칙 조회
  %(prog)s vm-rules <vm-uuid>
  
  # 포트 할당 미리보기
  %(prog)s preview --service-type ssh
  
  # 상태 조회
  %(prog)s status
  %(prog)s floating-ips
        """
    )
    
    parser.add_argument('--url', default='http://localhost:8080', 
                       help='API URL (기본값: http://localhost:8080)')
    parser.add_argument('--token', help='API 토큰 (선택사항)')
    
    subparsers = parser.add_subparsers(dest='command', help='명령어')
    
    # create 명령
    create_parser = subparsers.add_parser('create', help='포트포워딩 규칙 생성')
    create_parser.add_argument('rule_name', help='규칙 이름')
    create_parser.add_argument('vm_id', help='VM ID (UUID)')
    create_parser.add_argument('vm_name', help='VM 이름')
    create_parser.add_argument('internal_ip', help='내부 IP')
    create_parser.add_argument('internal_port', type=int, help='내부 포트')
    create_parser.add_argument('--service-type', default='other', choices=['ssh', 'other'], 
                              help='서비스 유형: ssh(1번 IP) 또는 other(2번/3번 IP)')
    create_parser.add_argument('--floating-ip', help='Floating IP (선택)')
    create_parser.add_argument('--external-port', type=int, help='외부 포트 (선택)')
    create_parser.add_argument('--protocol', default='tcp', choices=['tcp', 'udp'], help='프로토콜')
    create_parser.add_argument('--description', help='설명')
    
    # list 명령
    list_parser = subparsers.add_parser('list', help='규칙 목록 조회')
    list_parser.add_argument('--status', choices=['active', 'inactive', 'pending', 'error'], help='상태 필터')
    list_parser.add_argument('--floating-ip', help='Floating IP 필터')
    list_parser.add_argument('--service-type', choices=['ssh', 'other'], help='서비스 유형 필터')
    list_parser.add_argument('--vm-id', help='VM ID 필터')
    
    # vm-rules 명령
    vm_rules_parser = subparsers.add_parser('vm-rules', help='VM별 규칙 조회')
    vm_rules_parser.add_argument('vm_id', help='VM ID (UUID)')
    
    # get 명령
    get_parser = subparsers.add_parser('get', help='규칙 조회')
    get_parser.add_argument('rule_id', help='규칙 ID')
    
    # update 명령
    update_parser = subparsers.add_parser('update', help='규칙 업데이트')
    update_parser.add_argument('rule_id', help='규칙 ID')
    update_parser.add_argument('--status', choices=['active', 'inactive'], help='상태')
    update_parser.add_argument('--description', help='설명')
    
    # delete 명령
    delete_parser = subparsers.add_parser('delete', help='규칙 삭제')
    delete_parser.add_argument('rule_id', help='규칙 ID')
    delete_parser.add_argument('--force', action='store_true', help='확인 없이 삭제')
    
    # status 명령
    subparsers.add_parser('status', help='시스템 상태 조회')
    
    # floating-ips 명령
    subparsers.add_parser('floating-ips', help='Floating IP 상세 상태')
    
    # preview 명령
    preview_parser = subparsers.add_parser('preview', help='포트 할당 미리보기')
    preview_parser.add_argument('--service-type', default='other', choices=['ssh', 'other'],
                                help='서비스 유형')
    
    # health 명령
    subparsers.add_parser('health', help='헬스 체크')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(0)
    
    client = PortForwardingClient(args.url, args.token)
    
    try:
        if args.command == 'create':
            result = client.create_rule(
                args.rule_name,
                args.vm_id,
                args.vm_name,
                args.internal_ip,
                args.internal_port,
                args.service_type,
                args.floating_ip,
                args.external_port,
                args.protocol,
                args.description
            )
            print("\n✅ 규칙 생성 성공!")
            print_rule(result)
            
            # SSH 접속 명령어 출력
            if args.service_type == 'ssh' or args.internal_port == 22:
                print(f"\n💡 SSH 접속 명령어:")
                print(f"   ssh user@{result['proxy_external_ip']} -p {result['proxy_external_port']}")
        
        elif args.command == 'list':
            rules = client.list_rules(args.status, args.floating_ip, args.service_type, args.vm_id)
            print_rules_table(rules)
        
        elif args.command == 'vm-rules':
            rules = client.get_rules_by_vm(args.vm_id)
            print(f"\n📋 VM {args.vm_id[:8]}...의 포트포워딩 규칙:")
            print_rules_table(rules)
        
        elif args.command == 'get':
            rule = client.get_rule(args.rule_id)
            print_rule(rule)
        
        elif args.command == 'update':
            updates = {}
            if args.status:
                updates['status'] = args.status
            if args.description is not None:
                updates['description'] = args.description
            
            result = client.update_rule(args.rule_id, **updates)
            print("\n✅ 규칙 업데이트 성공!")
            print_rule(result)
        
        elif args.command == 'delete':
            if not args.force:
                rule = client.get_rule(args.rule_id)
                print(f"\n삭제할 규칙: {rule['rule_name']}")
                print(f"  유형: {rule.get('service_type', 'other').upper()}")
                print(f"  {rule['proxy_external_ip']}:{rule['proxy_external_port']} → {rule['user_vm_internal_ip']}:{rule['user_vm_internal_port']}")
                
                confirm = input("\n정말 삭제하시겠습니까? (y/N): ")
                if confirm.lower() != 'y':
                    print("❌ 삭제 취소됨")
                    sys.exit(0)
            
            client.delete_rule(args.rule_id)
            print("✅ 규칙 삭제 성공!")
        
        elif args.command == 'status':
            status = client.get_status()
            print_status(status)
        
        elif args.command == 'floating-ips':
            ips = client.get_floating_ips()
            print_floating_ips(ips)
        
        elif args.command == 'preview':
            result = client.preview_allocation(args.service_type)
            role_text = "SSH 전용 (1번 IP)" if result['role'] == 'ssh' else "포트포워딩 (2번/3번 IP)"
            print(f"\n🔍 포트 할당 미리보기 ({args.service_type}):")
            print(f"  Floating IP: {result['floating_ip']}")
            print(f"  외부 포트: {result['external_port']}")
            print(f"  역할: {role_text}")
        
        elif args.command == 'health':
            health = client.health_check()
            print(f"\n✅ API 상태: {health['status']}")
            print(f"   버전: {health['version']}")
            print(f"   시간: {health['timestamp']}")
            if 'config' in health:
                print(f"   SSH IP: {health['config']['ssh_ip']}")
                print(f"   포트포워딩 IPs: {health['config']['portfwd_ips']}")
                print(f"   환경: {health['config']['env']}")
    
    except Exception as e:
        print(f"\n❌ 오류: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main()
