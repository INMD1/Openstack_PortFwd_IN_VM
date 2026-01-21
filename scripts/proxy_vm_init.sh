#!/bin/bash
# proxy_vm_init.sh - Proxy VM 초기 설정 스크립트
# 이 스크립트를 Proxy VM에서 실행하세요

set -e

echo "=============================================="
echo "  Proxy VM 포트포워딩 초기 설정"
echo "=============================================="

# 1. IP 포워딩 활성화
echo "[1/5] IP 포워딩 활성화..."
if ! grep -q "net.ipv4.ip_forward = 1" /etc/sysctl.conf; then
    echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
fi
sysctl -p

# 2. iptables-persistent 설치
echo "[2/5] iptables-persistent 설치..."
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y iptables-persistent

# 3. iptables 기본 규칙 설정
echo "[3/5] iptables 기본 규칙 설정..."

# 기본 MASQUERADE 규칙 (외부 인터페이스에서)
# eth0은 실제 외부 인터페이스 이름으로 변경 필요
EXTERNAL_IF=$(ip route | grep default | awk '{print $5}' | head -n1)
echo "   외부 인터페이스: $EXTERNAL_IF"

iptables -t nat -C POSTROUTING -o $EXTERNAL_IF -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -o $EXTERNAL_IF -j MASQUERADE

# 4. iptables 규칙 저장
echo "[4/5] iptables 규칙 저장..."
mkdir -p /etc/iptables
iptables-save > /etc/iptables/rules.v4
ip6tables-save > /etc/iptables/rules.v6

# 5. netfilter-persistent 서비스 활성화
echo "[5/5] 서비스 활성화..."
systemctl enable netfilter-persistent
systemctl start netfilter-persistent

echo ""
echo "=============================================="
echo "  설정 완료!"
echo "=============================================="
echo ""
echo "현재 NAT 규칙:"
iptables -t nat -L -n -v
echo ""
echo "IP 포워딩 상태:"
cat /proc/sys/net/ipv4/ip_forward
echo ""
echo "Proxy VM이 포트포워딩을 처리할 준비가 되었습니다."
