#!/bin/bash
# ============================================================================
# proxy_vm_init.sh - Proxy VM 포트포워딩 초기화 스크립트
#
# 확인된 네트워크 구성:
#   ens3  192.168.10.16   ↔ 113.198.230.20  (포트포워딩)
#   ens4  192.168.10.3    ↔ 113.198.230.17  (SSH 전용)
#   ens5  192.168.10.179  ↔ 113.198.230.18  (포트포워딩)
#   ens6  192.168.10.198  관리용 (default route, 이 스크립트에서 건드리지 않음)
#   tailscale0            관리자 SSH (이 스크립트에서 건드리지 않음)
#
#   공통 게이트웨이: 192.168.10.1
#   공통 서브넷:    192.168.10.0/24
# ============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[ OK ]${NC} $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[FAIL]${NC} $*"; exit 1; }

GW="192.168.10.1"
SUBNET="192.168.10.0/24"

declare -A IP=(    [ens3]="192.168.10.16"  [ens4]="192.168.10.3"  [ens5]="192.168.10.179" )
declare -A TID=(   [ens3]=100              [ens4]=101              [ens5]=102              )
declare -A TNAME=( [ens3]="rt_ens3"        [ens4]="rt_ens4"        [ens5]="rt_ens5"        )
IFACES=(ens3 ens4 ens5)

echo ""
echo "================================================================"
echo "  Proxy VM 포트포워딩 초기화"
echo "================================================================"
echo "  ens3  192.168.10.16   ↔ 113.198.230.20  포트포워딩"
echo "  ens4  192.168.10.3    ↔ 113.198.230.17  SSH 전용"
echo "  ens5  192.168.10.179  ↔ 113.198.230.18  포트포워딩"
echo "  ens6  192.168.10.198  관리용 (건드리지 않음)"
echo "  GW=$GW  SUBNET=$SUBNET"
echo "================================================================"
echo ""

[ "$(id -u)" -ne 0 ] && error "root 권한 필요. sudo 로 실행하세요."

# ─────────────────────────────────────────────────
# STEP 1: 필수 패키지
# ─────────────────────────────────────────────────
info "[1/6] 필수 패키지 설치..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q iptables-persistent netfilter-persistent
success "패키지 설치 완료"

# ─────────────────────────────────────────────────
# STEP 2: 커널 파라미터
# ─────────────────────────────────────────────────
info "[2/6] 커널 파라미터 설정..."
cat > /etc/sysctl.d/99-portfwd.conf << 'EOF'
net.ipv4.ip_forward = 1
# rp_filter=2 (Loose): 다중 NIC 환경 필수
# strict(1) 이면 ens3~5 응답 패킷을 커널이 버림
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
net.ipv4.conf.ens3.rp_filter = 2
net.ipv4.conf.ens4.rp_filter = 2
net.ipv4.conf.ens5.rp_filter = 2
EOF
sysctl --system -q
success "ip_forward=1, rp_filter=2 적용"

# ─────────────────────────────────────────────────
# STEP 3: 라우팅 테이블 등록
# ─────────────────────────────────────────────────
info "[3/6] 라우팅 테이블 등록..."
for iface in "${IFACES[@]}"; do
    tid="${TID[$iface]}"; tname="${TNAME[$iface]}"
    if grep -qE "^${tid}[[:space:]]" /etc/iproute2/rt_tables; then
        info "  이미 존재: $tid $tname"
    else
        echo "$tid $tname" >> /etc/iproute2/rt_tables
        info "  등록: $tid $tname"
    fi
done
success "라우팅 테이블 등록 완료"

# ─────────────────────────────────────────────────
# STEP 4: Policy-Based Routing 적용 (런타임)
#
# 흐름 예시 (ens3):
#   외부 → ens3(192.168.10.16) 수신
#   DNAT → 내부VM:port
#   POSTROUTING -o ens3 MASQUERADE → src=192.168.10.16
#   내부VM 응답 → dst=192.168.10.16
#   ip rule "from 192.168.10.16 → rt_ens3"
#   rt_ens3: default via 192.168.10.1 dev ens3 → ens3 으로만 나감 ✓
# ─────────────────────────────────────────────────
info "[4/6] Policy-Based Routing 적용..."

for iface in "${IFACES[@]}"; do
    tid="${TID[$iface]}"; tname="${TNAME[$iface]}"; ip_addr="${IP[$iface]}"

    ip route replace "$SUBNET" dev "$iface" src "$ip_addr" table "$tid"
    info "  [route] $tname: $SUBNET dev $iface src $ip_addr"

    ip route replace default via "$GW" dev "$iface" table "$tid"
    info "  [route] $tname: default via $GW dev $iface"

    if ip rule show | grep -q "from ${ip_addr} lookup ${tname}"; then
        info "  [rule]  from $ip_addr → $tname 이미 존재"
    else
        ip rule add from "$ip_addr" lookup "$tname" priority 100
        info "  [rule]  from $ip_addr → $tname 추가"
    fi
    success "  $iface ($ip_addr) PBR 완료"
done

# ─────────────────────────────────────────────────
# STEP 5: iptables
# ─────────────────────────────────────────────────
info "[5/6] iptables 설정..."

# FORWARD: 응답 패킷 허용 (없으면 TCP 연결 불가)
if ! iptables -C FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null; then
    iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    info "  FORWARD ESTABLISHED,RELATED → ACCEPT 추가"
else
    info "  FORWARD ESTABLISHED,RELATED → ACCEPT 이미 존재"
fi

# 각 Floating 인터페이스 개별 MASQUERADE
# ⚠️  ens6 에 걸면 안 됨: 응답이 관리 인터페이스로 나가버림
for iface in "${IFACES[@]}"; do
    if ! iptables -t nat -C POSTROUTING -o "$iface" -j MASQUERADE 2>/dev/null; then
        iptables -t nat -A POSTROUTING -o "$iface" -j MASQUERADE
        info "  POSTROUTING -o $iface → MASQUERADE 추가"
    else
        info "  POSTROUTING -o $iface → MASQUERADE 이미 존재"
    fi
done

mkdir -p /etc/iptables
iptables-save  > /etc/iptables/rules.v4
ip6tables-save > /etc/iptables/rules.v6
systemctl enable --quiet netfilter-persistent
systemctl restart netfilter-persistent
success "iptables 저장 완료"

# ─────────────────────────────────────────────────
# STEP 6: netplan PBR 영구화 (재부팅 대비)
# ⚠️  netplan apply 시 네트워크 순간 재설정됨
#    Tailscale / ens6 SSH 연결은 자동 복구
# ─────────────────────────────────────────────────
info "[6/6] netplan 설정 파일 생성..."

cat > /etc/netplan/50-portfwd-pbr.yaml << EOF
# /etc/netplan/50-portfwd-pbr.yaml  (proxy_vm_init.sh 생성)
# ens3/ens4/ens5 전용 라우팅 테이블 - 비대칭 라우팅 방지
# ens6 / tailscale0 은 이 파일에서 건드리지 않음
network:
  version: 2
  ethernets:
    ens3:
      dhcp4: true
      dhcp4-overrides:
        use-routes: false       # main 테이블 default route 추가 안 함
      routing-policy:
        - from: 192.168.10.16/32
          table: 100
          priority: 100
      routes:
        - to: $SUBNET
          scope: link
          table: 100
        - to: default
          via: $GW
          table: 100
    ens4:
      dhcp4: true
      dhcp4-overrides:
        use-routes: false
      routing-policy:
        - from: 192.168.10.3/32
          table: 101
          priority: 100
      routes:
        - to: $SUBNET
          scope: link
          table: 101
        - to: default
          via: $GW
          table: 101
    ens5:
      dhcp4: true
      dhcp4-overrides:
        use-routes: false
      routing-policy:
        - from: 192.168.10.179/32
          table: 102
          priority: 100
      routes:
        - to: $SUBNET
          scope: link
          table: 102
        - to: default
          via: $GW
          table: 102
EOF

chmod 600 /etc/netplan/50-portfwd-pbr.yaml
info "  생성: /etc/netplan/50-portfwd-pbr.yaml"

if netplan generate 2>&1 | grep -qi error; then
    warn "netplan 문법 오류 - 확인 후 수동으로 'sudo netplan apply' 실행"
else
    netplan apply
    success "netplan apply 완료 (재부팅 후에도 유지)"
fi

# ─────────────────────────────────────────────────
# 결과 확인
# ─────────────────────────────────────────────────
echo ""
echo "================================================================"
echo "  완료 - 상태 확인"
echo "================================================================"
echo ""
echo "▶ ip_forward (1=정상):"
cat /proc/sys/net/ipv4/ip_forward

echo ""
echo "▶ rp_filter (2=Loose/정상):"
for iface in "${IFACES[@]}"; do
    echo "  $iface: $(cat /proc/sys/net/ipv4/conf/$iface/rp_filter 2>/dev/null)"
done

echo ""
echo "▶ ip rule:"
ip rule show

echo ""
echo "▶ 전용 라우팅 테이블:"
for iface in "${IFACES[@]}"; do
    echo "  ── ${TNAME[$iface]} ──"
    ip route show table "${TNAME[$iface]}" 2>/dev/null || echo "  (비어있음)"
done

echo ""
echo "▶ POSTROUTING:"
iptables -t nat -L POSTROUTING -n --line-numbers 2>/dev/null | grep -E "^Chain|MASQUERADE" || true

echo ""
echo "================================================================"
echo "  .env 파일 설정값 (복붙용)"
echo "================================================================"
cat << 'ENVEOF'

ENV=production
PROXY_MODE=local

EXT_IFACE_1=ens3
EXT_TABLE_1=rt_ens3
EXT_IP_1=192.168.10.16

EXT_IFACE_2=ens4
EXT_TABLE_2=rt_ens4
EXT_IP_2=192.168.10.3

EXT_IFACE_3=ens5
EXT_TABLE_3=rt_ens5
EXT_IP_3=192.168.10.179

SSH_FLOATING_IP=192.168.10.3
SSH_FLOATING_IP_GET=113.198.230.17

PORTFWD_FLOATING_IP_1=192.168.10.16
PORTFWD_FLOATING_IP_1_GET=113.198.230.20

PORTFWD_FLOATING_IP_2=192.168.10.179
PORTFWD_FLOATING_IP_2_GET=113.198.230.18
ENVEOF

echo ""
success "모든 설정 완료!"
echo "  다음: 위 .env 값 복붙 후  python3 portfwd_api.py"
echo ""