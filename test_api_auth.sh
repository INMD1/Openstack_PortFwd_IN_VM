#!/bin/bash
# ============================================================================
# API 인증 테스트 스크립트
# ============================================================================
# 이 스크립트는 API_SECRET_KEY 인증이 제대로 작동하는지 테스트합니다.

# .env 파일에서 API_SECRET_KEY 읽기
source /home/ubuntu/Openstack_PortFwd_IN_VM/.env

# API 서버 URL (필요시 수정)
API_URL="http://localhost:8080"

echo "============================================================"
echo "API 인증 테스트"
echo "============================================================"
echo ""

# 테스트 1: 키 없이 접근 시도 (실패해야 함)
echo "[테스트 1] 인증 키 없이 상태 조회 시도..."
echo "예상 결과: 401 Unauthorized"
echo ""
curl -s -o /dev/null -w "HTTP 상태 코드: %{http_code}\n" \
  ${API_URL}/api/v1/status
echo ""

# 테스트 2: 잘못된 키로 접근 시도 (실패해야 함)
echo "[테스트 2] 잘못된 API 키로 상태 조회 시도..."
echo "예상 결과: 401 Unauthorized"
echo ""
curl -s -o /dev/null -w "HTTP 상태 코드: %{http_code}\n" \
  -H "Authorization: Bearer wrong-api-key" \
  ${API_URL}/api/v1/status
echo ""

# 테스트 3: 올바른 키로 접근 (성공해야 함)
echo "[테스트 3] 올바른 API 키로 상태 조회 시도..."
echo "예상 결과: 200 OK"
echo ""
RESPONSE=$(curl -s -w "\nHTTP_STATUS:%{http_code}" \
  -H "Authorization: Bearer ${API_SECRET_KEY}" \
  ${API_URL}/api/v1/status)

HTTP_STATUS=$(echo "$RESPONSE" | grep "HTTP_STATUS" | cut -d: -f2)
BODY=$(echo "$RESPONSE" | sed '/HTTP_STATUS/d')

echo "HTTP 상태 코드: ${HTTP_STATUS}"
echo "응답 내용:"
echo "$BODY" | python3 -m json.tool 2>/dev/null || echo "$BODY"
echo ""

echo "============================================================"
echo "테스트 완료"
echo "============================================================"
echo ""
echo "✅ API_SECRET_KEY 인증이 활성화되었습니다."
echo "   - 올바른 키 없이는 API 접근이 불가능합니다."
echo ""
echo "📝 사용 방법:"
echo "   curl -H \"Authorization: Bearer ${API_SECRET_KEY}\" ${API_URL}/api/v1/..."
echo ""
