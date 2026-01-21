-- migration_v1.1.sql - 기존 DB 마이그레이션
-- 기존 테이블에 새 컬럼 추가

-- service_type 컬럼 추가 (ssh 또는 other)
ALTER TABLE port_forwarding_rules ADD COLUMN IF NOT EXISTS service_type VARCHAR(20) DEFAULT 'other';

-- is_persistent 컬럼 추가 (재시작 시 복구 여부)
ALTER TABLE port_forwarding_rules ADD COLUMN IF NOT EXISTS is_persistent BOOLEAN DEFAULT TRUE;

-- 인덱스 추가
CREATE INDEX IF NOT EXISTS idx_service_type ON port_forwarding_rules(service_type);
CREATE INDEX IF NOT EXISTS idx_vm_id ON port_forwarding_rules(user_vm_id);

-- 기존 SSH 포트(22) 규칙을 ssh 타입으로 업데이트
UPDATE port_forwarding_rules 
SET service_type = 'ssh' 
WHERE user_vm_internal_port = 22 AND service_type = 'other';
