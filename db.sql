-- Script de criação do banco de dados EcoBat
-- Execute como superusuário PostgreSQL primeiro:
-- CREATE DATABASE ecobat;
-- CREATE USER ecobat WITH PASSWORD 'db-p@ssw0rd';
-- GRANT ALL PRIVILEGES ON DATABASE ecobat TO ecobat;

-- Conecte ao banco ecobat como usuário ecobat e execute:

-- Tabela para armazenar pacotes de rede
CREATE TABLE IF NOT EXISTS packets (
    id BIGSERIAL PRIMARY KEY,
    node_id VARCHAR(32) NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,  -- Changed from DOUBLE PRECISION to TIMESTAMPTZ
    src_ip INET NOT NULL,
    dst_ip INET,
    protocol VARCHAR(10),  -- Changed from SMALLINT to VARCHAR to accept protocol names
    length INTEGER,
    created_at TIMESTAMP DEFAULT NOW(),
    location_country CHAR(2),
    location_city VARCHAR(100)
);

-- Índices para consultas rápidas
CREATE INDEX IF NOT EXISTS idx_packets_src_ip ON packets(src_ip);
CREATE INDEX IF NOT EXISTS idx_packets_dst_ip ON packets(dst_ip);
CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets(timestamp);
CREATE INDEX IF NOT EXISTS idx_packets_node_id ON packets(node_id);

-- Tabela para alertas de segurança
CREATE TABLE IF NOT EXISTS alerts (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    node_id VARCHAR(32),
    type VARCHAR(50) NOT NULL,
    severity VARCHAR(10) NOT NULL,
    src_ip INET,
    dst_ip INET,
    description TEXT,
    acknowledged BOOLEAN DEFAULT FALSE,
    acknowledged_by VARCHAR(100),
    acknowledged_at TIMESTAMP
);

-- Índices para alertas
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_src_ip ON alerts(src_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(type);

-- Tabela para IPs anômalos conhecidos (honeypots, darknets, etc.)
CREATE TABLE IF NOT EXISTS anomalous_ips (
    id BIGSERIAL PRIMARY KEY,
    ip INET NOT NULL UNIQUE,
    type VARCHAR(50) NOT NULL,
    description TEXT,
    first_seen TIMESTAMPTZ DEFAULT NOW(),
    last_seen TIMESTAMPTZ DEFAULT NOW(),
    confidence SMALLINT DEFAULT 50
);

-- Tabela para estatísticas agregadas
CREATE TABLE IF NOT EXISTS stats_aggregated (
    id BIGSERIAL PRIMARY KEY,
    time_period TIMESTAMPTZ NOT NULL,
    period_type VARCHAR(10) NOT NULL, -- 'minute', 'hour', 'day'
    src_ip INET,
    packet_count INTEGER,
    avg_packet_size FLOAT,
    protocols JSONB,
    top_destinations JSONB
);

-- Tabela de nós do cluster
CREATE TABLE IF NOT EXISTS nodes (
    node_id VARCHAR(32) PRIMARY KEY,
    hostname VARCHAR(255) NOT NULL,
    ip_address INET,
    last_seen TIMESTAMPTZ,
    status VARCHAR(20),
    location VARCHAR(100),
    metadata JSONB
);

-- Função para atualizar last_seen automaticamente
CREATE OR REPLACE FUNCTION update_last_seen()
RETURNS TRIGGER AS $$
BEGIN
    NEW.last_seen = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Gatilho para atualizar last_seen em anomalous_ips
CREATE TRIGGER update_anomalous_ip_last_seen
BEFORE UPDATE ON anomalous_ips
FOR EACH ROW
EXECUTE FUNCTION update_last_seen();

-- Visualização para estatísticas de protocolos
CREATE OR REPLACE VIEW protocol_stats AS
SELECT 
    protocol,
    COUNT(*) as packet_count,
    AVG(length) as avg_length,
    MIN(timestamp) as first_seen,
    MAX(timestamp) as last_seen
FROM packets
GROUP BY protocol
ORDER BY packet_count DESC;

-- Visualização para top talkers
CREATE OR REPLACE VIEW top_talkers AS
SELECT 
    src_ip,
    COUNT(*) as packet_count,
    COUNT(DISTINCT dst_ip) as unique_destinations,
    AVG(length) as avg_length
FROM packets
GROUP BY src_ip
ORDER BY packet_count DESC
LIMIT 100;

-- Visualização para alertas não reconhecidos
CREATE OR REPLACE VIEW unacknowledged_alerts AS
SELECT *
FROM alerts
WHERE acknowledged = FALSE
ORDER BY timestamp DESC;

-- Permissões
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO ecobat;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO ecobat;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO ecobat;