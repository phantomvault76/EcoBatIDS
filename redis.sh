#! /bin/bash 
# Configurar limites padrão (ajuste conforme necessário)
redis-cli HMSET thresholds distributed_port_scan 50 min_scan_nodes 3 syn_flood 100 distributed_syn_flood 500 fan_out 5

# Configurar tempo de expiração padrão para chaves temporárias (em segundos)
redis-cli SET scan_key_expire 3600
redis-cli SET alert_key_expire 86400