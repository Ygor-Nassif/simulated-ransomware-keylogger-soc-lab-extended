# Relatório de Análise Defensiva e MITRE ATT&CK

- **Gerado em (UTC):** `2026-11-27T10:40:08.810849+00:00`

## Resumo Executivo

- **Nível de risco geral:** `CRITICO`
- **Total de eventos analisados:** `11`
- **Total de alertas:** `3`

## Técnicas MITRE ATT&CK Observadas

- **[T1486]** Data Encrypted for Impact (Impact / `TA0040`)
- **[T1547]** Boot or Logon Autostart Execution (Persistence / `TA0003`)
- **[T1048]** Exfiltration Over Alternative Protocol (Exfiltration / `TA0010`)

## Alertas Detalhados

### DET-RANSOM-001 — Cifragem de arquivos ou nota de resgate observada em laboratório

- **Severidade:** `CRITICA`
- **Técnica MITRE:** `[T1486]` Data Encrypted for Impact
- **Tática MITRE:** Impact (`TA0040`)

### DET-PERSIST-001 — Simulação de mecanismo de persistência registrada

- **Severidade:** `ALTA`
- **Técnica MITRE:** `[T1547]` Boot or Logon Autostart Execution
- **Tática MITRE:** Persistence (`TA0003`)

### DET-EXFIL-001 — Tentativa ou ocorrência de transmissão de dados simulada em rede

- **Severidade:** `ALTA`
- **Técnica MITRE:** `[T1048]` Exfiltration Over Alternative Protocol
- **Tática MITRE:** Exfiltration (`TA0010`)

## Recomendações de Mitigação

- Manter backups offline e imutáveis testados periodicamente.
- Monitorar alterações rápidas em lote de extensões/arquivos e criação de notas de resgate.
- Aplicar princípio do menor privilégio nos diretórios de dados sensíveis.
- Monitorar alterações em pontos de inicialização (serviços, tarefas agendadas, perfis de usuário).
- Comparar periodicamente o baseline de configurações e binários críticos.
- Restringir conexões de saída (egress filtering) no firewall apenas a destinos e portas esperados.
- Inspecionar fluxos de rede anômalos ou volumes incomuns enviados a hosts internos/externos.
- Correlacionar eventos de leitura de logs/arquivos sensíveis com conexões de rede subsequentes.
