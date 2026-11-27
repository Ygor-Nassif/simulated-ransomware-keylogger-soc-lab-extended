from pathlib import Path
from defense.indicators import extrair_indicadores
from ransomware.file_generator import LAB_TARGET_DIR
from ransomware.key_manager import LOG_FILE


def avaliar_comportamentos(
    arquivo_log: Path = LOG_FILE,
    diretorio_alvo: Path = LAB_TARGET_DIR,
) -> dict:
    indicadores = extrair_indicadores(
        arquivo_log=arquivo_log,
        diretorio_alvo=diretorio_alvo,
    )

    por_acao = indicadores.get("por_acao", {})
    artefactos = indicadores.get("artefactos", {})
    artefactos_logs = artefactos.get("artefactos_logs", {})

    arquivos_enc = artefactos.get("ficheiros_cifrados_enc", [])
    nota_resgate = bool(artefactos.get("nota_resgate_presente", False))
    acoes_cifragem = int(por_acao.get("criptografar_arquivo_sucesso", 0)) + int(
        por_acao.get("execucao_cifragem_concluida", 0)
    )

    teclas_sessoes = int(indicadores.get("total_teclas_registadas_em_sessoes", 0))
    log_teclas_presente = bool(artefactos_logs.get("keylogger_simulado_txt", False))

    acoes_persistencia = int(por_acao.get("simular_persistencia_sucesso", 0))
    persistencia_arquivo = bool(artefactos_logs.get("sim_persistence_json", False))

    destinos_rede = indicadores.get("destinos_rede_simulados", [])
    transmissoes_sem_receptor = int(por_acao.get("simular_transmissao_sem_receptor", 0))
    transmissoes_sucesso = int(por_acao.get("simular_transmissao_sucesso", 0))

    alertas = []

    if arquivos_enc or nota_resgate or acoes_cifragem > 0:
        alertas.append(
            {
                "regra_id": "DET-RANSOM-001",
                "severidade": "CRITICA",
                "titulo": "Cifragem de arquivos ou nota de resgate observada em laboratório",
                "mitre_attack": {
                    "tatica": "Impact",
                    "tatica_id": "TA0040",
                    "tecnica": "Data Encrypted for Impact",
                    "tecnica_id": "T1486",
                },
                "evidencias": {
                    "arquivos_cifrados_enc": arquivos_enc,
                    "nota_resgate_presente": nota_resgate,
                    "acoes_cifragem_log": acoes_cifragem,
                },
            }
        )

    if teclas_sessoes > 0 or log_teclas_presente:
        alertas.append(
            {
                "regra_id": "DET-KEYLOG-001",
                "severidade": "MEDIA",
                "titulo": "Registro de entradas de teclado observado em sessão simulada",
                "mitre_attack": {
                    "tatica": "Collection",
                    "tatica_id": "TA0009",
                    "tecnica": "Input Capture (GUI Input Capture)",
                    "tecnica_id": "T1056.002",
                },
                "evidencias": {
                    "total_teclas_sessoes": teclas_sessoes,
                    "log_teclas_presente": log_teclas_presente,
                },
            }
        )

    if acoes_persistencia > 0 or persistencia_arquivo:
        alertas.append(
            {
                "regra_id": "DET-PERSIST-001",
                "severidade": "ALTA",
                "titulo": "Simulação de mecanismo de persistência registrada",
                "mitre_attack": {
                    "tatica": "Persistence",
                    "tatica_id": "TA0003",
                    "tecnica": "Boot or Logon Autostart Execution",
                    "tecnica_id": "T1547",
                },
                "evidencias": {
                    "acoes_persistencia_log": acoes_persistencia,
                    "sim_persistence_json_presente": persistencia_arquivo,
                },
            }
        )

    if destinos_rede or transmissoes_sem_receptor > 0 or transmissoes_sucesso > 0:
        alertas.append(
            {
                "regra_id": "DET-EXFIL-001",
                "severidade": "ALTA",
                "titulo": "Tentativa ou ocorrência de transmissão de dados simulada em rede",
                "mitre_attack": {
                    "tatica": "Exfiltration",
                    "tatica_id": "TA0010",
                    "tecnica": "Exfiltration Over Alternative Protocol",
                    "tecnica_id": "T1048",
                },
                "evidencias": {
                    "transmissoes_sucesso": transmissoes_sucesso,
                    "transmissoes_sem_receptor": transmissoes_sem_receptor,
                    "destinos_observados": destinos_rede,
                },
            }
        )

    return {
        "total_alertas": len(alertas),
        "alertas": alertas,
    }