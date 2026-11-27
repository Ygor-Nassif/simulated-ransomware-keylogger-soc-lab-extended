from datetime import datetime, timezone
import json
from pathlib import Path

from defense.detection import avaliar_comportamentos
from defense.indicators import extrair_indicadores
from ransomware.file_generator import LAB_TARGET_DIR, LOGS_DIR
from ransomware.key_manager import LOG_FILE, garantir_caminho_seguro, registrar_evento


DEFAULT_REPORT_FILE = (LOGS_DIR / "defense_report.json").resolve()

RECOMENDACOES_POR_REGRA = {
    "DET-RANSOM-001": [
        "Manter backups offline e imutáveis testados periodicamente.",
        "Monitorar alterações rápidas em lote de extensões/arquivos e criação de notas de resgate.",
        "Aplicar princípio do menor privilégio nos diretórios de dados sensíveis.",
    ],
    "DET-KEYLOG-001": [
        "Auditar processos com acesso a entradas de usuário e sessões interativas.",
        "Restringir execução de scripts não assinados ou fora de diretórios aprovados.",
        "Monitorar arquivos de log inesperados criados em diretórios de trabalho/logs.",
    ],
    "DET-PERSIST-001": [
        "Monitorar alterações em pontos de inicialização (serviços, tarefas agendadas, perfis de usuário).",
        "Comparar periodicamente o baseline de configurações e binários críticos.",
    ],
    "DET-EXFIL-001": [
        "Restringir conexões de saída (egress filtering) no firewall apenas a destinos e portas esperados.",
        "Inspecionar fluxos de rede anômalos ou volumes incomuns enviados a hosts internos/externos.",
        "Correlacionar eventos de leitura de logs/arquivos sensíveis com conexões de rede subsequentes.",
    ],
}


def calcular_nivel_risco(alertas: list[dict]) -> str:
    """Determina o nível geral de risco a partir das severidades dos alertas."""
    severidades = {alerta.get("severidade", "BAIXA") for alerta in alertas}
    if "ALTA" in severidades and len(alertas) >= 2:
        return "CRITICO"
    if "ALTA" in severidades:
        return "ALTO"
    if "MEDIA" in severidades:
        return "MODERADO"
    if alertas:
        return "BAIXO"
    return "SEM_ALERTAS"


def gerar_relatorio_defensivo(
    arquivo_log: Path = LOG_FILE,
    diretorio_alvo: Path = LAB_TARGET_DIR,
    arquivo_saida: Path = DEFAULT_REPORT_FILE,
) -> dict:
    """Consolida indicadores, alertas, mapeamento MITRE e recomendações em um relatório JSON."""
    indicadores = extrair_indicadores(arquivo_log=arquivo_log, diretorio_alvo=diretorio_alvo)
    deteccao = avaliar_comportamentos(arquivo_log=arquivo_log, diretorio_alvo=diretorio_alvo)
    alertas = deteccao.get("alertas", [])

    recomendacoes: list[str] = []
    tecnicas_mitre: list[dict] = []
    vistas_mitre: set[tuple[str, str]] = set()

    for alerta in alertas:
        regra_id = alerta.get("regra_id", "")
        for medida in RECOMENDACOES_POR_REGRA.get(regra_id, []):
            if medida not in recomendacoes:
                recomendacoes.append(medida)

        mitre = alerta.get("mitre_attack")
        if mitre:
            chave = (mitre.get("tecnica_id", ""), mitre.get("tecnica", ""))
            if chave not in vistas_mitre:
                vistas_mitre.add(chave)
                tecnicas_mitre.append(mitre)

    relatorio = {
        "gerado_em_utc": datetime.now(timezone.utc).isoformat(),
        "nivel_risco_geral": calcular_nivel_risco(alertas),
        "resumo_executivo": {
            "total_eventos_analisados": indicadores.get("total_eventos_log", 0),
            "total_alertas": deteccao.get("total_alertas", 0),
            "destinos_rede_observados": indicadores.get("destinos_rede_simulados", []),
            "total_teclas_sessoes": indicadores.get("total_teclas_registadas_em_sessoes", 0),
            "tecnicas_mitre_observadas": tecnicas_mitre,
        },
        "indicadores": indicadores,
        "deteccao": deteccao,
        "recomendacoes_mitigacao": recomendacoes,
    }

    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    destino_seguro = garantir_caminho_seguro(arquivo_saida, LOGS_DIR)
    destino_seguro.write_text(
        json.dumps(relatorio, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    registrar_evento(
        modulo="defense.analysis",
        acao="relatorio_defensivo_gerado",
        detalhes={
            "arquivo_relatorio": destino_seguro.name,
            "nivel_risco_geral": relatorio["nivel_risco_geral"],
            "total_alertas": len(alertas),
            "tecnicas_mitre": [t.get("tecnica_id") for t in tecnicas_mitre],
        },
    )
    return relatorio


if __name__ == "__main__":
    relatorio_final = gerar_relatorio_defensivo()
    print(f"Nível de risco geral: {relatorio_final['nivel_risco_geral']}")
    print(f"Total de alertas: {relatorio_final['resumo_executivo']['total_alertas']}")
    print("Técnicas MITRE ATT&CK observadas:")
    for tec in relatorio_final["resumo_executivo"]["tecnicas_mitre_observadas"]:
        print(f" - [{tec['tecnica_id']}] {tec['tecnica']} ({tec['tatica']} / {tec['tatica_id']})")
    print("Recomendações:")
    for rec in relatorio_final["recomendacoes_mitigacao"]:
        print(f" - {rec}")
    print(f"Relatório salvo em: {DEFAULT_REPORT_FILE}")