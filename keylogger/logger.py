from datetime import datetime, timezone
from pathlib import Path
from ransomware.key_manager import LOGS_DIR, garantir_caminho_seguro, registrar_evento


DEFAULT_KEYLOG_FILE = (LOGS_DIR / "keylogger_simulado.txt").resolve()


class KeyloggerError(Exception):
    """Exceção específica para falhas no módulo de keylogger simulado."""


def formatar_tecla(tecla: str, keysym: str | None = None) -> str:
    """Padroniza a representação de teclas comuns e especiais para o log."""
    mapa_especiais = {
        "Return": "[ENTER]",
        "BackSpace": "[BACKSPACE]",
        "space": "[SPACE]",
        "Tab": "[TAB]",
        "Escape": "[ESC]",
        "Shift_L": "[SHIFT]",
        "Shift_R": "[SHIFT]",
        "Control_L": "[CTRL]",
        "Control_R": "[CTRL]",
        "Alt_L": "[ALT]",
        "Alt_R": "[ALT]",
    }
    if keysym and keysym in mapa_especiais:
        return mapa_especiais[keysym]
    if tecla == " ":
        return "[SPACE]"
    if tecla == "\r" or tecla == "\n":
        return "[ENTER]"
    if tecla == "\t":
        return "[TAB]"
    if tecla and tecla.isprintable():
        return tecla
    return f"[{keysym or 'TECLA_NAO_IMPRIMIVEL'}]"


def registrar_tecla(
    tecla: str,
    keysym: str | None = None,
    contexto_janela: str = "JanelaTesteKeylogger",
    arquivo_log: Path = DEFAULT_KEYLOG_FILE,
) -> Path:
    """Registra uma tecla capturada dentro da janela de teste com carimbo de horário."""
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    destino = garantir_caminho_seguro(arquivo_log, LOGS_DIR)

    agora = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    tecla_formatada = formatar_tecla(tecla, keysym=keysym)
    linha = f"[{agora}] [janela={contexto_janela}] tecla={tecla_formatada}\n"

    try:
        with destino.open("a", encoding="utf-8") as f:
            f.write(linha)
        return destino
    except OSError as exc:
        registrar_evento(
            modulo="keylogger.logger",
            acao="registrar_tecla_erro",
            detalhes={"arquivo": destino.name, "erro": str(exc)},
        )
        raise KeyloggerError(f"Falha ao escrever no log do keylogger simulado: {exc}") from exc


if __name__ == "__main__":
    caminho_gerado = registrar_tecla("a", keysym="a", contexto_janela="TesteInicial")
    registrar_tecla("", keysym="Return", contexto_janela="TesteInicial")
    registrar_evento(
        modulo="keylogger.logger",
        acao="teste_unitario_logger",
        detalhes={"arquivo_log": caminho_gerado.name},
    )
    print(f"Registro de teste salvo em: {caminho_gerado}")
    print(caminho_gerado.read_text(encoding="utf-8"))