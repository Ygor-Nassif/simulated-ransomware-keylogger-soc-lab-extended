from pathlib import Path
import tkinter as tk
from keylogger.logger import DEFAULT_KEYLOG_FILE, registrar_tecla
from ransomware.key_manager import registrar_evento

TITULO_JANELA = "Lab Keylogger Simulado (Escopo Restrito a Esta Janela)"


class JanelaCapturaSimulada:
    """Janela de teste local para demonstrar captura de teclado restrita à própria janela."""

    def __init__(self, root: tk.Tk, arquivo_log: Path = DEFAULT_KEYLOG_FILE) -> None:
        self.root = root
        self.arquivo_log = arquivo_log
        self.total_teclas = 0

        self.root.title(TITULO_JANELA)
        self.root.geometry("620x340")
        self.root.resizable(False, False)

        self._construir_interface()
        self.root.bind("<KeyPress>", self._ao_pressionar_tecla)
        self.root.protocol("WM_DELETE_WINDOW", self.encerrar)

        registrar_evento(
            modulo="keylogger.capture",
            acao="sessao_captura_iniciada",
            detalhes={"janela": TITULO_JANELA, "arquivo_log": str(self.arquivo_log)},
        )

    def _construir_interface(self) -> None:
        aviso = tk.Label(
            self.root,
            text=(
                "SIMULACAO EDUCACIONAL — Captura ativa APENAS enquanto esta janela estiver em foco.\n"
                "Digite textos ficticios abaixo para testar o registro com horario em logs/."
            ),
            wraplength=580,
            justify="left",
            padx=12,
            pady=10,
        )
        aviso.pack(anchor="w")

        self.area_digitacao = tk.Text(self.root, height=9, width=68)
        self.area_digitacao.pack(padx=12, pady=6)
        self.area_digitacao.focus_set()

        rodape = tk.Frame(self.root)
        rodape.pack(fill="x", padx=12, pady=8)

        self.lbl_contador = tk.Label(rodape, text="Teclas capturadas nesta janela: 0")
        self.lbl_contador.pack(side="left")

        btn_fechar = tk.Button(rodape, text="Encerrar e Salvar", command=self.encerrar)
        btn_fechar.pack(side="right")

    def _ao_pressionar_tecla(self, event: tk.Event) -> None:
        registrar_tecla(
            tecla=event.char,
            keysym=event.keysym,
            contexto_janela=TITULO_JANELA,
            arquivo_log=self.arquivo_log,
        )
        self.total_teclas += 1
        self.lbl_contador.config(text=f"Teclas capturadas nesta janela: {self.total_teclas}")

    def encerrar(self) -> None:
        registrar_evento(
            modulo="keylogger.capture",
            acao="sessao_captura_encerrada",
            detalhes={"janela": TITULO_JANELA, "total_teclas": self.total_teclas},
        )
        self.root.destroy()


def iniciar_janela_captura(arquivo_log: Path = DEFAULT_KEYLOG_FILE) -> None:
    """Inicializa e executa o loop da janela de captura simulada."""
    root = tk.Tk()
    JanelaCapturaSimulada(root=root, arquivo_log=arquivo_log)
    root.mainloop()


if __name__ == "__main__":
    iniciar_janela_captura()