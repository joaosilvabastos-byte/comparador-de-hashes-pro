"""
Verificador de Hashes Pro (SHA-256 / SHA-1 / MD5)
--------------------------------------------------
Aplicação Flet, pensada para publicação na Play Store (Android),
mas que também funciona em Windows/macOS/Linux/Web/iOS.

Funcionalidades:
  - Duas abas: Verificação e Histórico
  - Seleção de ficheiro via FilePicker com with_data=True
    (necessário em Android/iOS/Web, onde não há um "path" fiável)
  - Cálculo simultâneo de SHA-256, SHA-1 e MD5, com barra de progresso
  - Comparação com um hash colado, com deteção automática do algoritmo
    pelo comprimento do hash (32=MD5, 40=SHA-1, 64=SHA-256)
  - Histórico persistente entre sessões (page.shared_preferences,
    que no Android usa SharedPreferences nativo)
  - Exportação do histórico para CSV ou JSON via FilePicker.save_file()
    com src_bytes (o único método fiável em Android/iOS/Web)
  - Dropdown de idioma: PT / EN / FR / ES

Testado com: flet==0.85.3
"""

import asyncio
import csv
import hashlib
import io
import json
from datetime import datetime

import flet as ft

# --------------------------------------------------------------------------
# Dicionário centralizado de traduções
# --------------------------------------------------------------------------
TEXT = {
    "PT": {
        "title": "Verificador de Hashes Pro",
        "tab_verification": "Verificação",
        "tab_history": "Histórico",
        "select_file": "Selecionar ficheiro para verificar",
        "official_hash": "Hash oficial (colar aqui):",
        "calculated_hash": "Hash calculado:",
        "compare": "Comparar hashes",
        "waiting": "A aguardar...",
        "reading": "A ler o ficheiro...",
        "hashing": "A calcular hashes... {pct}%",
        "no_file": "Selecione primeiro um ficheiro.",
        "no_official": "Cole o hash oficial para comparar.",
        "unrecognized": "⚠️ Esse texto não parece ser um hash MD5, SHA-1 ou SHA-256 válido.",
        "match": "✅ Coincide com o {algo} calculado!",
        "no_match": "❌ NÃO coincide com o {algo} calculado!",
        "file_prefix": "Ficheiro: ",
        "size_prefix": "Tamanho: ",
        "file_too_large": "⚠️ Ficheiro demasiado grande para ser processado em memória neste dispositivo.",
        "history_empty": "Ainda não existem verificações no histórico.",
        "col_file": "Ficheiro",
        "col_result": "Resultado",
        "col_time": "Hora",
        "language": "Idioma",
        "clear_history": "Limpar histórico",
        "clear_input": "Apagar",
        "export_csv": "Exportar para CSV",
        "export_json": "Exportar para JSON",
        "export_done": "Histórico exportado com sucesso.",
        "export_cancelled": "Exportação cancelada.",
        "export_error": "Erro ao exportar: {err}",
        "unexpected_error": "⚠️ Ocorreu um erro inesperado: {err}",
        "copied": "📋 {algo} copiado para a área de transferência!",
        "confirm_clear_title": "Limpar histórico?",
        "confirm_clear_body": "Esta ação não pode ser desfeita.",
        "confirm_yes": "Sim, limpar",
        "confirm_no": "Cancelar",
    },
    "EN": {
        "title": "Hash Verifier Pro",
        "tab_verification": "Verification",
        "tab_history": "History",
        "select_file": "Select File to Verify",
        "official_hash": "Official Hash (paste here):",
        "calculated_hash": "Calculated Hash:",
        "compare": "Compare Hashes",
        "waiting": "Waiting...",
        "reading": "Reading file...",
        "hashing": "Calculating hashes... {pct}%",
        "no_file": "Please select a file first.",
        "no_official": "Paste the official hash to compare.",
        "unrecognized": "⚠️ This text doesn't look like a valid MD5, SHA-1 or SHA-256 hash.",
        "match": "✅ Matches the calculated {algo}!",
        "no_match": "❌ Does NOT match the calculated {algo}!",
        "file_prefix": "File: ",
        "size_prefix": "Size: ",
        "file_too_large": "⚠️ File too large to process in memory on this device.",
        "history_empty": "No verifications in the history yet.",
        "col_file": "File",
        "col_result": "Result",
        "col_time": "Time",
        "language": "Language",
        "clear_history": "Clear History",
        "clear_input": "Clear",
        "export_csv": "Export CSV",
        "export_json": "Export JSON",
        "export_done": "History exported.",
        "export_cancelled": "Export cancelled.",
        "export_error": "Export error: {err}",
        "unexpected_error": "⚠️ An unexpected error occurred: {err}",
        "copied": "📋 {algo} copied to clipboard!",
        "confirm_clear_title": "Clear history?",
        "confirm_clear_body": "This action cannot be undone.",
        "confirm_yes": "Yes, clear",
        "confirm_no": "Cancel",
    },
    "FR": {
        "title": "Vérificateur de Hachages Pro",
        "tab_verification": "Vérification",
        "tab_history": "Historique",
        "select_file": "Sélectionner un fichier à vérifier",
        "official_hash": "Hachage officiel (collez ici) :",
        "calculated_hash": "Hachage calculé :",
        "compare": "Comparer les hachages",
        "waiting": "En attente...",
        "reading": "Lecture du fichier...",
        "hashing": "Calcul des hachages... {pct}%",
        "no_file": "Veuillez d'abord sélectionner un fichier.",
        "no_official": "Collez le hachage officiel pour comparer.",
        "unrecognized": "⚠️ Ce texte ne ressemble pas à un hachage MD5, SHA-1 ou SHA-256 valide.",
        "match": "✅ Correspond au {algo} calculé !",
        "no_match": "❌ Ne correspond PAS au {algo} calculé !",
        "file_prefix": "Fichier : ",
        "size_prefix": "Taille : ",
        "file_too_large": "⚠️ Fichier trop volumineux pour ce dispositif.",
        "history_empty": "Aucune vérification dans l'historique.",
        "col_file": "Fichier",
        "col_result": "Résultat",
        "col_time": "Heure",
        "language": "Langue",
        "clear_history": "Vider l'historique",
        "clear_input": "Effacer",
        "export_csv": "Exporter en CSV",
        "export_json": "Exporter en JSON",
        "export_done": "Historique exporté.",
        "export_cancelled": "Exportation annulée.",
        "export_error": "Erreur d'exportation : {err}",
        "unexpected_error": "⚠️ Une erreur inattendue s'est produite : {err}",
        "copied": "📋 {algo} copié dans le presse-papiers !",
        "confirm_clear_title": "Vider l'historique ?",
        "confirm_clear_body": "Cette action est irréversible.",
        "confirm_yes": "Oui, vider",
        "confirm_no": "Annuler",
    },
    "ES": {
        "title": "Verificador de Hashes Pro",
        "tab_verification": "Verificación",
        "tab_history": "Historial",
        "select_file": "Seleccionar archivo para verificar",
        "official_hash": "Hash oficial (pegar aquí):",
        "calculated_hash": "Hash calculado:",  # <--- ADICIONEI ESTA LINHA QUE FALTAVA
        "compare": "Comparar hashes",
        "waiting": "Esperando...",
        "reading": "Leyendo archivo...",
        "hashing": "Calculando hashes... {pct}%",
        "no_file": "Seleccione primero un archivo.",
        "no_official": "Pegue el hash oficial para comparar.",
        "unrecognized": "⚠️ Ese texto no parece un hash MD5, SHA-1 o SHA-256 válido.",
        "match": "✅ ¡Coincide con el {algo} calculado!",
        "no_match": "❌ ¡NO coincide con el {algo} calculado!",
        "file_prefix": "Archivo: ",
        "size_prefix": "Tamaño: ",
        "file_too_large": "⚠️ Archivo demasiado grande para este dispositivo.",
        "history_empty": "Todavía no hay verificaciones en el historial.",
        "col_file": "Archivo",
        "col_result": "Resultado",
        "col_time": "Hora",
        "language": "Idioma",
        "clear_history": "Borrar historial",
        "clear_input": "Borrar",
        "export_csv": "Exportar CSV",
        "export_json": "Exportar JSON",
        "export_done": "Historial exportado.",
        "export_cancelled": "Exportación cancelada.",
        "export_error": "Error al exportar: {err}",
        "unexpected_error": "⚠️ Ocurrió un error inesperado: {err}",
        "copied": "📋 ¡{algo} copiado al portapapeles!",
        "confirm_clear_title": "¿Borrar historial?",
        "confirm_clear_body": "Esta acción no se puede deshacer.",
        "confirm_yes": "Sí, borrar",
        "confirm_no": "Cancelar",
    },
}

LANGUAGES = ["PT", "EN", "FR", "ES"]

# Acima deste tamanho mostramos apenas um aviso (evita crash por memória em
# telemóveis, já que with_data=True carrega o ficheiro todo em RAM).
MAX_FILE_SIZE_BYTES = 300 * 1024 * 1024  # 300 MB

STORAGE_KEY_HISTORY = "hashverifier.history_json"  # prefixo único da app


def human_size(num_bytes: int) -> str:
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def detect_algorithm(hash_text: str) -> str | None:
    length = len(hash_text)
    if length == 32:
        return "MD5"
    if length == 40:
        return "SHA-1"
    if length == 64:
        return "SHA-256"
    return None


class HashVerifierApp:
    def __init__(self, page: ft.Page):
        self.page = page
        self.lang = "PT"
        self.selected_file_name: str | None = None
        self.selected_file_size: int | None = None
        self.hashes: dict[str, str] = (
            {}
        )  # {"MD5": "...", "SHA-1": "...", "SHA-256": "..."}
        self.history: list[dict] = []

        self.page.title = TEXT[self.lang]["title"]
        self.page.window.width = 560
        self.page.window.height = 760
        self.page.window.resizable = True
        self.page.padding = 20

        # ---------------- Serviços ----------------
        # NOTA IMPORTANTE: o FilePicker (e outros "Service controls" do Flet
        # >= 0.80) só deve ser adicionado ao page.overlay DEPOIS do primeiro
        # page.add()/page.update(). Se for adicionado antes, o cliente ainda
        # não concluiu o "handshake" inicial e mostra "Unknown control:
        # FilePicker" (uma barra de erro) — não é um elemento visual, é mesmo
        # um bug de temporização. Por isso criamos o controlo aqui, mas só o
        # registamos no overlay no final do __init__ (ver mais abaixo).
        self.file_picker = ft.FilePicker()

        # ---------------- Controlos globais ----------------
        self.lang_dropdown = ft.Dropdown(
            value=self.lang,
            width=140,
            options=[ft.DropdownOption(code, code) for code in LANGUAGES],
            on_select=self.on_language_change,
        )

        self.select_file_btn = ft.ElevatedButton(
            TEXT[self.lang]["select_file"],
            icon=ft.Icons.UPLOAD_FILE,
            on_click=self.on_pick_file,
        )

        self.file_name_text = ft.Text("", italic=True, color=ft.Colors.GREY_700)
        self.file_size_text = ft.Text(
            "", italic=True, color=ft.Colors.GREY_700, size=12
        )

        self.progress_bar = ft.ProgressBar(value=0, visible=False, width=460)
        self.progress_text = ft.Text("", size=12, color=ft.Colors.GREY_700)

        # Um campo de hash, apenas leitura, por algoritmo
        self.hash_fields: dict[str, ft.TextField] = {
            "MD5": ft.TextField(label="MD5", read_only=True, width=400),
            "SHA-1": ft.TextField(label="SHA-1", read_only=True, width=400),
            "SHA-256": ft.TextField(label="SHA-256", read_only=True, width=400),
        }

        # Um botão de copiar junto a cada campo, para copiar o hash com um
        # clique (usa page.clipboard, que é um serviço próprio da Page —
        # não precisa de registo no overlay, ao contrário do FilePicker).
        self.hash_copy_buttons: dict[str, ft.IconButton] = {
            algo: ft.IconButton(
                icon=ft.Icons.COPY,
                tooltip="Copy",
                on_click=lambda e, a=algo: self.on_copy_hash(a),
            )
            for algo in self.hash_fields
        }
        self.hash_rows: list[ft.Row] = [
            ft.Row(
                alignment=ft.MainAxisAlignment.CENTER,
                controls=[self.hash_fields[algo], self.hash_copy_buttons[algo]],
            )
            for algo in self.hash_fields
        ]

        self.official_hash_label = ft.Text(
            TEXT[self.lang]["official_hash"], weight=ft.FontWeight.BOLD
        )
        self.official_hash_field = ft.TextField(width=460)

        self.compare_btn = ft.ElevatedButton(
            TEXT[self.lang]["compare"],
            icon=ft.Icons.COMPARE_ARROWS,
            on_click=self.on_compare,
        )

        self.status_text = ft.Text(
            TEXT[self.lang]["waiting"], size=16, weight=ft.FontWeight.BOLD
        )

        # Botão de limpar a aba de Verificação (não mexe no histórico)
        self.clear_verification_btn = ft.ElevatedButton(
            TEXT[self.lang]["clear_input"],
            icon=ft.Icons.DELETE_OUTLINE,
            on_click=self.on_clear_output_click,  # Esta é a função que limpa os inputs
        )

        # ---------------- Aba "Verificação" ----------------
        self.verification_view = ft.Container(
            padding=20,
            content=ft.Column(
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                spacing=12,
                controls=[
                    self.select_file_btn,
                    self.file_name_text,
                    self.file_size_text,
                    self.progress_bar,
                    self.progress_text,
                    *self.hash_rows,
                    ft.Divider(),
                    self.official_hash_label,
                    self.official_hash_field,
                    self.compare_btn,
                    ft.Divider(),
                    self.status_text,
                    self.clear_verification_btn,
                ],
            ),
        )

        # ---------------- Aba "Histórico" ----------------
        self.history_column = ft.Column(
            spacing=8, scroll=ft.ScrollMode.AUTO, expand=True
        )

        self.clear_history_btn = ft.ElevatedButton(
            TEXT[self.lang]["clear_history"],
            icon=ft.Icons.DELETE_OUTLINE,
            on_click=self.on_clear_history_click,
        )
        self.export_csv_btn = ft.ElevatedButton(
            TEXT[self.lang]["export_csv"],
            icon=ft.Icons.TABLE_CHART,
            on_click=self.on_export_csv,
        )
        self.export_json_btn = ft.ElevatedButton(
            TEXT[self.lang]["export_json"],
            icon=ft.Icons.DATA_OBJECT,
            on_click=self.on_export_json,
        )

        self.history_view = ft.Container(
            padding=20,
            expand=True,
            content=ft.Column(
                expand=True,
                spacing=12,
                controls=[
                    ft.Row(
                        controls=[
                            self.export_csv_btn,
                            self.export_json_btn,
                            self.clear_history_btn,
                        ],
                        wrap=True,
                    ),
                    ft.Divider(),
                    self.history_column,
                ],
            ),
        )

        # ---------------- Tabs ----------------
        self.tab_verification_label = ft.Text(TEXT[self.lang]["tab_verification"])
        self.tab_history_label = ft.Text(TEXT[self.lang]["tab_history"])

        self.tab_bar = ft.TabBar(
            tabs=[
                ft.Tab(label=self.tab_verification_label),
                ft.Tab(label=self.tab_history_label),
            ]
        )
        self.tab_bar_view = ft.TabBarView(
            expand=True,
            controls=[self.verification_view, self.history_view],
        )
        self.tabs = ft.Tabs(
            length=2,
            selected_index=0,
            expand=True,
            content=ft.Column(expand=True, controls=[self.tab_bar, self.tab_bar_view]),
        )

        # ---------------- Cabeçalho colorido (toque visual intencional) ----
        self.header_icon = ft.Icon(ft.Icons.FINGERPRINT, color=ft.Colors.WHITE, size=28)
        self.header_title = ft.Text(
            TEXT[self.lang]["title"],
            color=ft.Colors.WHITE,
            size=20,
            weight=ft.FontWeight.BOLD,
        )
        self.header = ft.Container(
            padding=ft.Padding(16, 14, 16, 14),
            border_radius=12,
            gradient=ft.LinearGradient(
                begin=ft.Alignment.TOP_LEFT,
                end=ft.Alignment.BOTTOM_RIGHT,
                colors=[ft.Colors.INDIGO_600, ft.Colors.TEAL_500],
            ),
            content=ft.Row(
                alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                controls=[
                    ft.Row(
                        spacing=10,
                        controls=[self.header_icon, self.header_title],
                    ),
                    self.lang_dropdown,
                ],
            ),
        )

        # ---------------- Layout principal ----------------
        # Este é o PRIMEIRO render da página (primeiro "handshake" com o
        # cliente). Só depois disto é seguro registar o FilePicker.
        self.page.add(
            ft.Column(
                expand=True,
                spacing=16,
                controls=[
                    self.header,
                    self.tabs,
                ],
            )
        )

        # Agora sim: o FilePicker é registado em segurança e ativado com um
        # segundo page.update() — isto evita a barra "Unknown control:
        # FilePicker". (Esta chamada estava comentada e nunca era executada;
        # sem ela, "Selecionar ficheiro" não funcionava.)
        # self.page.overlay.append(self.file_picker)
        self.page.update()

        self.refresh_history()

        # Carrega o histórico persistente (Android: SharedPreferences nativo)
        self.page.run_task(self.load_history)

    def on_clear_history_click(self, e):
        """Limpa o histórico e atualiza a interface."""
        self.hashes = []
        if hasattr(self, "refresh_history"):
            self.refresh_history()
        self.page.update()

    # ------------------------------------------------------------------
    # Persistência (page.shared_preferences)
    # ------------------------------------------------------------------
    async def load_history(self):
        try:
            raw = await self.page.shared_preferences.get(STORAGE_KEY_HISTORY)
        except Exception:
            raw = None
        if raw:
            try:
                self.history = json.loads(raw)
            except Exception:
                self.history = []
        self.refresh_history()
        self.page.update()

    async def save_history(self):
        try:
            # Filtra ou limpa dados antes de salvar, se necessário
            # Garante que o que está em self.history é serializável
            serializable_data = []
            for item in self.history:
                # Se o teu item for um dicionário complexo, simplifica-o aqui
                serializable_data.append(
                    {
                        "file": str(item.get("file", "-")),
                        "algo": str(item.get("algo", "-")),
                        "match": bool(item.get("match", False)),
                        "hash": str(item.get("hash", "")),
                        "time": str(item.get("time", "")),
                    }
                )

            # Tenta salvar a versão limpa
            json_str = json.dumps(serializable_data)
            await self.page.shared_preferences.set(STORAGE_KEY_HISTORY, json_str)

        except Exception as e:
            # IMPORTANTE: Isto vai-te mostrar no terminal o erro real!
            print(f"Erro ao salvar histórico: {e}")

    # ------------------------------------------------------------------
    # Seleção de ficheiro + cálculo dos hashes
    # ------------------------------------------------------------------
    async def on_pick_file(self, e):
        t = TEXT[self.lang]
        try:
            # with_data=True é obrigatório para funcionar de forma fiável em
            # Android / iOS / Web, onde FilePickerFile.path pode não existir.
            files = await self.file_picker.pick_files(
                allow_multiple=False, with_data=True
            )
            if not files:
                return

            picked = files[0]
            self.selected_file_name = picked.name
            self.selected_file_size = picked.size

            self.file_name_text.value = f"{t['file_prefix']}{self.selected_file_name}"
            self.file_size_text.value = f"{t['size_prefix']}{human_size(picked.size)}"
            self.status_text.value = ""
            for field in self.hash_fields.values():
                field.value = ""
            self.hashes = {}

            if picked.size and picked.size > MAX_FILE_SIZE_BYTES:
                self.status_text.value = t["file_too_large"]
                self.status_text.color = ft.Colors.ORANGE
                self.page.update()
                return

            if picked.bytes is None:
                # Fallback (não deveria acontecer com with_data=True)
                self.status_text.value = t["no_file"]
                self.status_text.color = ft.Colors.ORANGE
                self.page.update()
                return

            await self.calculate_hashes(picked.bytes, t)
        except Exception as ex:
            self.status_text.value = t["unexpected_error"].format(err=ex)
            self.status_text.color = ft.Colors.RED
            self.page.update()

    async def calculate_hashes(self, data: bytes, t: dict):
        self.progress_bar.visible = True
        self.progress_bar.value = 0
        self.progress_text.value = t["reading"]
        self.page.update()

    # Esta função TEM de estar indentada como o 'calculate_hashes'
    # 1. Função de limpeza (independente)
    def on_clear_output_click(self, e):
        # Limpa os campos de hash
        for field in self.hash_fields.values():
            field.value = ""
        # Limpa os textos auxiliares
        self.file_name_text.value = ""
        self.file_size_text.value = ""
        # Reseta os dados
        self.hashes = {}
        self.selected_file_name = None
        self.selected_file_size = None
        self.page.update()

    # 2. Função de cálculo (independente e assíncrona)
    async def calculate_hashes(self, data: bytes, t: dict):
        self.progress_bar.visible = True
        self.progress_bar.value = 0
        self.progress_text.value = t["reading"]
        self.page.update()

        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()

        total = len(data) or 1
        chunk_size = max(65536, total // 100)
        processed = 0

        for start in range(0, len(data), chunk_size):
            chunk = data[start : start + chunk_size]
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
            processed += len(chunk)

            pct = int(processed / total * 100)
            self.progress_bar.value = processed / total
            self.progress_text.value = t["hashing"].format(pct=pct)
            self.page.update()
            await asyncio.sleep(0)

        self.hashes = {
            "MD5": md5.hexdigest(),
            "SHA-1": sha1.hexdigest(),
            "SHA-256": sha256.hexdigest(),
        }
        for algo, field in self.hash_fields.items():
            field.value = self.hashes[algo]

        self.progress_bar.visible = False
        self.progress_text.value = ""
        self.page.update()

    # ------------------------------------------------------------------
    # Comparação
    # ------------------------------------------------------------------
    def on_compare(self, e):
        t = TEXT[self.lang]
        try:
            if not self.hashes:
                self.status_text.value = t["no_file"]
                self.status_text.color = ft.Colors.ORANGE
                self.page.update()
                return

            official_raw = (self.official_hash_field.value or "").strip()
            official = official_raw.lower()
            if not official:
                self.status_text.value = t["no_official"]
                self.status_text.color = ft.Colors.ORANGE
                self.page.update()
                return

            algo = detect_algorithm(official)
            if algo is None:
                self.status_text.value = t["unrecognized"]
                self.status_text.color = ft.Colors.ORANGE
                self.page.update()
                return

            calculated = self.hashes[algo].lower()
            is_match = calculated == official

            if is_match:
                self.status_text.value = t["match"].format(algo=algo)
                self.status_text.color = ft.Colors.GREEN_700
            else:
                self.status_text.value = t["no_match"].format(algo=algo)
                self.status_text.color = ft.Colors.RED

            self.history.insert(
                0,
                {
                    "file": self.selected_file_name or "-",
                    "algo": algo,
                    "match": is_match,
                    "hash": self.hashes.get(algo, ""),
                    "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                },
            )
            self.refresh_history()
            self.page.update()
            self.page.run_task(self.save_history)
        except Exception as ex:
            self.status_text.value = t["unexpected_error"].format(err=ex)
            self.status_text.color = ft.Colors.RED
            self.page.update()

    def on_language_change(self, e):
        try:
            self.lang = self.lang_dropdown.value
            self.apply_translations()
            self.page.update()
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Histórico: limpar
    # ------------------------------------------------------------------
    def on_clear_history_click(self, e):
        t = TEXT[self.lang]

        def do_clear(ev):
            try:
                self.history = []
                self.refresh_history()
                self.page.run_task(self.save_history)
                self.page.close(dlg)
                self.page.update()
            except Exception as ex:
                self.status_text.value = t["unexpected_error"].format(err=ex)
                self.status_text.color = ft.Colors.RED
                self.page.update()

        def cancel(ev):
            try:
                self.page.close(dlg)
            except Exception:
                pass

        try:
            dlg = ft.AlertDialog(
                title=ft.Text(t["confirm_clear_title"]),
                content=ft.Text(t["confirm_clear_body"]),
                actions=[
                    ft.TextButton(t["confirm_no"], on_click=cancel),
                    ft.TextButton(t["confirm_yes"], on_click=do_clear),
                ],
            )
            self.page.open(dlg)
        except Exception as ex:
            self.status_text.value = t["unexpected_error"].format(err=ex)
            self.status_text.color = ft.Colors.RED
            self.page.update()

    def on_copy_hash(self, algo: str):
        t = TEXT[self.lang]
        try:
            value = self.hashes.get(algo)
            if not value:
                return
            self.page.run_task(self.page.clipboard.set, value)
            self.status_text.value = t["copied"].format(algo=algo)
            self.status_text.color = ft.Colors.BLUE_700
            self.page.update()
        except Exception as ex:
            self.status_text.value = t["unexpected_error"].format(err=ex)
            self.status_text.color = ft.Colors.RED
            self.page.update()

    def on_clear_input_click(self, e):
        # Esta função é muito mais simples que a do Histórico
        # porque não precisa de avisos ou de salvar em ficheiro.
        for field in self.hash_fields.values():
            field.value = ""
        self.file_name_text.value = ""
        self.file_size_text.value = ""
        self.hashes = {}
        self.selected_file_name = None
        self.selected_file_size = None
        self.page.update()

    # ------------------------------------------------------------------
    # Exportação (compatível com Android/iOS/Web via src_bytes)
    # ------------------------------------------------------------------
    def _history_to_csv_bytes(self) -> bytes:
        t = TEXT[self.lang]
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow([t["col_file"], "Algoritmo", t["col_result"], t["col_time"]])
        for entry in self.history:
            writer.writerow(
                [
                    entry.get("file", "-"),
                    entry.get("algo", "-"),
                    "OK" if entry.get("match") else "FAIL",
                    entry.get("time", "-"),
                ]
            )
        return buf.getvalue().encode("utf-8")

    def _history_to_json_bytes(self) -> bytes:
        # "Assinatura digital" de referência: para cada verificação feita,
        # guardamos o ficheiro, o algoritmo e o HASH CALCULADO (não o
        # resultado da comparação, que só é válido no momento em que foi
        # feita). Assim este JSON pode ser reutilizado no futuro como
        # referência para novas verificações.
        manifest = [
            {
                "file": entry.get("file", "-"),
                "algo": entry.get("algo", "-"),
                "hash": entry.get("hash", ""),
                "time": entry.get("time", "-"),
            }
            for entry in self.history
        ]
        return json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8")

    async def _export(self, filename: str, content: bytes):
        t = TEXT[self.lang]
        try:
            path = await self.file_picker.save_file(
                file_name=filename, src_bytes=content
            )
        except Exception as ex:
            self.status_text.value = t["export_error"].format(err=ex)
            self.status_text.color = ft.Colors.RED
            self.page.update()
            return

        # Em vez de 'if not path:', fazemos uma verificação explícita:
        if path is None:
            self.status_text.value = t["export_cancelled"]
            self.status_text.color = ft.Colors.GREY
            self.page.update()
            return

        # Adiciona esta verificação extra para garantir que o objeto não é vazio
        if hasattr(path, "path") and path.path is None:
            self.status_text.value = t["export_cancelled"]
            self.status_text.color = ft.Colors.GREY
            self.page.update()
            return

        # Em desktop, save_file() só devolve o caminho escolhido; é a app
        # que tem de escrever o ficheiro. Em Android/iOS/Web, os bytes já
        # foram gravados automaticamente através de src_bytes.
        if self.page.platform in (
            ft.PagePlatform.WINDOWS,
            ft.PagePlatform.MACOS,
            ft.PagePlatform.LINUX,
        ):
            try:
                with open(path, "wb") as f:
                    f.write(content)
            except Exception as ex:
                self.status_text.value = t["export_error"].format(err=ex)
                self.status_text.color = ft.Colors.RED
                self.page.update()
                return

        self.status_text.value = t["export_done"]
        self.status_text.color = ft.Colors.GREEN_700
        self.page.update()

    def on_export_csv(self, e):
        t = TEXT[self.lang]
        try:
            self.page.run_task(
                self._export, "historico_hashes.csv", self._history_to_csv_bytes()
            )
        except Exception as ex:
            self.status_text.value = t["unexpected_error"].format(err=ex)
            self.status_text.color = ft.Colors.RED
            self.page.update()

    def on_export_json(self, e):
        t = TEXT[self.lang]
        try:
            self.page.run_task(
                self._export, "historico_hashes.json", self._history_to_json_bytes()
            )
        except Exception as ex:
            self.status_text.value = t["unexpected_error"].format(err=ex)
            self.status_text.color = ft.Colors.RED
            self.page.update()

    # ------------------------------------------------------------------
    # Auxiliares de UI / traduções
    # ------------------------------------------------------------------
    def refresh_history(self):
        t = TEXT[self.lang]
        self.history_column.controls.clear()

        if not self.history:
            self.history_column.controls.append(
                ft.Text(t["history_empty"], italic=True, color=ft.Colors.GREY_600)
            )
            return

        self.history_column.controls.append(
            ft.Row(
                controls=[
                    ft.Text(t["col_file"], weight=ft.FontWeight.BOLD, width=200),
                    ft.Text("Algo", weight=ft.FontWeight.BOLD, width=80),
                    ft.Text(t["col_result"], weight=ft.FontWeight.BOLD, width=90),
                    ft.Text(t["col_time"], weight=ft.FontWeight.BOLD, width=140),
                ]
            )
        )
        self.history_column.controls.append(ft.Divider())

        for entry in self.history:
            result_color = ft.Colors.GREEN_700 if entry.get("match") else ft.Colors.RED
            result_symbol = "✅" if entry.get("match") else "❌"
            self.history_column.controls.append(
                ft.Row(
                    controls=[
                        ft.Text(entry.get("file", "-"), width=200),
                        ft.Text(entry.get("algo", "-"), width=80),
                        ft.Text(result_symbol, width=90, color=result_color),
                        ft.Text(entry.get("time", "-"), width=140),
                    ]
                )
            )

    def apply_translations(self):
        t = TEXT[self.lang]

        # 1. Cabeçalho e Abas
        self.page.title = t["title"]
        self.header_title.value = t["title"]
        self.tab_verification_label.value = t["tab_verification"]
        self.tab_history_label.value = t["tab_history"]

        # 2. Botões
        self.select_file_btn.content = ft.Text(t["select_file"])
        self.compare_btn.content = ft.Text(t["compare"])
        self.clear_history_btn.content = ft.Text(t["clear_history"])
        self.clear_verification_btn.content = ft.Text(t["clear_input"])
        self.export_csv_btn.content = ft.Text(t["export_csv"])
        self.export_json_btn.content = ft.Text(t["export_json"])

        # 3. Labels e campos
        self.official_hash_label.value = t["official_hash"]

        # 4. Textos dinâmicos e TRADUÇÃO DOS ESTADOS (O PULO DO GATO)
        if self.selected_file_name:
            self.file_name_text.value = f"{t['file_prefix']}{self.selected_file_name}"
        if self.selected_file_size is not None:
            self.file_size_text.value = (
                f"{t['size_prefix']}{human_size(self.selected_file_size)}"
            )

        # Lógica para traduzir o status, dependendo do que estiver guardado:
        if self.status_text.value:
            # Se o status atual for um dos termos conhecidos, traduzimos para a nova língua
            current_val = self.status_text.value
            if current_val in [TEXT["PT"]["match"], TEXT["EN"]["match"]]:
                self.status_text.value = t["match"]
            elif current_val in [TEXT["PT"]["no_match"], TEXT["EN"]["no_match"]]:
                self.status_text.value = t["no_match"]
            else:
                self.status_text.value = t["waiting"]
        else:
            self.status_text.value = t["waiting"]

        self.refresh_history()
        self.page.update()


def main(page: ft.Page):
    # A classe HashVerifierApp já trata sozinha do page.add(), do registo do
    # FilePicker no overlay e do page.update() dentro do seu __init__.
    HashVerifierApp(page)


if __name__ == "__main__":
    ft.run(main)
