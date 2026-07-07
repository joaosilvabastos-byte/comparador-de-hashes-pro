"""
Verificador SHA-256 Pro
-----------------------
Aplicação Flet (compatível com Flet >= 0.80 / API "V1") com:
  - Duas abas: Verificação e Histórico
  - Seleção de ficheiro + cálculo automático do hash SHA-256
  - Campo para colar o hash oficial e comparação
  - Dropdown de idioma: PT / EN / FR / ES
  - Histórico das verificações efetuadas nesta sessão

Testado com: flet==0.85.3
"""

import hashlib
from datetime import datetime

import flet as ft

# --------------------------------------------------------------------------
# Dicionário centralizado de traduções
# --------------------------------------------------------------------------
TEXT = {
    "PT": {
        "title": "Verificador SHA-256 Pro",
        "tab_verification": "Verificação",
        "tab_history": "Histórico",
        "select_file": "Selecionar Ficheiro para Verificar",
        "calculated_hash": "Hash Calculado:",
        "official_hash": "Hash Oficial (Colar aqui):",
        "compare": "Comparar Hashes",
        "waiting": "Aguardando...",
        "calculating": "A calcular hash...",
        "no_file": "Selecione primeiro um ficheiro.",
        "no_official": "Cole o hash oficial para comparar.",
        "match": "✅ Os hashes coincidem!",
        "no_match": "❌ Os hashes NÃO coincidem!",
        "file_prefix": "Ficheiro: ",
        "history_empty": "Ainda não existem verificações no histórico.",
        "col_file": "Ficheiro",
        "col_result": "Resultado",
        "col_time": "Hora",
        "language": "Idioma",
    },
    "EN": {
        "title": "SHA-256 Verifier Pro",
        "tab_verification": "Verification",
        "tab_history": "History",
        "select_file": "Select File to Verify",
        "calculated_hash": "Calculated Hash:",
        "official_hash": "Official Hash (paste here):",
        "compare": "Compare Hashes",
        "waiting": "Waiting...",
        "calculating": "Calculating hash...",
        "no_file": "Please select a file first.",
        "no_official": "Paste the official hash to compare.",
        "match": "✅ The hashes match!",
        "no_match": "❌ The hashes DO NOT match!",
        "file_prefix": "File: ",
        "history_empty": "No verifications in the history yet.",
        "col_file": "File",
        "col_result": "Result",
        "col_time": "Time",
        "language": "Language",
    },
    "FR": {
        "title": "Vérificateur SHA-256 Pro",
        "tab_verification": "Vérification",
        "tab_history": "Historique",
        "select_file": "Sélectionner un fichier à vérifier",
        "calculated_hash": "Hachage calculé :",
        "official_hash": "Hachage officiel (collez ici) :",
        "compare": "Comparer les hachages",
        "waiting": "En attente...",
        "calculating": "Calcul du hachage...",
        "no_file": "Veuillez d'abord sélectionner un fichier.",
        "no_official": "Collez le hachage officiel pour comparer.",
        "match": "✅ Les hachages correspondent !",
        "no_match": "❌ Les hachages NE correspondent PAS !",
        "file_prefix": "Fichier : ",
        "history_empty": "Aucune vérification dans l'historique.",
        "col_file": "Fichier",
        "col_result": "Résultat",
        "col_time": "Heure",
        "language": "Langue",
    },
    "ES": {
        "title": "Verificador SHA-256 Pro",
        "tab_verification": "Verificación",
        "tab_history": "Historial",
        "select_file": "Seleccionar archivo para verificar",
        "calculated_hash": "Hash calculado:",
        "official_hash": "Hash oficial (pegar aquí):",
        "compare": "Comparar hashes",
        "waiting": "Esperando...",
        "calculating": "Calculando hash...",
        "no_file": "Seleccione primero un archivo.",
        "no_official": "Pegue el hash oficial para comparar.",
        "match": "✅ ¡Los hashes coinciden!",
        "no_match": "❌ ¡Los hashes NO coinciden!",
        "file_prefix": "Archivo: ",
        "history_empty": "Todavía no hay verificaciones en el historial.",
        "col_file": "Archivo",
        "col_result": "Resultado",
        "col_time": "Hora",
        "language": "Idioma",
    },
}

LANGUAGES = ["PT", "EN", "FR", "ES"]


def calculate_sha256(file_path: str) -> str:
    """Calcula o hash SHA-256 de um ficheiro, lendo-o em blocos."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


class SHA256VerifierApp:
    def __init__(self, page: ft.Page):
        self.page = page
        self.lang = "PT"
        self.selected_file_path: str | None = None
        self.selected_file_name: str | None = None
        self.history: list[dict] = []

        self.page.title = TEXT[self.lang]["title"]
        self.page.window.width = 560
        self.page.window.height = 680
        self.page.window.resizable = True
        self.page.padding = 20

        # ---------------- Controlos ----------------
        self.file_picker = ft.FilePicker()
        self.page.overlay.append(self.file_picker)

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

        self.calculated_hash_label = ft.Text(
            TEXT[self.lang]["calculated_hash"], weight=ft.FontWeight.BOLD
        )
        self.calculated_hash_field = ft.TextField(
            read_only=True,
            width=460,
        )

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
            TEXT[self.lang]["waiting"],
            size=16,
            weight=ft.FontWeight.BOLD,
        )

        self.file_name_text = ft.Text("", italic=True, color=ft.Colors.GREY_700)

        # ---------------- Aba "Verificação" ----------------
        self.verification_view = ft.Container(
            padding=20,
            content=ft.Column(
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                spacing=14,
                controls=[
                    self.select_file_btn,
                    self.file_name_text,
                    self.calculated_hash_label,
                    self.calculated_hash_field,
                    self.official_hash_label,
                    self.official_hash_field,
                    self.compare_btn,
                    ft.Divider(),
                    self.status_text,
                ],
            ),
        )

        # ---------------- Aba "Histórico" ----------------
        self.history_column = ft.Column(spacing=8, scroll=ft.ScrollMode.AUTO)
        self.history_view = ft.Container(
            padding=20,
            content=self.history_column,
        )
        self.refresh_history()

        # ---------------- Tabs (API Flet v1: Tabs -> TabBar + TabBarView) ----------------
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
            content=ft.Column(
                expand=True,
                controls=[self.tab_bar, self.tab_bar_view],
            ),
        )

        # ---------------- Layout principal ----------------
        self.page.add(
            ft.Row(
                alignment=ft.MainAxisAlignment.END,
                controls=[
                    ft.Text(TEXT[self.lang]["language"] + ":"),
                    self.lang_dropdown,
                ],
            ),
            self.tabs,
        )

    # ----------------------------------------------------------------
    # Eventos
    # ----------------------------------------------------------------
    async def on_pick_file(self, e):
        files = await self.file_picker.pick_files(allow_multiple=False)
        if not files:
            return

        picked = files[0]
        self.selected_file_path = picked.path
        self.selected_file_name = picked.name

        t = TEXT[self.lang]
        self.file_name_text.value = f"{t['file_prefix']}{self.selected_file_name}"
        self.calculated_hash_field.value = t["calculating"]
        self.status_text.value = ""
        self.page.update()

        try:
            digest = calculate_sha256(self.selected_file_path)
        except Exception as ex:
            self.calculated_hash_field.value = ""
            self.status_text.value = f"⚠️ {ex}"
            self.status_text.color = ft.Colors.RED
            self.page.update()
            return

        self.calculated_hash_field.value = digest
        self.page.update()

    def on_compare(self, e):
        t = TEXT[self.lang]

        if not self.calculated_hash_field.value or self.calculated_hash_field.value == t["calculating"]:
            self.status_text.value = t["no_file"]
            self.status_text.color = ft.Colors.ORANGE
            self.page.update()
            return

        official = (self.official_hash_field.value or "").strip().lower()
        if not official:
            self.status_text.value = t["no_official"]
            self.status_text.color = ft.Colors.ORANGE
            self.page.update()
            return

        calculated = self.calculated_hash_field.value.strip().lower()
        is_match = calculated == official

        self.status_text.value = t["match"] if is_match else t["no_match"]
        self.status_text.color = ft.Colors.GREEN_700 if is_match else ft.Colors.RED

        self.history.insert(
            0,
            {
                "file": self.selected_file_name or "-",
                "match": is_match,
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            },
        )
        self.refresh_history()
        self.page.update()

    def on_language_change(self, e):
        self.lang = self.lang_dropdown.value
        self.apply_translations()
        self.page.update()

    # ----------------------------------------------------------------
    # Auxiliares
    # ----------------------------------------------------------------
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
                    ft.Text(t["col_file"], weight=ft.FontWeight.BOLD, width=220),
                    ft.Text(t["col_result"], weight=ft.FontWeight.BOLD, width=120),
                    ft.Text(t["col_time"], weight=ft.FontWeight.BOLD, width=140),
                ]
            )
        )
        self.history_column.controls.append(ft.Divider())

        for entry in self.history:
            result_text = t["match"] if entry["match"] else t["no_match"]
            result_color = ft.Colors.GREEN_700 if entry["match"] else ft.Colors.RED
            self.history_column.controls.append(
                ft.Row(
                    controls=[
                        ft.Text(entry["file"], width=220),
                        ft.Text(result_text, width=120, color=result_color),
                        ft.Text(entry["time"], width=140),
                    ]
                )
            )

    def apply_translations(self):
        t = TEXT[self.lang]

        self.page.title = t["title"]
        self.tab_verification_label.value = t["tab_verification"]
        self.tab_history_label.value = t["tab_history"]

        self.select_file_btn.content = t["select_file"]
        self.calculated_hash_label.value = t["calculated_hash"]
        self.official_hash_label.value = t["official_hash"]
        self.compare_btn.content = t["compare"]

        if self.selected_file_name:
            self.file_name_text.value = f"{t['file_prefix']}{self.selected_file_name}"

        # Repõe o texto de estado apenas se ainda não houve comparação/erro
        if not self.official_hash_field.value and not self.status_text.value:
            self.status_text.value = t["waiting"]

        self.refresh_history()


def main(page: ft.Page):
    SHA256VerifierApp(page)


if __name__ == "__main__":
    ft.run(main)
