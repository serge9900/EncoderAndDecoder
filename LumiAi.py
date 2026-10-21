"""LumiAi — modern message encryption, with compatibility for the old script.

Requires: pip install cryptography
Run:      python LumiAi.py
Tests:    python LumiAi.py --self-test
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import secrets
import string
import sys
import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import filedialog, messagebox

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    AESGCM = None  # type: ignore[assignment,misc]
    InvalidTag = Exception  # type: ignore[assignment,misc]


APP_NAME = "LumiAi"
APP_VERSION = "2.8"
AUTHOR_GITHUB = "https://github.com/serge9900"
FORMAT_PREFIX = "LUMIAI1:"
PBKDF2_ITERATIONS = 600_000
SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
MAX_OPEN_FILE_SIZE = 2_000_000

# Only interface language is persisted; plaintext, ciphertext, and keys are never saved here.
if sys.platform == "win32":
    _config_base = Path(os.environ.get("APPDATA", str(Path.home())))
else:
    _config_base = Path(os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config")))
LANGUAGE_SETTINGS_PATH = _config_base / "LumiAi" / "settings.json"


def load_ui_language() -> str:
    try:
        value = json.loads(LANGUAGE_SETTINGS_PATH.read_text(encoding="utf-8"))
        language = value.get("language", "ru")
        return language if language in ("ru", "en") else "ru"
    except (OSError, UnicodeError, ValueError, AttributeError, TypeError):
        return "ru"


def save_ui_language(language: str) -> None:
    try:
        LANGUAGE_SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
        LANGUAGE_SETTINGS_PATH.write_text(
            json.dumps({"language": language}, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    except OSError:
        pass  # Permission problems must never stop encryption or normal UI use.

# Windows virtual-key identifiers are independent of the active keyboard layout.
# Tk can fail to generate Ctrl+<letter> events with Russian and Armenian layouts,
# so Windows gets an additional native-key-state fallback.
WIN_VK_ACTIONS = {0x41: "all", 0x43: "copy", 0x56: "paste", 0x58: "cut",
                  0x5A: "undo", 0x59: "redo"}
ACTION_WIN_VK = {value: key for key, value in WIN_VK_ACTIONS.items()}


def _require_password(password: str) -> None:
    if not password:
        raise ValueError("Введите пароль (ключ).")


def _aesgcm_available() -> None:
    if AESGCM is None:
        raise RuntimeError("Не найдена библиотека cryptography. Установите её: pip install cryptography")


def encrypt_secure(password: str, message: str) -> str:
    """AES-256-GCM + a new random salt/nonce for every encryption."""
    _aesgcm_available()
    _require_password(password)
    if len(password) < 8:
        raise ValueError("Для современного шифрования используйте пароль минимум из 8 символов.")
    salt = secrets.token_bytes(SALT_SIZE)
    nonce = secrets.token_bytes(NONCE_SIZE)
    key = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS, dklen=32
    )
    encrypted = AESGCM(key).encrypt(nonce, message.encode("utf-8"), FORMAT_PREFIX.encode("ascii"))
    payload = base64.urlsafe_b64encode(salt + nonce + encrypted).decode("ascii")
    return FORMAT_PREFIX + payload


def decrypt_secure(password: str, token: str) -> str:
    _aesgcm_available()
    _require_password(password)
    token = token.strip()
    if not token.startswith(FORMAT_PREFIX):
        raise ValueError("Это не сообщение LumiAi. Для старых сообщений выберите «Старый формат».")
    encoded = token[len(FORMAT_PREFIX):]
    try:
        payload = base64.b64decode(encoded, altchars=b"-_", validate=True)
    except (UnicodeError, ValueError, binascii.Error) as exc:
        raise ValueError("Шифротекст повреждён: неверный формат Base64.") from exc
    if len(payload) < SALT_SIZE + NONCE_SIZE + TAG_SIZE:
        raise ValueError("Шифротекст неполный или повреждён.")
    salt = payload[:SALT_SIZE]
    nonce = payload[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ciphertext = payload[SALT_SIZE + NONCE_SIZE:]
    key = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS, dklen=32
    )
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, FORMAT_PREFIX.encode("ascii"))
    except InvalidTag as exc:
        raise ValueError("Неверный пароль или сообщение изменено/повреждено.") from exc
    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Ошибка чтения текста: повреждённые данные UTF-8.") from exc


def encrypt_legacy(password: str, message: str) -> str:
    """The original algorithm, kept for compatibility only."""
    _require_password(password)
    if any(ord(ch) > 255 for ch in message):
        raise ValueError("Старый алгоритм не поддерживает русский, армянский и другие Unicode-символы без потери данных.")
    encoded_chars = [
        chr((ord(ch) + ord(password[i % len(password)])) % 256)
        for i, ch in enumerate(message)
    ]
    return base64.urlsafe_b64encode("".join(encoded_chars).encode("utf-8")).decode("ascii")


def decrypt_legacy(password: str, token: str) -> str:
    """Byte-for-byte compatible with Decode() from encode_and_decode.py."""
    _require_password(password)
    try:
        raw = base64.b64decode(token.strip(), altchars=b"-_", validate=True).decode("utf-8")
    except (ValueError, UnicodeError, binascii.Error) as exc:
        raise ValueError("Не удалось прочитать старое сообщение. Проверьте шифротекст.") from exc
    return "".join(
        chr((256 + ord(ch) - ord(password[i % len(password)])) % 256)
        for i, ch in enumerate(raw)
    )


DARK = {
    "base": "#0B1120", "panel": "#151F33", "field": "#0E182A", "border": "#2B3B53",
    "text": "#EFF5FF", "muted": "#99A9C0", "accent": "#8DD8FE", "accent_fg": "#07101E",
    "button": "#293B54", "button_active": "#364E6C", "notice": "#F9C77A", "success": "#86EFAC",
}
LIGHT = {
    "base": "#F2F6FC", "panel": "#FFFFFF", "field": "#F7F9FD", "border": "#DDE5F1",
    "text": "#16233A", "muted": "#62738E", "accent": "#187FBA", "accent_fg": "#FFFFFF",
    "button": "#E5EDF7", "button_active": "#D0E1F2", "notice": "#95600A", "success": "#17633B",
}



# User-facing interface strings; the encryption format is independent of language.
MESSAGES = {
    "ru": {
        "window_title": "LumiAi {version} — шифрование сообщений",
        "subtitle": "Шифруй сообщения. Сохраняй секреты.",
        "info_button": "ⓘ Info", "github_button": "↗ GitHub",
        "about_title": "О программе LumiAi",
        "about_content": "LumiAi {version}\n\nАвтор проекта: Сергей Варданян\nGitHub: {github}\n\nLumiAi — современная версия оригинальной программы автора для шифрования и расшифровки сообщений.",
        "theme_light": "☀  Светлая тема", "theme_dark": "☾  Тёмная тема",
        "algorithm": "АЛГОРИТМ", "modern": "🔒  Современный · AES-256-GCM",
        "legacy": "↩  Старый формат · совместимость",
        "modern_hint": "Современный формат: защита паролем, Unicode, случайная соль и проверка целостности.",
        "legacy_hint": "⚠ Старый формат оставлен для совместимости. Он НЕ защищает секретные данные.",
        "secret": "СЕКРЕТНЫЙ КЛЮЧ / ПАРОЛЬ", "key_unsaved": "Ключ нигде не сохраняется",
        "show": "Показать", "hide": "Скрыть", "generate_key": "Создать ключ",
        "source": "ИСХОДНЫЙ ТЕКСТ", "result": "РЕЗУЛЬТАТ", "copy": "⧉  Копировать",
        "paste": "Вставить", "open_file": "Открыть файл", "save_result": "Сохранить результат",
        "save_encrypted": "Сохранить шифротекст", "save_decrypted": "Сохранить расшифровку",
        "encrypt": "🔒  Зашифровать", "decrypt": "🔓  Расшифровать",
        "swap": "⇄  Поменять", "clear": "Очистить",
        "characters_one": "{count} символ", "characters_few": "{count} символа", "characters_many": "{count} символов",
        "menu_cut": "Вырезать", "menu_copy": "Копировать", "menu_paste": "Вставить", "menu_all": "Выделить всё",
        "ready": "Готово к работе",
        "selected_modern": "Выбрано современное шифрование AES-256-GCM.",
        "selected_legacy": "Старый алгоритм: подходит только для расшифровки прежних сообщений.",
        "generated": "Новый случайный ключ создан. Сохраните его в надёжном месте — восстановить его нельзя.",
        "select_to_copy": "Выделите текст, который хотите скопировать.",
        "selection_copied": "Выделенный текст скопирован.",
        "clipboard_empty": "Буфер обмена пуст или содержит не текст.",
        "pasted": "Текст вставлен из буфера обмена.",
        "selected_all": "Весь текст выделен (Ctrl+A).",
        "enter_message": "Введите сообщение в левое поле.",
        "operation_failed": "Операция не выполнена. Проверьте сообщение и ключ.",
        "encrypted_ok": "✓ Сообщение успешно зашифровано.",
        "decrypted_ok": "✓ Сообщение успешно расшифровано.",
        "legacy_caution": " Старый формат не проверяет правильность ключа.",
        "legacy_decrypted_ok": "✓ Сообщение успешно расшифровано. Старый формат не проверяет правильность ключа.",
        "nothing_to_swap": "В правом поле пока нет результата.",
        "swapped": "Результат перенесён в исходное поле.",
        "cleared": "Поля и ключ очищены.",
        "nothing_to_copy": "Нечего копировать.",
        "result_copied": "Результат скопирован в буфер обмена.",
        "open_title": "Открыть текст",
        "open_types": "Текст и сообщения", "all_files": "Все файлы",
        "open_error": "Не удалось открыть файл:\n{error}",
        "too_large": "Файл слишком большой (максимум 2 МБ).",
        "opened_cipher": "Открыт шифротекст {file} в левом поле. Введите пароль и нажмите «Расшифровать».",
        "opened_invalid_lumi": "Открыт {file}, но внутри нет заголовка LUMIAI1:. Проверьте, шифротекст ли это.",
        "opened_file": "Открыт файл {file} в поле «Исходный текст».",
        "nothing_to_save": "В поле «Результат» пока ничего нет. Сначала нажмите «Зашифровать» или «Расшифровать».",
        "save_encrypted_type": "Зашифрованное сообщение (*.lumi)",
        "save_text_type": "Текст (*.txt)",
        "save_plain_type": "Обычный текст (*.txt)",
        "save_encrypted_title": "Сохранить шифротекст из правого поля",
        "save_plain_title": "Сохранить РАСШИФРОВАННЫЙ текст из правого поля (без защиты)",
        "bad_plain_extension": "Расшифрованный текст нельзя сохранять под расширением .lumi. Это обычный НЕЗАЩИЩЁННЫЙ текст. Выберите имя .txt.",
        "save_error": "Не удалось сохранить файл:\n{error}",
        "saved_encrypted": "Сохранён ЗАШИФРОВАННЫЙ результат из правого поля: {file} ({count} символов)",
        "saved_decrypted": "Сохранён РАСШИФРОВАННЫЙ текст из правого поля: {file} ({count} символов)",
        "error_need_password": "Введите пароль (ключ).",
        "error_password_short": "Для современного шифрования используйте пароль минимум из 8 символов.",
        "error_crypto_missing": "Не найдена библиотека cryptography. Установите её: pip install cryptography",
        "error_not_lumiai": "Это не сообщение LumiAi. Для старых сообщений выберите «Старый формат».",
        "error_bad_base64": "Шифротекст повреждён: неверный формат Base64.",
        "error_incomplete": "Шифротекст неполный или повреждён.",
        "error_bad_password": "Неверный пароль или сообщение изменено/повреждено.",
        "error_bad_utf8": "Ошибка чтения текста: повреждённые данные UTF-8.",
        "error_legacy_unicode": "Старый алгоритм не поддерживает русский, армянский и другие Unicode-символы без потери данных.",
        "error_legacy_failed": "Не удалось прочитать старое сообщение. Проверьте шифротекст.",
    },
    "en": {
        "window_title": "LumiAi {version} — Message Encryption",
        "subtitle": "Encrypt messages. Keep your secrets safe.",
        "info_button": "ⓘ Info", "github_button": "↗ GitHub",
        "about_title": "About LumiAi",
        "about_content": "LumiAi {version}\n\nProject creator: Sergey Vardanyan\nGitHub: {github}\n\nLumiAi is a modern version of the author's original message encryption and decryption program.",
        "theme_light": "☀  Light theme", "theme_dark": "☾  Dark theme",
        "algorithm": "ALGORITHM", "modern": "🔒  Modern · AES-256-GCM",
        "legacy": "↩  Legacy format · compatibility",
        "modern_hint": "Modern format: password protection, Unicode, random salt and integrity check.",
        "legacy_hint": "⚠ Legacy format is for compatibility only. It does NOT protect sensitive data.",
        "secret": "SECRET KEY / PASSWORD", "key_unsaved": "The key is never saved",
        "show": "Show", "hide": "Hide", "generate_key": "Generate key",
        "source": "SOURCE TEXT", "result": "RESULT", "copy": "⧉  Copy",
        "paste": "Paste", "open_file": "Open file", "save_result": "Save result",
        "save_encrypted": "Save ciphertext", "save_decrypted": "Save decrypted text",
        "encrypt": "🔒  Encrypt", "decrypt": "🔓  Decrypt",
        "swap": "⇄  Swap", "clear": "Clear",
        "characters_one": "{count} character", "characters_few": "{count} characters", "characters_many": "{count} characters",
        "menu_cut": "Cut", "menu_copy": "Copy", "menu_paste": "Paste", "menu_all": "Select all",
        "ready": "Ready",
        "selected_modern": "AES-256-GCM encryption selected.",
        "selected_legacy": "Legacy algorithm: use only to decrypt old messages.",
        "generated": "A random key was generated. Store it safely — it cannot be recovered.",
        "select_to_copy": "Select the text you want to copy.",
        "selection_copied": "Selected text copied.",
        "clipboard_empty": "The clipboard is empty or does not contain text.",
        "pasted": "Text pasted from the clipboard.",
        "selected_all": "All text selected (Ctrl+A).",
        "enter_message": "Enter a message in the left pane.",
        "operation_failed": "Operation failed. Check the message and password.",
        "encrypted_ok": "✓ Message encrypted successfully.",
        "decrypted_ok": "✓ Message decrypted successfully.",
        "legacy_caution": " Legacy mode cannot verify the password.",
        "legacy_decrypted_ok": "✓ Message decrypted successfully. Legacy mode cannot verify the password.",
        "nothing_to_swap": "There is no result in the right pane yet.",
        "swapped": "The result was moved to the source pane.",
        "cleared": "Text fields and password cleared.",
        "nothing_to_copy": "Nothing to copy.",
        "result_copied": "Result copied to the clipboard.",
        "open_title": "Open text",
        "open_types": "Text and messages", "all_files": "All files",
        "open_error": "Could not open file:\n{error}",
        "too_large": "File is too large (maximum 2 MB).",
        "opened_cipher": "Opened encrypted file {file} in the left pane. Enter your password and click Decrypt.",
        "opened_invalid_lumi": "Opened {file}, but the LUMIAI1: header is missing. Check whether it is encrypted.",
        "opened_file": "Opened {file} in the Source Text pane.",
        "nothing_to_save": "The Result pane is empty. Click Encrypt or Decrypt first.",
        "save_encrypted_type": "Encrypted message (*.lumi)",
        "save_text_type": "Text (*.txt)",
        "save_plain_type": "Plain text (*.txt)",
        "save_encrypted_title": "Save ciphertext from the right pane",
        "save_plain_title": "Save DECRYPTED text from the right pane (not protected)",
        "bad_plain_extension": "Decrypted text cannot be saved as .lumi. It is unprotected plain text. Choose a .txt filename.",
        "save_error": "Could not save file:\n{error}",
        "saved_encrypted": "Saved ENCRYPTED result from the right pane: {file} ({count} characters)",
        "saved_decrypted": "Saved DECRYPTED text from the right pane: {file} ({count} characters)",
        "error_need_password": "Enter a password (key).",
        "error_password_short": "For modern encryption, use a password of at least 8 characters.",
        "error_crypto_missing": "The cryptography package is missing. Install it: pip install cryptography",
        "error_not_lumiai": "This is not a LumiAi message. Select Legacy format for older messages.",
        "error_bad_base64": "Damaged ciphertext: invalid Base64 encoding.",
        "error_incomplete": "Ciphertext is incomplete or corrupted.",
        "error_bad_password": "Incorrect password, or the message was modified or corrupted.",
        "error_bad_utf8": "Cannot read text: invalid UTF-8 data.",
        "error_legacy_unicode": "The legacy algorithm cannot safely encode Russian, Armenian or other Unicode characters.",
        "error_legacy_failed": "Could not decode legacy message. Check the ciphertext.",
    },
}
assert MESSAGES["ru"].keys() == MESSAGES["en"].keys(), "Untranslated UI keys"
ERROR_KEYS = (
    "error_need_password", "error_password_short", "error_crypto_missing",
    "error_not_lumiai", "error_bad_base64", "error_incomplete", "error_bad_password",
    "error_bad_utf8", "error_legacy_unicode", "error_legacy_failed",
)


class LumiAiApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.is_dark = True
        self.language = load_ui_language()
        self._translated_widgets: list[tuple[tk.Widget, str]] = []
        self._translated_menu_entries: list[tuple[tk.Menu, int, str]] = []
        self._last_notice: tuple[str, dict[str, object], bool] = ("ready", {}, False)
        self.algorithm = "secure"
        self.last_action = "encrypt"
        self.password_var = tk.StringVar()
        self.password_visible = False
        self.counter_var = tk.StringVar(value="")
        self.status_var = tk.StringVar(value="")
        self._elements: list[tuple[tk.Widget, str]] = []
        self._edit_menus: list[tk.Menu] = []
        # Only key metadata, never text/password or clipboard contents.
        self.last_keyboard_event = "Пока не зарегистрировано ни одного сочетания Ctrl."
        self.shortcut_count = 0
        # Suppress duplicates if both Tk and native-Windows polling see the key.
        # Latches reset as soon as the physical key is released.
        self._win_hotkey_latch: set[int] = set()

        root.title(self.t("window_title", version=APP_VERSION))
        root.geometry("1020x690")
        root.minsize(790, 590)
        root.configure(bg=DARK["base"])
        self.build_ui()
        self.refresh_language()
        self.apply_theme()
        if sys.platform == "win32":
            # Tk 8.6 may drop non-Latin Ctrl+letter presses entirely. Unlike
            # extra Tk bindings, Windows virtual-key polling sees them anyway.
            self.root.after(15, self.poll_windows_shortcuts)

    def add(self, widget: tk.Widget, role: str) -> tk.Widget:
        self._elements.append((widget, role))
        return widget

    def frame(self, parent: tk.Misc, role: str = "base", **kwargs: object) -> tk.Frame:
        return self.add(tk.Frame(parent, bd=0, **kwargs), role)  # type: ignore[return-value]

    def label(self, parent: tk.Misc, content: str = "", role: str = "text", **kwargs: object) -> tk.Label:
        return self.add(tk.Label(parent, text=content, bd=0, **kwargs), role)  # type: ignore[return-value]

    def button(self, parent: tk.Misc, title: str, command: object, role: str = "secondary", **kwargs: object) -> tk.Button:
        return self.add(
            tk.Button(parent, text=title, command=command, relief="flat", bd=0,
                      highlightthickness=0, cursor="hand2", **kwargs), role
        )  # type: ignore[return-value]

    def t(self, key: str, **kwargs: object) -> str:
        return MESSAGES[self.language][key].format(**kwargs)

    def loc_label(self, parent: tk.Misc, key: str, role: str = "text", **kwargs: object) -> tk.Label:
        widget = self.label(parent, self.t(key), role, **kwargs)
        self._translated_widgets.append((widget, key))
        return widget

    def loc_button(self, parent: tk.Misc, key: str, command: object,
                   role: str = "secondary", **kwargs: object) -> tk.Button:
        widget = self.button(parent, self.t(key), command, role, **kwargs)
        self._translated_widgets.append((widget, key))
        return widget

    def set_notice(self, key: str, success: bool = False, **kwargs: object) -> None:
        self._last_notice = (key, kwargs, success)
        self.set_status(self.t(key, **kwargs), success=success)

    def _translate_error(self, error: BaseException) -> str:
        original = str(error)
        if self.language == "ru":
            return original
        for key in ERROR_KEYS:
            if original == MESSAGES["ru"][key]:
                return MESSAGES["en"][key]
        if original == MESSAGES["ru"]["too_large"]:
            return self.t("too_large")
        return original  # Preserve unknown system errors verbatim.

    def _character_count_text(self, count: int) -> str:
        if self.language == "en":
            return self.t("characters_one" if count == 1 else "characters_many", count=count)
        if count % 10 == 1 and count % 100 != 11:
            key = "characters_one"
        elif 2 <= count % 10 <= 4 and not 12 <= count % 100 <= 14:
            key = "characters_few"
        else:
            key = "characters_many"
        return self.t(key, count=count)

    def _save_label_key(self) -> str:
        return "save_result" if not self.get_output() else ("save_decrypted" if self.last_action == "decrypt" else "save_encrypted")

    def refresh_language(self) -> None:
        self.root.title(self.t("window_title", version=APP_VERSION))
        for widget, key in self._translated_widgets:
            widget.config(text=self.t(key))
        for menu, index, key in self._translated_menu_entries:
            menu.entryconfigure(index, label=self.t(key))
        self.reveal_btn.config(text=self.t("hide" if self.password_visible else "show"))
        self.theme_button.config(text=self.t("theme_light" if self.is_dark else "theme_dark"))
        self.save_button.config(text=self.t(self._save_label_key()))
        self.format_hint.config(text=self.t("modern_hint" if self.algorithm == "secure" else "legacy_hint"))
        self.update_counter()
        key, params, success = self._last_notice
        self.set_status(self.t(key, **params), success=success)

    def set_language(self, language: str) -> None:
        if language not in MESSAGES:
            raise ValueError(f"Unsupported language: {language}")
        self.language = language
        self.refresh_language()
        save_ui_language(language)

    def show_language_menu(self) -> None:
        # This replaces the old shortcut-diagnostics button.
        x = self.language_button.winfo_rootx()
        y = self.language_button.winfo_rooty() + self.language_button.winfo_height()
        try:
            self.language_menu.tk_popup(x, y)
        finally:
            self.language_menu.grab_release()

    def show_about(self) -> None:
        """Show project credits in the currently selected interface language."""
        messagebox.showinfo(
            title=self.t("about_title"),
            message=self.t("about_content", version=APP_VERSION, github=AUTHOR_GITHUB),
            parent=self.root,
        )

    def open_author_github(self) -> None:
        """Open the developer's public GitHub profile in the default browser."""
        webbrowser.open_new_tab(AUTHOR_GITHUB)

    def build_ui(self) -> None:
        page = self.frame(self.root)
        page.pack(fill="both", expand=True, padx=22, pady=14)

        header = self.frame(page)
        header.pack(fill="x", pady=(0, 14))
        heading = self.frame(header)
        heading.pack(side="left")
        self.label(heading, "✦", "accent_text", font=("Segoe UI Symbol", 28)).pack(side="left", padx=(0, 11))
        title_col = self.frame(heading)
        title_col.pack(side="left")
        self.label(title_col, APP_NAME, "text", font=("Segoe UI", 25, "bold")).pack(anchor="w")
        self.loc_label(title_col, "subtitle", "muted", font=("Segoe UI", 10)).pack(anchor="w")
        # Compact author links at the top right; keep the theme toggle unchanged.
        self.theme_button = self.loc_button(header, "theme_light", self.toggle_theme, "secondary", font=("Segoe UI", 10), padx=14, pady=10)
        self.theme_button.pack(side="right", pady=9)
        self.github_button = self.loc_button(header, "github_button", self.open_author_github, "secondary", font=("Segoe UI", 9), padx=10, pady=8)
        self.github_button.pack(side="right", padx=(0, 7), pady=9)
        self.info_button = self.loc_button(header, "info_button", self.show_about, "secondary", font=("Segoe UI", 9), padx=10, pady=8)
        self.info_button.pack(side="right", padx=(0, 7), pady=9)

        settings = self.frame(page, "panel")
        settings.pack(fill="x", pady=(0, 13))
        settings_inner = self.frame(settings, "panel")
        settings_inner.pack(fill="x", padx=20, pady=15)
        self.loc_label(settings_inner, "algorithm", "panel_muted", font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(0, 8))
        algo_row = self.frame(settings_inner, "panel")
        algo_row.pack(fill="x")
        self.modern_btn = self.loc_button(algo_row, "modern", lambda: self.select_algorithm("secure"), "primary", font=("Segoe UI", 10, "bold"), padx=14, pady=9)
        self.modern_btn.pack(side="left", padx=(0, 8))
        self.legacy_btn = self.loc_button(algo_row, "legacy", lambda: self.select_algorithm("legacy"), "secondary", font=("Segoe UI", 10), padx=14, pady=9)
        self.legacy_btn.pack(side="left")
        self.format_hint = self.loc_label(settings_inner, "modern_hint", "panel_muted", font=("Segoe UI", 9), anchor="w")
        self.format_hint.pack(fill="x", pady=(10, 0))

        secret_card = self.frame(page, "panel")
        secret_card.pack(fill="x", pady=(0, 13))
        secret_inner = self.frame(secret_card, "panel")
        secret_inner.pack(fill="x", padx=20, pady=14)
        title_row = self.frame(secret_inner, "panel")
        title_row.pack(fill="x", pady=(0, 8))
        self.loc_label(title_row, "secret", "panel_muted", font=("Segoe UI", 9, "bold")).pack(side="left")
        self.loc_label(title_row, "key_unsaved", "panel_muted", font=("Segoe UI", 9)).pack(side="right")
        secret_row = self.frame(secret_inner, "panel")
        secret_row.pack(fill="x")
        self.password_entry = self.add(tk.Entry(secret_row, textvariable=self.password_var, show="●", font=("Consolas", 12), relief="flat", bd=0, highlightthickness=1), "entry")
        self.password_entry.pack(side="left", fill="x", expand=True, ipady=10, padx=(0, 9))
        self.reveal_btn = self.button(secret_row, self.t("show"), self.toggle_password, "secondary", font=("Segoe UI", 10), padx=12, pady=10)
        self.reveal_btn.pack(side="left", padx=(0, 9))
        self.loc_button(secret_row, "generate_key", self.generate_password, "secondary", font=("Segoe UI", 10), padx=12, pady=10).pack(side="left")

        footer = self.frame(page)
        footer.pack(side="bottom", fill="x")
        status_wrap = self.frame(footer)
        status_wrap.pack(side="left", fill="x", expand=True)
        self.status_label = self.add(tk.Label(status_wrap, textvariable=self.status_var, anchor="w", font=("Segoe UI", 9), bd=0), "muted")
        self.status_label.pack(fill="x")
        self.save_button = self.button(footer, self.t("save_result"), self.save_result, "secondary", font=("Segoe UI", 9), padx=12, pady=8)
        self.save_button.pack(side="right", padx=(8, 0))
        self.loc_button(footer, "open_file", self.load_text, "secondary", font=("Segoe UI", 9), padx=12, pady=8).pack(side="right")
        self.language_button = self.button(footer, "🌐 Language / Язык", self.show_language_menu,
                                           "secondary", font=("Segoe UI", 9), padx=12, pady=8)
        self.language_button.pack(side="right", padx=(0, 8))
        self.language_menu = tk.Menu(self.root, tearoff=False)
        self.language_menu.add_command(label="Русский", command=lambda: self.set_language("ru"))
        self.language_menu.add_command(label="English", command=lambda: self.set_language("en"))
        self._edit_menus.append(self.language_menu)

        actions = self.frame(page)
        actions.pack(side="bottom", fill="x", pady=(0, 11))
        self.loc_button(actions, "encrypt", self.encrypt_action, "primary", font=("Segoe UI", 11, "bold"), padx=18, pady=12).pack(side="left", padx=(0, 9))
        self.loc_button(actions, "decrypt", self.decrypt_action, "secondary", font=("Segoe UI", 11, "bold"), padx=18, pady=12).pack(side="left", padx=(0, 9))
        self.loc_button(actions, "swap", self.swap_texts, "secondary", font=("Segoe UI", 10), padx=12, pady=12).pack(side="left", padx=(0, 9))
        self.loc_button(actions, "clear", self.clear_texts, "secondary", font=("Segoe UI", 10), padx=12, pady=12).pack(side="right")


        editors = self.frame(page)
        editors.pack(fill="both", expand=True, pady=(0, 12))
        editors.grid_columnconfigure(0, weight=1, uniform="editor_columns")
        editors.grid_columnconfigure(1, weight=1, uniform="editor_columns")
        editors.grid_rowconfigure(0, weight=1)
        left = self.frame(editors, "panel")
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 7))
        right = self.frame(editors, "panel")
        right.grid(row=0, column=1, sticky="nsew", padx=(7, 0))
        self.input_text = self.create_editor(left, "source", output=False)
        self.output_text = self.create_editor(right, "result", output=True)
        self.input_text.bind("<KeyRelease>", self.update_counter)
        self.input_text.bind("<<Paste>>", lambda e: self.root.after_idle(self.update_counter))
        self.input_text.bind("<<Cut>>", lambda e: self.root.after_idle(self.update_counter))
        self.input_text.bind("<Control-Return>", lambda e: self.hotkey_encrypt())
        self.input_text.bind("<Control-Shift-Return>", lambda e: self.hotkey_decrypt())
        # A dedicated bindtag is put FIRST, ahead of Text/Entry default bindings.
        # This works by physical virtual-key code even when an IME / Cyrillic /
        # Armenian layout produces a different keysym for the same physical key.
        self.root.bind_class("LumiAiKeyboard", "<KeyPress>", self.handle_edit_shortcut)
        for editor in (self.input_text, self.output_text, self.password_entry):
            current_tags = editor.bindtags()
            editor.bindtags(("LumiAiKeyboard",) + tuple(tag for tag in current_tags if tag != "LumiAiKeyboard"))
            # Some Tk versions fire <<Paste>> even when their Control-v event
            # was consumed elsewhere. Override virtual events *on the widget*
            # so a second built-in Text/Entry paste cannot take place.
            for name, operation in (("Paste", "paste"), ("Cut", "cut"), ("Copy", "copy")):
                editor.bind(f"<<{name}>>", lambda event, op=operation: self.handle_tk_virtual_edit(event, op))

        self.root.after_idle(self.input_text.focus_set)
        self.install_edit_menu(self.input_text, editable=True)
        self.install_edit_menu(self.output_text, editable=False)
        self.install_edit_menu(self.password_entry, editable=True)

    def create_editor(self, parent: tk.Frame, header_key: str, output: bool) -> tk.Text:
        inside = self.frame(parent, "panel")
        inside.pack(fill="both", expand=True, padx=17, pady=15)
        toolbar = self.frame(inside, "panel")
        toolbar.pack(fill="x", pady=(0, 11))
        self.loc_label(toolbar, header_key, "panel_muted", font=("Segoe UI", 9, "bold")).pack(side="left")
        if output:
            self.loc_button(toolbar, "copy", self.copy_result, "secondary", font=("Segoe UI", 9), padx=10, pady=6).pack(side="right")
        else:
            self.loc_button(toolbar, "paste", self.paste_into_input, "secondary", font=("Segoe UI", 9), padx=8, pady=6).pack(side="right")
            self.add(tk.Label(toolbar, textvariable=self.counter_var, font=("Segoe UI", 9)), "panel_muted").pack(side="right", padx=(0, 9))
        box = self.frame(inside, "field")
        box.pack(fill="both", expand=True)
        widget = self.add(
            tk.Text(box, wrap="word", undo=not output, font=("Segoe UI", 11), width=1, height=1,
                    bd=0, relief="flat", padx=13, pady=13, highlightthickness=1), "text_field"
        )
        widget.pack(side="left", fill="both", expand=True)
        scroll = tk.Scrollbar(box, command=widget.yview, relief="flat", width=10)
        scroll.pack(side="right", fill="y")
        widget.configure(yscrollcommand=scroll.set)
        if output:
            widget.config(state="disabled")
        return widget

    def apply_theme(self) -> None:
        p = DARK if self.is_dark else LIGHT
        self.root.config(bg=p["base"])
        for widget, role in self._elements:
            if role == "base":
                widget.config(bg=p["base"])
            elif role == "panel":
                widget.config(bg=p["panel"])
            elif role == "field":
                widget.config(bg=p["field"])
            elif role in ("text", "muted", "accent_text"):
                color = p["text"] if role == "text" else p["accent"] if role == "accent_text" else p["muted"]
                widget.config(bg=p["base"], fg=color)
            elif role in ("panel_muted", "panel_text"):
                widget.config(bg=p["panel"], fg=p["muted"] if role == "panel_muted" else p["text"])
            elif role in ("entry", "text_field"):
                widget.config(bg=p["field"], fg=p["text"], insertbackground=p["text"], selectbackground=p["button_active"],
                              selectforeground=p["text"], highlightbackground=p["border"], highlightcolor=p["accent"])
            elif role in ("primary", "secondary"):
                is_primary = role == "primary"
                widget.config(bg=p["accent"] if is_primary else p["button"],
                              fg=p["accent_fg"] if is_primary else p["text"],
                              activebackground=p["accent"] if is_primary else p["button_active"],
                              activeforeground=p["accent_fg"] if is_primary else p["text"])
        self.modern_btn.config(bg=p["accent"] if self.algorithm == "secure" else p["button"],
                               fg=p["accent_fg"] if self.algorithm == "secure" else p["text"])
        self.legacy_btn.config(bg=p["accent"] if self.algorithm == "legacy" else p["button"],
                               fg=p["accent_fg"] if self.algorithm == "legacy" else p["text"])
        self.theme_button.config(text=self.t("theme_light" if self.is_dark else "theme_dark"))
        if self.algorithm == "legacy":
            self.format_hint.config(fg=p["notice"])
        self.status_label.config(fg=p["success"] if self._last_notice[2] else p["muted"])
        for menu in self._edit_menus:
            menu.config(bg=p["panel"], fg=p["text"], activebackground=p["button_active"],
                        activeforeground=p["text"], borderwidth=0)

    def toggle_theme(self) -> None:
        self.is_dark = not self.is_dark
        self.apply_theme()

    def select_algorithm(self, algorithm: str) -> None:
        self.algorithm = algorithm
        if algorithm == "secure":
            self.format_hint.config(text=self.t("modern_hint"))
            self.set_notice("selected_modern")
        else:
            self.format_hint.config(text=self.t("legacy_hint"))
            self.set_notice("selected_legacy")
        self.apply_theme()

    def toggle_password(self) -> None:
        self.password_visible = not self.password_visible
        self.password_entry.config(show="" if self.password_visible else "●")
        self.reveal_btn.config(text=self.t("hide" if self.password_visible else "show"))

    def generate_password(self) -> None:
        alphabet = string.ascii_letters + string.digits + "-_@#%+!"
        # Rejection of a generated key without letters or digits is just a usability improvement.
        while True:
            password = "".join(secrets.choice(alphabet) for _ in range(24))
            if any(x.isalpha() for x in password) and any(x.isdigit() for x in password):
                break
        self.password_var.set(password)
        self.set_notice("generated")

    def _selected_text(self, widget: tk.Widget) -> str | None:
        try:
            if isinstance(widget, tk.Text):
                return widget.get("sel.first", "sel.last")
            if isinstance(widget, tk.Entry):
                return widget.get()[widget.index("sel.first"):widget.index("sel.last")] if widget.selection_present() else None
        except tk.TclError:
            pass
        return None

    def _delete_selection(self, widget: tk.Widget) -> bool:
        try:
            if isinstance(widget, (tk.Text, tk.Entry)) and self._selected_text(widget) is not None:
                widget.delete("sel.first", "sel.last")
                if widget == self.input_text:
                    self.update_counter()
                return True
        except tk.TclError:
            pass
        return False

    def copy_selection(self, widget: tk.Widget) -> None:
        selected = self._selected_text(widget)
        if selected is None:
            self.set_notice("select_to_copy")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(selected)
        self.root.update_idletasks()
        self.set_notice("selection_copied", success=True)

    def cut_selection(self, widget: tk.Widget) -> None:
        if widget == self.output_text:
            return
        selected = self._selected_text(widget)
        if selected is None:
            return
        self.copy_selection(widget)
        self._delete_selection(widget)

    def paste_text(self, widget: tk.Widget, *, replace_all: bool = False) -> None:
        """Paste at the caret for Ctrl+V; replace a complete message via Paste button.

        The explicit Paste button is a *message import* action, unlike editor
        Ctrl+V. Repeated button clicks do not append the same message twice.
        """
        if widget == self.output_text:
            return
        try:
            value = self.root.clipboard_get()
        except tk.TclError:
            self.set_notice("clipboard_empty")
            return
        if not isinstance(widget, (tk.Text, tk.Entry)):
            return
        widget.focus_set()
        if replace_all:
            if isinstance(widget, tk.Text):
                widget.delete("1.0", "end")
            else:
                widget.delete(0, "end")
        else:
            self._delete_selection(widget)
        widget.insert("insert", value)
        if widget == self.input_text:
            self.update_counter()
        self.set_notice("pasted", success=True)

    def paste_into_input(self) -> None:
        # Paste button loads ONE message, replacing the previous message.
        # Ctrl+V and the right-click edit menu retain ordinary caret behavior.
        self.paste_text(self.input_text, replace_all=True)

    def handle_tk_virtual_edit(self, event: tk.Event, operation: str) -> str:
        """Stop Tk's built-in <<Paste>>/<<Cut>>/<<Copy>> from acting twice.

        Some Tk/Windows layouts generate a virtual edit event in addition to
        the physical-key event that our custom handler or Win32 poll caught.
        All three entry points now share the same physical-key latch.
        """
        widget = event.widget
        if widget not in (self.input_text, self.output_text, self.password_entry):
            return "break"
        if sys.platform == "win32" and operation in ACTION_WIN_VK:
            # If the physical key is STILL DOWN, suppress a duplicate virtual
            # event if Tk or Win32 already performed this shortcut.
            vk = ACTION_WIN_VK[operation]
            if vk in self._win_hotkey_latch:
                return "break"
            try:
                import ctypes
                ctypes.windll.user32.GetAsyncKeyState.argtypes = (ctypes.c_int,)
                ctypes.windll.user32.GetAsyncKeyState.restype = ctypes.c_short
                if ctypes.windll.user32.GetAsyncKeyState(vk) & 0x8000:
                    self._win_hotkey_latch.add(vk)
            except (AttributeError, OSError):
                pass
        self._execute_keyboard_operation(widget, operation, event_details=f"Tk virtual {operation}")
        return "break"

    def select_all_text(self, widget: tk.Widget) -> None:
        if isinstance(widget, tk.Text):
            widget.tag_add("sel", "1.0", "end-1c")
            widget.mark_set("insert", "end-1c")
            widget.see("insert")
        elif isinstance(widget, tk.Entry):
            widget.selection_range(0, "end")
            widget.icursor("end")
        widget.focus_set()

    @staticmethod
    def _ctrl_alt_state(event: tk.Event) -> tuple[bool, bool]:
        state = int(getattr(event, "state", 0))
        ctrl = bool(state & 0x0004)
        alt = bool(state & 0x0008)
        if sys.platform == "win32":
            try:
                import ctypes
                user32 = ctypes.windll.user32
                # On some Win/Tk versions event.state is incomplete under IME.
                ctrl |= bool(user32.GetAsyncKeyState(0x11) & 0x8000)
                alt |= bool(user32.GetAsyncKeyState(0x12) & 0x8000)
            except (AttributeError, OSError):
                pass
        return ctrl, alt

    def handle_edit_shortcut(self, event: tk.Event) -> str | None:
        """Catch Ctrl+C/V/X/A before Tk's default class handler.

        Tk keysyms can differ with EN/RU/AM layouts. When Tk supplies an
        event, handle by physical virtual-key code before class bindings.
        On Windows a separate native keyboard check covers events Tk drops.
        """
        widget = event.widget
        if widget not in (self.input_text, self.output_text, self.password_entry):
            return None

        ctrl, alt = self._ctrl_alt_state(event)
        state = int(getattr(event, "state", 0))
        shift = bool(state & 0x0001)
        # Preserve the standard Windows fallback shortcuts.
        keysym = str(getattr(event, "keysym", "")).lower()
        if not ctrl and shift and keysym == "insert":
            operation = "paste"
        elif not ctrl and shift and keysym == "delete":
            operation = "cut"
        elif ctrl and not alt and keysym == "insert":
            operation = "copy"
        elif not ctrl or alt:  # Leave regular typing and AltGr untouched.
            return None
        else:
            # On Windows virtual-key codes for the physical A/C/V/X keys are
            # Latin uppercase ASCII, *regardless* of keyboard language.
            keycode = int(getattr(event, "keycode", 0))
            operation = WIN_VK_ACTIONS.get(keycode) if sys.platform == "win32" else None
            aliases = {
                "c": "copy", "с": "copy", "cyrillic_es": "copy", "\x03": "copy",
                "v": "paste", "м": "paste", "cyrillic_em": "paste", "\x16": "paste",
                "x": "cut", "ч": "cut", "cyrillic_che": "cut", "\x18": "cut",
                "a": "all", "ф": "all", "cyrillic_ef": "all", "\x01": "all",
                "z": "undo", "я": "undo", "cyrillic_ya": "undo", "\x1a": "undo",
                "y": "redo", "н": "redo", "cyrillic_en": "redo", "\x19": "redo",
            }
            operation = operation or aliases.get(keysym) or aliases.get(str(getattr(event, "char", "")).lower())
            # In Tk's X11 implementation, physical keycodes are X11 codes.
            # The keysym-based fallback above covers normal keypresses.
            if not operation:
                self.last_keyboard_event = (
                    f"Ctrl=ДА, Alt=НЕТ; НЕ РАСПОЗНАНО: "
                    f"keycode={keycode}, keysym={keysym}; "
                    f"распознано действий={self.shortcut_count}"
                )
                return None

        if sys.platform == "win32" and operation in ACTION_WIN_VK:
            vk = ACTION_WIN_VK[operation]
            if vk in self._win_hotkey_latch:
                return "break"
            self._win_hotkey_latch.add(vk)

        self._execute_keyboard_operation(widget, operation, event_details=(
            f"Tk keycode={getattr(event, 'keycode', '?')}, "
            f"keysym={getattr(event, 'keysym', '?')}"
        ))
        return "break"  # Don't let Tk perform the action a second time.

    def _execute_keyboard_operation(self, widget: tk.Widget, operation: str,
                                    event_details: str) -> None:
        """Run an editor shortcut exactly once, whether triggered by Tk or Win32."""
        self.shortcut_count += 1
        self.last_keyboard_event = (
            f"{event_details}; команда={operation}; "
            f"перехвачено={self.shortcut_count}"
        )
        if operation == "copy":
            self.copy_selection(widget)
        elif operation == "paste":
            self.paste_text(widget)
        elif operation == "cut":
            self.cut_selection(widget)
        elif operation == "all":
            self.select_all_text(widget)
            self.set_notice("selected_all", success=True)
        elif operation in ("undo", "redo") and widget == self.input_text:
            try:
                widget.edit_undo() if operation == "undo" else widget.edit_redo()
                self.update_counter()
            except tk.TclError:
                pass

    @staticmethod
    def _windows_native_shortcuts(root: tk.Tk) -> set[int]:
        """Read physical shortcut keys only when this application's window is active.

        Uses Win32 API without hooks, elevation, packages, or listening to other
        applications. No typed character content is collected or saved.
        """
        if sys.platform != "win32":
            return set()
        import ctypes
        user32 = ctypes.windll.user32
        # Do not capture anything when another application has focus.
        user32.GetForegroundWindow.restype = ctypes.c_void_p
        user32.GetAncestor.argtypes = (ctypes.c_void_p, ctypes.c_uint)
        user32.GetAncestor.restype = ctypes.c_void_p
        own_top = user32.GetAncestor(ctypes.c_void_p(root.winfo_id()), 2)  # GA_ROOT
        if own_top != user32.GetForegroundWindow():
            return set()
        user32.GetAsyncKeyState.argtypes = (ctypes.c_int,)
        user32.GetAsyncKeyState.restype = ctypes.c_short
        is_down = lambda vk: bool(user32.GetAsyncKeyState(vk) & 0x8000)
        if not (is_down(0x11) or is_down(0xA2) or is_down(0xA3)):
            return set()
        if is_down(0x12) or is_down(0xA4) or is_down(0xA5):
            return set()  # Keep AltGr and Ctrl+Alt available for normal typing.
        return {key for key in WIN_VK_ACTIONS if is_down(key)}

    def poll_windows_shortcuts(self) -> None:
        """Fallback for Cyrillic/Armenian keypress events lost by Tk on Windows."""
        try:
            focused = self.root.focus_get()
            currently_down = self._windows_native_shortcuts(self.root)
            # Reset latches when physical keys are released, or window loses focus.
            self._win_hotkey_latch.intersection_update(currently_down)
            if focused in (self.input_text, self.output_text, self.password_entry):
                for vk in sorted(currently_down):
                    if vk not in self._win_hotkey_latch:
                        self._win_hotkey_latch.add(vk)
                        self._execute_keyboard_operation(
                            focused, WIN_VK_ACTIONS[vk],
                            event_details=f"Win32 VK={vk} (раскладка не имеет значения)",
                        )
        except (OSError, tk.TclError, AttributeError) as exc:
            self.last_keyboard_event = f"Ошибка проверки Win32: {type(exc).__name__}"
        finally:
            try:
                if self.root.winfo_exists():
                    self.root.after(15, self.poll_windows_shortcuts)
            except tk.TclError:
                pass

    def install_edit_menu(self, widget: tk.Widget, editable: bool) -> None:
        menu = tk.Menu(widget, tearoff=False)
        if editable:
            menu.add_command(label=self.t("menu_cut"), command=lambda: self.cut_selection(widget))
            self._translated_menu_entries.append((menu, menu.index("end"), "menu_cut"))
        menu.add_command(label=self.t("menu_copy"), command=lambda: self.copy_selection(widget))
        self._translated_menu_entries.append((menu, menu.index("end"), "menu_copy"))
        if editable:
            menu.add_command(label=self.t("menu_paste"), command=lambda: self.paste_text(widget))
            self._translated_menu_entries.append((menu, menu.index("end"), "menu_paste"))
        menu.add_separator()
        menu.add_command(label=self.t("menu_all"), command=lambda: self.select_all_text(widget))
        self._translated_menu_entries.append((menu, menu.index("end"), "menu_all"))
        self._edit_menus.append(menu)

        def show_menu(event: tk.Event) -> str:
            try:
                menu.tk_popup(event.x_root, event.y_root)
            finally:
                menu.grab_release()
            return "break"

        widget.bind("<Button-3>", show_menu)

    def get_input(self) -> str:
        return self.input_text.get("1.0", "end-1c")

    def get_output(self) -> str:
        return self.output_text.get("1.0", "end-1c")

    def put_output(self, value: str) -> None:
        self.output_text.config(state="normal")
        self.output_text.delete("1.0", "end")
        self.output_text.insert("1.0", value)
        self.output_text.config(state="disabled")

    def set_status(self, text: str, success: bool = False) -> None:
        self.status_var.set(text)
        p = DARK if self.is_dark else LIGHT
        self.status_label.config(fg=p["success"] if success else p["muted"])

    def update_counter(self, event: object = None) -> None:
        self.counter_var.set(self._character_count_text(len(self.get_input())))

    def process(self, decrypt: bool) -> None:
        password = self.password_var.get()
        message = self.get_input()
        if not message.strip():
            messagebox.showwarning(APP_NAME, self.t("enter_message"), parent=self.root)
            return
        try:
            if self.algorithm == "secure":
                result = decrypt_secure(password, message) if decrypt else encrypt_secure(password, message)
            else:
                result = decrypt_legacy(password, message) if decrypt else encrypt_legacy(password, message)
        except (ValueError, RuntimeError) as exc:
            messagebox.showerror(APP_NAME, self._translate_error(exc), parent=self.root)
            self.set_notice("operation_failed")
            return
        self.put_output(result)
        self.last_action = "decrypt" if decrypt else "encrypt"
        self.save_button.config(text=self.t(self._save_label_key()))
        key = "decrypted_ok" if decrypt else "encrypted_ok"
        if self.algorithm == "legacy" and decrypt:
            key = "legacy_decrypted_ok"
        self.set_notice(key, success=True)

    def encrypt_action(self) -> None:
        self.process(False)

    def decrypt_action(self) -> None:
        self.process(True)

    def hotkey_encrypt(self) -> str:
        self.encrypt_action()
        return "break"

    def hotkey_decrypt(self) -> str:
        self.decrypt_action()
        return "break"

    def swap_texts(self) -> None:
        output = self.get_output()
        if not output:
            self.set_notice("nothing_to_swap")
            return
        self.input_text.delete("1.0", "end")
        self.input_text.insert("1.0", output)
        self.put_output("")
        self.save_button.config(text=self.t("save_result"))
        self.update_counter()
        self.set_notice("swapped")

    def clear_texts(self) -> None:
        self.input_text.delete("1.0", "end")
        self.put_output("")
        self.save_button.config(text=self.t("save_result"))
        self.password_var.set("")
        self.update_counter()
        self.set_notice("cleared")

    def copy_result(self) -> None:
        result = self.get_output()
        if not result:
            self.set_notice("nothing_to_copy")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(result)
        self.root.update_idletasks()
        self.set_notice("result_copied", success=True)

    def load_text(self) -> None:
        path = filedialog.askopenfilename(parent=self.root, title=self.t("open_title"), filetypes=[(self.t("open_types"), "*.txt *.lumi *.enc"), (self.t("all_files"), "*.*")])
        if not path:
            return
        try:
            file = Path(path)
            if file.stat().st_size > MAX_OPEN_FILE_SIZE:
                raise ValueError(self.t("too_large"))
            value = file.read_text(encoding="utf-8-sig")
        except (OSError, UnicodeError, ValueError) as exc:
            messagebox.showerror(APP_NAME, self.t("open_error", error=self._translate_error(exc)), parent=self.root)
            return
        self.input_text.delete("1.0", "end")
        self.input_text.insert("1.0", value)
        self.put_output("")
        self.save_button.config(text=self.t("save_result"))
        self.update_counter()
        # Opening a file prepares it for decryption. It never places anything
        # in Result; the Result panel only displays the operation output.
        if file.suffix.lower() == ".lumi" and value.startswith(FORMAT_PREFIX):
            self.select_algorithm("secure")
            self.set_notice("opened_cipher", success=True, file=file.name)
        elif file.suffix.lower() == ".lumi":
            self.set_notice("opened_invalid_lumi", file=file.name)
        else:
            self.set_notice("opened_file", success=True, file=file.name)

    def save_result(self) -> None:
        # IMPORTANT: only the right-hand Result is saved, never the source text.
        value = self.get_output()
        if not value:
            self.set_notice("nothing_to_save")
            return
        encrypted = self.last_action == "encrypt"
        if encrypted:
            ext = ".lumi"
            filters = [(self.t("save_encrypted_type"), "*.lumi"), (self.t("save_text_type"), "*.txt")]
            title = self.t("save_encrypted_title")
        else:
            ext = ".txt"
            filters = [(self.t("save_plain_type"), "*.txt")]
            title = self.t("save_plain_title")
        path = filedialog.asksaveasfilename(
            parent=self.root, title=title, defaultextension=ext, filetypes=filters
        )
        if not path:
            return
        file = Path(path)
        if not encrypted and file.suffix.lower() == ".lumi":
            messagebox.showerror(
                APP_NAME, self.t("bad_plain_extension"), parent=self.root
            )
            return
        try:
            file.write_text(value, encoding="utf-8")
        except OSError as exc:
            messagebox.showerror(APP_NAME, self.t("save_error", error=str(exc)), parent=self.root)
            return
        self.set_notice("saved_encrypted" if encrypted else "saved_decrypted", success=True,
                        file=file.name, count=len(value))


def run_self_test() -> None:
    password = "Надёжный🔑Ключ123"
    for sample in ("Hello, world!", "Привет! Բարեւ 🌍", "Line 1\nLine 2", "😀" * 50, ""):
        encrypted = encrypt_secure(password, sample)
        assert encrypted.startswith(FORMAT_PREFIX)
        assert decrypt_secure(password, encrypted) == sample
        assert encrypted != encrypt_secure(password, sample), "Salt/nonce must be random"
        try:
            decrypt_secure("wrong password", encrypted)
        except ValueError:
            pass
        else:
            raise AssertionError("Wrong passwords must fail")
    for message, key in (("Hello World!", "key"), ("123ABC", "abc"), ("café", "é"), ("", "key")):
        # The expected encoding function in the original script.
        expected = base64.urlsafe_b64encode("".join(chr((ord(ch) + ord(key[i % len(key)])) % 256)
                                                   for i, ch in enumerate(message)).encode()).decode()
        assert encrypt_legacy(key, message) == expected
        assert decrypt_legacy(key, expected) == message
    print("LumiAi: все тесты успешно пройдены ✓")


def main() -> None:
    if "--self-test" in sys.argv:
        run_self_test()
        return
    if AESGCM is None:
        # The app can still run in legacy-only mode; explain missing modern mode upfront.
        print("Внимание: установите cryptography: python -m pip install cryptography", file=sys.stderr)
    root = tk.Tk()
    LumiAiApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
