"""Functional and UI smoke tests. Run with: python test_lumiai.py
On Linux without GUI: xvfb-run -a python test_lumiai.py
"""
from __future__ import annotations

import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import tkinter as tk

import LumiAi


def assert_shortcut(app, widget, keysym, operation_text, action="paste"):
    # Real Tk widget binding is exercised through event_generate below.
    widget.focus_set()
    widget.event_generate("<KeyPress>", keysym=keysym, state=0x4, when="tail")
    app.root.update()


def run():
    LumiAi.run_self_test()
    root = tk.Tk()
    root.update()
    app = LumiAi.LumiAiApp(root)
    app.set_language("ru")  # Keep legacy Russian-label assertions deterministic.
    root.update()
    assert root.winfo_width() >= 790
    assert app.input_text.winfo_width() > 100
    assert app.output_text.winfo_width() > 100
    assert app.input_text.bindtags()[0] == "LumiAiKeyboard", "Shortcut handler must run first"
    assert app.output_text.bindtags()[0] == "LumiAiKeyboard"
    assert app.password_entry.bindtags()[0] == "LumiAiKeyboard"

    # Real widget key binding: copy / select all / cut / paste, with a non-English keysym.
    app.input_text.insert("1.0", "Привет Բարեւ")
    root.update()
    assert_shortcut(app, app.input_text, "a", "", "all")
    assert app._selected_text(app.input_text) == "Привет Բարեւ", "Ctrl+A did not select all"
    assert_shortcut(app, app.input_text, "c", "", "copy")
    assert root.clipboard_get() == "Привет Բարեւ", "Ctrl+C did not copy"
    assert_shortcut(app, app.input_text, "x", "", "cut")
    assert app.get_input() == "", "Ctrl+X did not cut"
    assert_shortcut(app, app.input_text, "v", "", "paste")
    assert app.get_input() == "Привет Բարեւ", "Ctrl+V did not paste"

    # Simulate RU and AM keyboard layouts delivered by Tk and ensure they work.
    for key, expected in (("Cyrillic_ef", "all"), ("Cyrillic_es", "copy"),
                          ("Cyrillic_che", "cut"), ("Cyrillic_em", "paste")):
        app.input_text.focus_set()
        event = SimpleNamespace(widget=app.input_text, state=0x4, keysym=key, char="", keycode=0)
        assert app.handle_edit_shortcut(event) == "break", (key, expected)
    assert app.get_input() == "Привет Բարեւ"

    # In Windows the physical VK codes remain Latin A/C/X/V even with Armenian layout.
    # Simulate Windows' native code while keeping the tests runnable on Linux.
    with patch.object(LumiAi.sys, "platform", "win32"), \
         patch.object(LumiAi.LumiAiApp, "_ctrl_alt_state", return_value=(True, False)):
        for vk, expected in ((65, "all"), (67, "copy"), (88, "cut"), (86, "paste")):
            event = SimpleNamespace(widget=app.input_text, state=0x4,
                                    keycode=vk, keysym="Armenian_sample", char="")
            assert app.handle_edit_shortcut(event) == "break", vk
            assert f"команда={expected}" in app.last_keyboard_event
    assert app.get_input() == "Привет Բարեւ"

    # Verify Ctrl+C from the disabled result widget (text should still be selectable).
    app.put_output("ciphertext")
    app.output_text.focus_set()
    app.output_text.event_generate("<KeyPress>", keysym="a", state=0x4, when="tail")
    root.update()
    assert app._selected_text(app.output_text) == "ciphertext"
    app.output_text.event_generate("<KeyPress>", keysym="c", state=0x4, when="tail")
    root.update()
    assert root.clipboard_get() == "ciphertext"

    # Modern encryption, save the actual Result widget, NOT source.
    app.input_text.delete("1.0", "end")
    original = "Привет! Բարեւ աշխարհ 🌍"
    app.input_text.insert("1.0", original)
    app.password_var.set("Очень длинный пароль 😃")
    app.encrypt_action()
    ciphertext = app.get_output()
    assert ciphertext.startswith("LUMIAI1:") and original not in ciphertext
    assert app.save_button.cget("text") == "Сохранить шифротекст"
    with tempfile.TemporaryDirectory() as tmp:
        enc_path = Path(tmp, "saved.lumi")
        with patch.object(LumiAi.filedialog, "asksaveasfilename", return_value=str(enc_path)):
            app.save_result()
        assert enc_path.read_text(encoding="utf-8") == ciphertext
        assert enc_path.read_text(encoding="utf-8") != original
        assert app.get_input() == original, "Saving must not change source"
        assert LumiAi.decrypt_secure(app.password_var.get(), enc_path.read_text(encoding="utf-8")) == original

        # Test re-opening a file. Encrypted source belongs to left pane for decryption.
        app.clear_texts()
        app.password_var.set("Очень длинный пароль 😃")
        with patch.object(LumiAi.filedialog, "askopenfilename", return_value=str(enc_path)):
            app.load_text()
        assert app.get_input() == ciphertext
        assert app.get_output() == ""
        app.decrypt_action()
        assert app.get_output() == original
        assert app.save_button.cget("text") == "Сохранить расшифровку"
        dec_path = Path(tmp, "decrypted.txt")
        with patch.object(LumiAi.filedialog, "asksaveasfilename", return_value=str(dec_path)):
            app.save_result()
        assert dec_path.read_text(encoding="utf-8") == original
        assert ciphertext != dec_path.read_text(encoding="utf-8")

        # Disallow misleading .lumi extension for plaintext.
        invalid_path = Path(tmp, "wrong.lumi")
        with patch.object(LumiAi.filedialog, "asksaveasfilename", return_value=str(invalid_path)):
            with patch.object(LumiAi.messagebox, "showerror") as warning:
                app.save_result()
        assert warning.call_count == 1
        assert not invalid_path.exists()

    root.destroy()
    print("GUI hotkeys, RU layout aliases, AES-GCM, encrypted/plain saves: OK")


if __name__ == "__main__":
    run()


def run_native_poll_simulation():
    """Simulated Win32 physical-key snapshots: no native Windows available here."""
    root = tk.Tk()
    root.update()
    app = LumiAi.LumiAiApp(root)
    root.update()
    widget = app.input_text
    widget.focus_set()
    root.update()
    widget.insert('1.0', 'Привет, world')

    def press(keys):
        with patch.object(app, '_windows_native_shortcuts', return_value=set(keys)):
            app.poll_windows_shortcuts()

    press({65})  # Ctrl+A
    assert app._selected_text(widget) == 'Привет, world'
    press(set())
    press({67})  # Ctrl+C
    assert root.clipboard_get() == 'Привет, world'
    press(set())
    press({88})  # Ctrl+X
    assert app.get_input() == ''
    press(set())
    press({86})  # Ctrl+V
    assert app.get_input() == 'Привет, world'
    press({86})  # holding Ctrl+V must not paste twice
    assert app.get_input() == 'Привет, world'
    press(set())
    press({65})  # Ctrl+A again
    assert app._selected_text(widget) == 'Привет, world'
    assert 'Win32 VK=65' in app.last_keyboard_event
    root.destroy()
    print('Simulated Windows physical hotkeys: Ctrl+A/C/X/V and dedup: OK')


if __name__ == '__main__':
    run_native_poll_simulation()
