"""Additional bilingual UI/functional smoke tests on a display (xvfb-run on Linux)."""
from __future__ import annotations
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import tkinter as tk
import LumiAi


def main():
    # Isolate settings so tests never modify an actual user preference.
    with TemporaryDirectory() as settings_dir:
        with patch.object(LumiAi, "LANGUAGE_SETTINGS_PATH", Path(settings_dir) / "settings.json"):
            _run()


def _run():
    root = tk.Tk()
    app = LumiAi.LumiAiApp(root)
    root.update()
    assert 'Проверка Ctrl' not in [w.cget('text') for w, role in app._elements if isinstance(w, (tk.Button, tk.Label))], 'diagnostic button still visible'
    assert app.language_button.cget('text') == '🌐 Language / Язык'
    assert app.language_menu.entrycget(0, 'label') == 'Русский'
    assert app.language_menu.entrycget(1, 'label') == 'English'
    app.input_text.insert('1.0','Привет, Բարեւ! 🌍')
    app.password_var.set('secret password')
    app.encrypt_action()
    original_cipher=app.get_output()
    assert original_cipher.startswith('LUMIAI1:')
    assert app.save_button.cget('text') == 'Сохранить шифротекст'
    app.set_language('en')
    root.update()
    assert 'Message Encryption' in root.title()
    assert app.save_button.cget('text') == 'Save ciphertext'
    assert app.reveal_btn.cget('text') == 'Show'
    assert app.get_output() == original_cipher
    assert app.get_input() == 'Привет, Բարեւ! 🌍'
    assert 'Message encrypted' in app.status_var.get()
    assert app.input_text.master.master.winfo_exists()
    assert app._character_count_text(1) == '1 character'
    app.toggle_password()
    assert app.reveal_btn.cget('text') == 'Hide'
    assert app.input_text.get('1.0','end-1c') == 'Привет, Բարեւ! 🌍'
    with TemporaryDirectory() as d:
        saved=Path(d)/'sample.lumi'
        with patch.object(LumiAi.filedialog,'asksaveasfilename', return_value=str(saved)):
            app.save_result()
        assert saved.read_text(encoding='utf8') == original_cipher
        assert app.status_var.get().startswith('Saved ENCRYPTED')
        with patch.object(LumiAi.messagebox,'showwarning') as warn:
            app.clear_texts();app.encrypt_action()
        assert warn.call_count == 1
        assert warn.call_args.args[1] == 'Enter a message in the left pane.'
        app.password_var.set('secret password')
        with patch.object(LumiAi.filedialog,'askopenfilename',return_value=str(saved)):
            app.load_text()
        assert 'Enter your password' in app.status_var.get()
        assert app.get_input() == original_cipher
        app.decrypt_action()
        assert app.get_output() == 'Привет, Բարեւ! 🌍'
        assert app.save_button.cget('text') == 'Save decrypted text'
        decoded=Path(d)/'decoded.txt'
        with patch.object(LumiAi.filedialog,'asksaveasfilename',return_value=str(decoded)):
            app.save_result()
        assert decoded.read_text(encoding='utf8') == 'Привет, Բարեւ! 🌍'
        app.password_var.set('wrong password')
        with patch.object(LumiAi.messagebox,'showerror') as err:
            app.decrypt_action()
        assert err.call_args.args[1].startswith('Incorrect password')
        app.set_language('ru')
        root.update()
        assert app.save_button.cget('text') == 'Сохранить расшифровку'
        assert app.reveal_btn.cget('text') == 'Скрыть'
        assert app.get_output() == 'Привет, Բարեւ! 🌍'
        assert app._character_count_text(1) == '1 символ'
        assert app._character_count_text(2) == '2 символа'
        assert app._character_count_text(5) == '5 символов'
        assert app._character_count_text(11) == '11 символов'
        assert app._character_count_text(21) == '21 символ'
        assert app._character_count_text(22) == '22 символа'
    # menu translations tested in both modes
    input_menu = app._edit_menus[1]
    assert input_menu.entrycget(0,'label') == 'Вырезать'
    app.set_language('en')
    assert input_menu.entrycget(0,'label') == 'Cut'
    assert LumiAi.load_ui_language() == 'en'
    assert LumiAi.LANGUAGE_SETTINGS_PATH.read_text(encoding='utf8').count('password') == 0
    # Visual geometry smoke test: none of header algo/actions/buttons off screen at narrow width.
    for w, h in [(1020,690), (790,590)]:
        root.geometry(f'{w}x{h}+5+5')
        root.update()
        assert root.winfo_width() >= 790 and root.winfo_height()>=590
        for widget in (app.language_button, app.save_button, app.modern_btn, app.legacy_btn):
            assert widget.winfo_rootx() >= root.winfo_rootx() - 2, (w,widget)
            assert widget.winfo_rootx()+widget.winfo_width() <= root.winfo_rootx()+root.winfo_width()+2, (w,widget,widget.winfo_rootx(),widget.winfo_width(),root.winfo_rootx(),root.winfo_width())
        bbox=(root.winfo_rootx(),root.winfo_rooty(),root.winfo_rootx()+root.winfo_width(),root.winfo_rooty()+root.winfo_height())
    root.destroy()
    print('LumiAi 2.6 language switching, hotkeys retained, translated dialogs, files, widget geometry: OK')
if __name__=='__main__':main()
