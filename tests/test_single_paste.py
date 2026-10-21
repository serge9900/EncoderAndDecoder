"""Regression tests for accidental duplicate paste in LumiAi 2.7.
Run xvfb-run -a python test_single_paste.py on Linux.
"""
from types import SimpleNamespace
from unittest.mock import patch
import tkinter as tk
import LumiAi


def main():
    root = tk.Tk()
    app = LumiAi.LumiAiApp(root)
    root.update()
    w = app.input_text
    w.focus_set()
    root.update()
    message = "LUMIAI1:single-test-ciphertext"
    root.clipboard_clear()
    root.clipboard_append(message)
    root.update_idletasks()

    # Clicking Paste is a message-level operation, not an insert at the caret.
    for i in range(4):
        app.paste_into_input()
        assert app.get_input() == message, f"Paste button repeated on click {i+1}"
    assert app.counter_var.get().startswith(str(len(message)))

    # The normal Ctrl+V hotkey still pastes at the cursor when editing a word.
    w.delete('1.0', 'end')
    w.insert('1.0', 'Prefix: ')
    w.mark_set('insert', 'end-1c')
    w.event_generate('<KeyPress>', keysym='v', state=0x4, when='tail')
    root.update()
    assert app.get_input() == 'Prefix: ' + message

    # Explicit Tk virtual Paste must not cause a second native paste.
    w.delete('1.0','end')
    w.event_generate('<<Paste>>', when='tail')
    root.update()
    assert app.get_input() == message

    # Simulate Win32 seeing the same physical key via Tk and as a virtual event.
    w.delete('1.0','end')
    app._win_hotkey_latch.clear()
    with patch.object(LumiAi.sys, 'platform', 'win32'), \
         patch.object(app, '_ctrl_alt_state', return_value=(True,False)):
        event = SimpleNamespace(widget=w, state=4, keycode=0x56, keysym='Cyrillic_em',char='')
        assert app.handle_edit_shortcut(event) == 'break'
        assert app.get_input() == message
        # Tk default virtual event after custom native processing is suppressed.
        assert app.handle_tk_virtual_edit(SimpleNamespace(widget=w), 'paste') == 'break'
        assert app.get_input() == message
        with patch.object(app, '_windows_native_shortcuts',return_value={0x56}):
            app.poll_windows_shortcuts()
        assert app.get_input() == message
        # Releasing then pressing again must count as a new paste, as usual.
        with patch.object(app, '_windows_native_shortcuts',return_value=set()):
            app.poll_windows_shortcuts()
        assert 0x56 not in app._win_hotkey_latch
    root.destroy()
    print('LumiAi 2.7 paste button idempotent, Tk edit keys, virtual event and Win32 dedup: OK')

if __name__ == '__main__':
    main()
