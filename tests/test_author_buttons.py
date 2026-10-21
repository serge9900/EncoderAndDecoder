"""LumiAi 2.8 Info/GitHub header controls. Run under xvfb on Linux."""
import tkinter as tk
from unittest.mock import patch
import LumiAi


def run():
    root = tk.Tk()
    app = LumiAi.LumiAiApp(root)
    root.update()
    assert app.info_button.winfo_ismapped() and app.github_button.winfo_ismapped()
    assert app.info_button.winfo_rooty() < app.input_text.winfo_rooty()
    app.password_var.set("test secret")
    app.input_text.insert("1.0", "Привет, աշխարհ")
    app.set_language("ru")
    with patch.object(LumiAi.messagebox, "showinfo") as info:
        app.info_button.invoke()
    assert info.call_count == 1
    assert "Сергей Варданян" in info.call_args.kwargs["message"]
    assert "github.com/serge9900" in info.call_args.kwargs["message"]
    with patch.object(LumiAi.webbrowser, "open_new_tab") as browser:
        app.github_button.invoke()
    browser.assert_called_once_with("https://github.com/serge9900")
    app.set_language("en")
    with patch.object(LumiAi.messagebox, "showinfo") as info:
        app.info_button.invoke()
    assert "Sergey Vardanyan" in info.call_args.kwargs["message"]
    assert app.get_input() == "Привет, աշխարհ"
    assert app.password_var.get() == "test secret"
    root.geometry("790x590")
    root.update()
    assert app.info_button.winfo_ismapped() and app.github_button.winfo_ismapped()
    assert app.info_button.winfo_rootx() > app.root.winfo_rootx()
    assert app.github_button.winfo_rootx() + app.github_button.winfo_width() <= root.winfo_rootx() + root.winfo_width()
    root.destroy()
    print("Info/GitHub RU+EN/header size: OK")

if __name__ == "__main__":
    run()
