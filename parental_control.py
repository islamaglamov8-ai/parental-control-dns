import tkinter as tk
from tkinter import simpledialog, messagebox
import subprocess
import json
import os
import sys
import ctypes
import winreg
import psutil
import threading
import time
import re

PIN_CODE = "1234"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WHITELIST_FILE = os.path.join(BASE_DIR, "whitelist.json")
DNS_SCRIPT = os.path.join(BASE_DIR, "dns_whitelist.py")

dns_enabled = False
internet_restricted = False
dns_process = None


# ---------- ADMIN ----------
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


# ---------- PIN ----------
def ask_pin():
    pin = simpledialog.askstring("PIN", "Введите PIN:", show="*")
    return pin == PIN_CODE


# ---------- HELPERS ----------
def run_cmd(cmd, check=False):
    return subprocess.run(
        cmd,
        shell=True,
        check=check,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="ignore"
    )



def get_active_interface():
    import subprocess

    cmd = (
        'powershell -Command "'
        "Get-NetAdapter | Where-object {$_.Status -eq 'Up'} | "
        "Select-Object -First 1 -ExpandProperty Name\""
    )

    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout.strip()


INTERFACE_NAME = get_active_interface()


# ---------- WHITELIST ----------
def load_whitelist():
    if not os.path.exists(WHITELIST_FILE):
        return []
    try:
        with open(WHITELIST_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return [str(x).strip().lower() for x in data if str(x).strip()]
    except Exception:
        return []


def save_whitelist():
    items = [str(x).strip().lower() for x in listbox.get(0, tk.END) if str(x).strip()]
    with open(WHITELIST_FILE, "w", encoding="utf-8") as f:
        json.dump(items, f, indent=4, ensure_ascii=False)


# ---------- FIREWALL ----------
def remove_firewall_rules():
    rules = [
        "Allow Local DNS UDP",
        "Allow Local DNS TCP",
    ]
    for rule in rules:
        run_cmd(f'netsh advfirewall firewall delete rule name="{rule}"')


def apply_firewall_rules():
    remove_firewall_rules()

    # Разрешаем локальный DNS
    run_cmd(
        'netsh advfirewall firewall add rule '
        'name="Allow Local DNS UDP" dir=out action=allow protocol=UDP remoteip=127.0.0.1 remoteport=53'
    )

    # ВАЖНО: разрешаем DNS серверу ходить наружу
    run_cmd(
        'netsh advfirewall firewall add rule '
        'name="Allow DNS Upstream" dir=out action=allow protocol=UDP remoteport=53'
    )


# ---------- DNS ----------
def set_system_dns_local():
    run_cmd(f'netsh interface ip set dns name="{INTERFACE_NAME}" static 127.0.0.1', check=True)
    run_cmd("ipconfig /flushdns")


def set_system_dns_dhcp():
    run_cmd(f'netsh interface ip set dns name="{INTERFACE_NAME}" source=dhcp')
    run_cmd("ipconfig /flushdns")


def log_dns_output(proc):
    try:
        if proc.stdout:
            for line in proc.stdout:
                print("[DNS]", line.strip())
    except Exception as e:
        print("[DNS LOG ERROR]", e)

    try:
        if proc.stderr:
            for line in proc.stderr:
                print("[DNS ERR]", line.strip())
    except Exception as e:
        print("[DNS STDERR ERROR]", e)


def start_dns_internal():
    global dns_process, dns_enabled, internet_restricted

    if dns_process and dns_process.poll() is None:
        status.config(text="DNS: ВКЛЮЧЕН", fg="green")
        return True

    try:
        dns_process = subprocess.Popen(
            [sys.executable, DNS_SCRIPT],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=subprocess.CREATE_NO_WINDOW,
            text=True,
            encoding="utf-8",
            errors="ignore"
        )

        time.sleep(2)

        if dns_process.poll() is not None:
            stderr = ""
            try:
                stderr = dns_process.stderr.read()
            except Exception:
                pass
            raise RuntimeError(f"DNS процесс завершился сразу после запуска.\n{stderr}")

        set_system_dns_local()
        apply_firewall_rules()

        dns_enabled = True
        internet_restricted = True

        threading.Thread(
            target=log_dns_output,
            args=(dns_process,),
            daemon=True
        ).start()

        status.config(text="DNS: ВКЛЮЧЕН", fg="green")
        return True

    except Exception as e:
        dns_enabled = False
        internet_restricted = False

        try:
            if dns_process and dns_process.poll() is None:
                dns_process.kill()
        except Exception:
            pass

        dns_process = None
        set_system_dns_dhcp()
        remove_firewall_rules()
        status.config(text="DNS: ВЫКЛЮЧЕН", fg="red")
        messagebox.showerror("Ошибка", f"Не удалось запустить DNS:\n{e}")
        return False


def start_dns():
    if not ask_pin():
        messagebox.showerror("Ошибка", "Неверный PIN")
        return

    ok = start_dns_internal()
    if ok:
        messagebox.showinfo("Запущено", "DNS whitelist запущен!")


def stop_dns_internal():
    global dns_process, dns_enabled, internet_restricted

    dns_enabled = False
    internet_restricted = False

    if dns_process:
        try:
            parent = psutil.Process(dns_process.pid)
            for child in parent.children(recursive=True):
                child.kill()
            parent.kill()
        except Exception:
            pass

    dns_process = None
    set_system_dns_dhcp()
    remove_firewall_rules()
    status.config(text="DNS: ВЫКЛЮЧЕН", fg="red")


def stop_dns():
    if not ask_pin():
        messagebox.showerror("Ошибка", "Неверный PIN")
        return

    stop_dns_internal()


# ---------- INTERNET ----------
def restore_internet():
    if not ask_pin():
        messagebox.showerror("Ошибка", "Неверный PIN")
        return

    try:
        stop_dns_internal()
        messagebox.showinfo("Готово", "✅ Интернет полностью восстановлен")
    except Exception as e:
        messagebox.showerror("Ошибка", f"Ошибка восстановления:\n{e}")


# ---------- PROTECTION ----------
def watchdog():
    while True:
        time.sleep(3)

        if not dns_enabled:
            continue

        if dns_process is None:
            print("[WATCHDOG] DNS отсутствует, перезапускаю...")
            start_dns_internal()
            continue

        if dns_process.poll() is not None:
            print("[WATCHDOG] DNS завершился, перезапускаю...")
            start_dns_internal()


# ---------- Block windows ----------
def block_personalization(enable_block=True):
    if not ask_pin():
        messagebox.showerror("Ошибка", "Неверный PIN")
        return

    try:
        if enable_block:
            reg_keys = [
                (r"Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop", "NoChangingWallPaper", 1),
                (r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoChangingWallPaper", 1),
                (r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoThemesTab", 1),
                (r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoColorChoice", 1),
                (r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoVisualStyleChoice", 1),
                (r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoPersonalizationChange", 1),
                (r"Software\Policies\Microsoft\Windows\Control Panel\Desktop", "ScreenSaveActive", 0),
            ]
            for path, name, value in reg_keys:
                try:
                    key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, path)
                    winreg.SetValueEx(key, name, 0, winreg.REG_DWORD, value)
                    winreg.CloseKey(key)
                except Exception:
                    pass
            messagebox.showinfo("Успех", "✅ Блокировка персонализации ВКЛЮЧЕНА!")
        else:
            reg_keys = [
                (r"Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop", "NoChangingWallPaper"),
                (r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoChangingWallPaper"),
                (r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoThemesTab"),
                (r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoColorChoice"),
                (r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoVisualStyleChoice"),
                (r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoPersonalizationChange"),
                (r"Software\Policies\Microsoft\Windows\Control Panel\Desktop", "ScreenSaveActive"),
            ]
            for path, name in reg_keys:
                try:
                    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_WRITE)
                    winreg.DeleteValue(key, name)
                    winreg.CloseKey(key)
                except Exception:
                    pass
            messagebox.showinfo("Успех", "✅ Блокировка персонализации ОТКЛЮЧЕНА!")

        os.system("taskkill /f /im explorer.exe >nul 2>&1")
        time.sleep(2)
        os.system("start explorer.exe >nul 2>&1")

    except Exception as e:
        messagebox.showerror("Ошибка", f"Не удалось изменить настройки:\n{e}")


# ---------- GUI ----------
def add_site():
    if not ask_pin():
        messagebox.showerror("Ошибка", "Неверный PIN")
        return

    site = simpledialog.askstring("Добавить сайт", "Домен:")
    if site:
        site = site.strip().lower()
        if site:
            existing = [listbox.get(i) for i in range(listbox.size())]
            if site not in existing:
                listbox.insert(tk.END, site)
                save_whitelist()


def remove_site():
    if not ask_pin():
        messagebox.showerror("Ошибка", "Неверный PIN")
        return

    sel = listbox.curselection()
    if sel:
        listbox.delete(sel)
        save_whitelist()


def on_close():
    if ask_pin():
        stop_dns_internal()
        root.destroy()
    else:
        messagebox.showerror("Ошибка", "Неверный PIN")


if not is_admin():
    temp_root = tk.Tk()
    temp_root.withdraw()
    messagebox.showerror("Ошибка", "Запусти программу от имени администратора")
    sys.exit(1)


root = tk.Tk()
root.title("Родительский контроль")
root.geometry("480x600")
root.configure(bg="#f0f2f5")
root.protocol("WM_DELETE_WINDOW", on_close)

canvas = tk.Canvas(root, bg="#f0f2f5", highlightthickness=0)
scrollbar = tk.Scrollbar(root, orient=tk.VERTICAL, command=canvas.yview)
canvas.configure(yscrollcommand=scrollbar.set)

scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

main_frame = tk.Frame(canvas, bg="#f0f2f5")
canvas.create_window((0, 0), window=main_frame, anchor="nw")


def _on_mousewheel(event):
    canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")


canvas.bind_all("<MouseWheel>", _on_mousewheel)


def on_frame_configure(event):
    canvas.configure(scrollregion=canvas.bbox("all"))


main_frame.bind("<Configure>", on_frame_configure)

header = tk.Label(
    main_frame,
    text="Родительский контроль (DNS)",
    font=("Segoe UI", 18, "bold"),
    fg="#333",
    bg="#f0f2f5"
)
header.pack(pady=15)

frame_whitelist = tk.LabelFrame(
    main_frame,
    text="Белый список сайтов",
    font=("Segoe UI", 12, "bold"),
    bg="#f0f2f5",
    fg="#555"
)
frame_whitelist.pack(padx=20, pady=10, fill="both")

listbox = tk.Listbox(frame_whitelist, width=45, height=12, font=("Segoe UI", 11))
listbox.pack(padx=10, pady=10)

for s in load_whitelist():
    listbox.insert(tk.END, s)

btn_frame = tk.Frame(frame_whitelist, bg="#f0f2f5")
btn_frame.pack(pady=5)

tk.Button(
    btn_frame,
    text="Добавить сайт",
    command=add_site,
    width=15,
    bg="#4CAF50",
    fg="white",
    font=("Segoe UI", 11),
    activebackground="#45a049"
).grid(row=0, column=0, padx=5, pady=5)

tk.Button(
    btn_frame,
    text="Удалить сайт",
    command=remove_site,
    width=15,
    bg="#f44336",
    fg="white",
    font=("Segoe UI", 11),
    activebackground="#e53935"
).grid(row=0, column=1, padx=5, pady=5)

frame_dns = tk.LabelFrame(
    main_frame,
    text="DNS Контроль",
    font=("Segoe UI", 12, "bold"),
    bg="#f0f2f5",
    fg="#555"
)
frame_dns.pack(padx=20, pady=10, fill="both")

tk.Button(
    frame_dns,
    text="▶ Запустить DNS",
    command=start_dns,
    width=22,
    bg="#2196F3",
    fg="white",
    font=("Segoe UI", 12),
    activebackground="#1976D2"
).pack(pady=8)

tk.Button(
    frame_dns,
    text="⏹ Остановить DNS",
    command=stop_dns,
    width=22,
    bg="#9E9E9E",
    fg="white",
    font=("Segoe UI", 12),
    activebackground="#757575"
).pack(pady=5)

status = tk.Label(
    frame_dns,
    text="DNS: ВЫКЛЮЧЕН",
    fg="red",
    font=("Segoe UI", 12, "bold"),
    bg="#f0f2f5"
)
status.pack(pady=10)

frame_block = tk.LabelFrame(
    main_frame,
    text="Блокировка персонализации Windows",
    font=("Segoe UI", 12, "bold"),
    bg="#f0f2f5",
    fg="#555"
)
frame_block.pack(padx=20, pady=10, fill="both")

tk.Button(
    frame_block,
    text="🔒 Включить блокировку",
    command=lambda: block_personalization(True),
    bg="#4CAF50",
    fg="white",
    font=("Segoe UI", 12),
    activebackground="#45a049",
    width=22,
    height=2
).pack(pady=5)

tk.Button(
    frame_block,
    text="🔓 Отключить блокировку",
    command=lambda: block_personalization(False),
    bg="#f44336",
    fg="white",
    font=("Segoe UI", 12),
    activebackground="#e53935",
    width=22,
    height=2
).pack(pady=5)

tk.Button(
    main_frame,
    text="🌐 Вернуть обычный интернет",
    command=restore_internet,
    width=25,
    bg="#FF9800",
    fg="white",
    font=("Segoe UI", 12),
    activebackground="#FB8C00"
).pack(pady=15)

threading.Thread(target=watchdog, daemon=True).start()

root.mainloop()