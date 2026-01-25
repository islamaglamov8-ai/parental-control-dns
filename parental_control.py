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

PIN_CODE = "1234"
WHITELIST_FILE = "whitelist.json"
DNS_SCRIPT = "dns_whitelist.py"
INTERFACE_NAME = "Ethernet"   # ← если Ethernet — поменяй
dns_enabled = False
internet_restricted = False




# ---------- ADMIN ----------
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    messagebox.showerror("Ошибка", "Запусти программу от имени администратора")
    sys.exit(1)


# ---------- PIN ----------
def ask_pin():
    pin = simpledialog.askstring("PIN", "Введите PIN:", show="*")
    return pin == PIN_CODE


# ---------- WHITELIST ----------
def load_whitelist():
    if not os.path.exists(WHITELIST_FILE):
        return []
    with open(WHITELIST_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def save_whitelist():
    with open(WHITELIST_FILE, "w", encoding="utf-8") as f:
        json.dump(listbox.get(0, tk.END), f, indent=4, ensure_ascii=False)


# ---------- DNS ----------
dns_process = None

def start_dns():

    if not ask_pin():
        messagebox.showerror("Ошибка", "Неверный PIN")
        return

    global dns_process, dns_enabled, internet_restricted
    if dns_process:
        messagebox.showinfo("Info", "DNS уже запущен")
        return

    dns_enabled = True
    internet_restricted = True

    try:
        dns_process = subprocess.Popen(
            [sys.executable, os.path.join(os.path.dirname(__file__), DNS_SCRIPT)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=subprocess.CREATE_NO_WINDOW
        )

        # Логирование в отдельном потоке
        def log_dns_output(proc):
            for line in proc.stdout:
                print("[DNS]", line.decode().strip())
            for line in proc.stderr:
                print("[DNS ERR]", line.decode().strip())

        threading.Thread(target=log_dns_output, args=(dns_process,), daemon=True).start()

        status.config(text="DNS: ВКЛЮЧЕН", fg="green")
        messagebox.showinfo("Запущено", "DNS whitelist запущен!")

    except Exception as e:
        messagebox.showerror("Ошибка", f"Не удалось запустить DNS:\n{e}")
        dns_enabled = False
        internet_restricted = False
        dns_process = None
        status.config(text="DNS: ВЫКЛЮЧЕН", fg="red")





def stop_dns():

    if not ask_pin():
        messagebox.showerror("Ошибка", "Неверный PIN")
        return

    global dns_process, dns_enabled

    dns_enabled = False

    if not dns_process:
        status.config(text="DNS: ВЫКЛЮЧЕН", fg="red")
        return

    try:
        parent = psutil.Process(dns_process.pid)
        for child in parent.children(recursive=True):
            child.kill()
        parent.kill()
    except:
        pass

    dns_process = None
    status.config(text="DNS: ВЫКЛЮЧЕН", fg="red")

# ---------- INTERNET ----------
def restore_internet():
    global dns_enabled, internet_restricted

    if not ask_pin():
        messagebox.showerror("Ошибка", "Неверный PIN")
        return

    # 1. Выключаем DNS-контроль
    dns_enabled = False
    internet_restricted = False
    stop_dns()

    # 2. Возвращаем DNS в DHCP
    subprocess.run(
        f'netsh interface ip set dns "{INTERFACE_NAME}" dhcp',
        shell=True
    )

    # 3. Снимаем firewall-блокировку DNS
    subprocess.run(
        'netsh advfirewall firewall delete rule name="Block External DNS"',
        shell=True
    )

    messagebox.showinfo("Готово", "Обычный интернет восстановлен")



# ---------- PROTECTION ----------
def watchdog():
    while True:
        time.sleep(3)

        if not dns_enabled:
            continue

        if dns_process is None or not psutil.pid_exists(dns_process.pid):
            start_dns()


# ---------- Block windows ----------
def block_personalization(enable_block=True):

    if not ask_pin():
        messagebox.showerror("Ошибка", "Неверный PIN")
        return
    """Включает или выключает блокировку персонализации Windows"""
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
                except:
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
                except:
                    pass
            messagebox.showinfo("Успех", "✅ Блокировка персонализации ОТКЛЮЧЕНА!")

        # Перезапуск проводника для применения изменений
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
        stop_dns()
        root.destroy()
    else:
        messagebox.showerror("Ошибка", "Неверный PIN")




root = tk.Tk()
root.title("Родительский контроль")
root.geometry("480x600")
root.configure(bg="#f0f2f5")
root.protocol("WM_DELETE_WINDOW", on_close)

# ---------- Canvas + Scrollbar ----------
canvas = tk.Canvas(root, bg="#f0f2f5", highlightthickness=0)
scrollbar = tk.Scrollbar(root, orient=tk.VERTICAL, command=canvas.yview)
canvas.configure(yscrollcommand=scrollbar.set)

scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

# ---------- Frame внутри Canvas ----------
main_frame = tk.Frame(canvas, bg="#f0f2f5")
canvas.create_window((0, 0), window=main_frame, anchor="nw")

# ---------- Прокрутка колесиком мыши ----------
def _on_mousewheel(event):
    canvas.yview_scroll(int(-1*(event.delta/120)), "units")

canvas.bind_all("<MouseWheel>", _on_mousewheel)

# ---------- Обновление scrollregion ----------
def on_frame_configure(event):
    canvas.configure(scrollregion=canvas.bbox("all"))

main_frame.bind("<Configure>", on_frame_configure)

# ---------- GUI внутри main_frame ----------

# Шапка
header = tk.Label(main_frame, text="Родительский контроль (DNS)", font=("Segoe UI", 18, "bold"), fg="#333", bg="#f0f2f5")
header.pack(pady=15)

# Белый список сайтов (фиксированный, без скролла)
frame_whitelist = tk.LabelFrame(main_frame, text="Белый список сайтов", font=("Segoe UI", 12, "bold"), bg="#f0f2f5", fg="#555")
frame_whitelist.pack(padx=20, pady=10, fill="both")

listbox = tk.Listbox(frame_whitelist, width=45, height=12, font=("Segoe UI", 11))
listbox.pack(padx=10, pady=10)

for s in load_whitelist():
    listbox.insert(tk.END, s)

btn_frame = tk.Frame(frame_whitelist, bg="#f0f2f5")
btn_frame.pack(pady=5)

tk.Button(btn_frame, text="Добавить сайт", command=add_site, width=15, bg="#4CAF50", fg="white", font=("Segoe UI", 11), activebackground="#45a049").grid(row=0, column=0, padx=5, pady=5)
tk.Button(btn_frame, text="Удалить сайт", command=remove_site, width=15, bg="#f44336", fg="white", font=("Segoe UI", 11), activebackground="#e53935").grid(row=0, column=1, padx=5, pady=5)

# DNS секция
frame_dns = tk.LabelFrame(main_frame, text="DNS Контроль", font=("Segoe UI", 12, "bold"), bg="#f0f2f5", fg="#555")
frame_dns.pack(padx=20, pady=10, fill="both")

tk.Button(frame_dns, text="▶ Запустить DNS", command=start_dns, width=22, bg="#2196F3", fg="white", font=("Segoe UI", 12), activebackground="#1976D2").pack(pady=8)
tk.Button(frame_dns, text="⏹ Остановить DNS", command=stop_dns, width=22, bg="#9E9E9E", fg="white", font=("Segoe UI", 12), activebackground="#757575").pack(pady=5)

status = tk.Label(frame_dns, text="DNS: ВЫКЛЮЧЕН", fg="red", font=("Segoe UI", 12, "bold"), bg="#f0f2f5")
status.pack(pady=10)

# Блокировка персонализации
frame_block = tk.LabelFrame(main_frame, text="Блокировка персонализации Windows", font=("Segoe UI", 12, "bold"), bg="#f0f2f5", fg="#555")
frame_block.pack(padx=20, pady=10, fill="both")

tk.Button(frame_block, text="🔒 Включить блокировку", command=lambda: block_personalization(True), bg="#4CAF50", fg="white", font=("Segoe UI", 12), activebackground="#45a049", width=22, height=2).pack(pady=5)
tk.Button(frame_block, text="🔓 Отключить блокировку", command=lambda: block_personalization(False), bg="#f44336", fg="white", font=("Segoe UI", 12), activebackground="#e53935", width=22, height=2).pack(pady=5)

# Восстановление интернета
tk.Button(main_frame, text="🌐 Вернуть обычный интернет", command=restore_internet, width=25, bg="#FF9800", fg="white", font=("Segoe UI", 12), activebackground="#FB8C00").pack(pady=15)

root.mainloop()
