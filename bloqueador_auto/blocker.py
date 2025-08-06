import sys
import os
import ctypes
import subprocess
import time
import tkinter as tk
import webbrowser

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def bloquear_hosts():
    hosts_path = r"C:\\Windows\\System32\\drivers\\etc\\hosts"
    backup_path = hosts_path + ".backup"
    if not os.path.exists(backup_path):
        subprocess.call(f'copy "{hosts_path}" "{backup_path}"', shell=True)

    with open(hosts_path, 'a') as f:
        f.write("\n### BLOQUEADOR PORNO ###\n")
        dominios = [
            "pornhub.com", "www.pornhub.com",
            "xvideos.com", "www.xvideos.com",
            "xnxx.com", "www.xnxx.com",
            "onlyfans.com", "redtube.com",
            "youporn.com", "xhamster.com"
        ]
        for d in dominios:
            f.write(f"127.0.0.1 {d}\n")

def configurar_dns():
    interfaces = ["Wi-Fi", "Ethernet"]
    for interface in interfaces:
        subprocess.call(f'netsh interface ip set dns name="{interface}" static 185.228.168.168', shell=True)
        subprocess.call(f'netsh interface ip add dns name="{interface}" 185.228.169.168 index=2', shell=True)

def mostrar_ventana_donacion():
    ventana = tk.Tk()
    ventana.title("Bloqueador Activo")
    ventana.geometry("300x150")
    ventana.resizable(False, False)

    label = tk.Label(ventana, text="NoMore porno en tu vida", font=("Helvetica", 14), pady=10)
    label.pack()

    def abrir_donacion():
        webbrowser.open("paypal.me/Avmich")  # Cambia esta URL por la de tu sistema de donaciones

    boton = tk.Button(ventana, text="Donar", command=abrir_donacion)
    boton.pack(pady=10)

    ventana.mainloop()

if __name__ == "__main__":
    if not is_admin():
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 1)
        sys.exit()

    bloquear_hosts()
    configurar_dns()
    time.sleep(2)
    mostrar_ventana_donacion()
