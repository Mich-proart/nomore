import sys
import os
import ctypes
import subprocess
import time
import tkinter as tk
import webbrowser
import hashlib

# Rutas y configuraciones
HOSTS_PATH = r"C:\\Windows\\System32\\drivers\\etc\\hosts"
BACKUP_PATH = HOSTS_PATH + ".backup"
DNS_GOOD = ["185.228.168.168", "185.228.169.168"]
INTERFACES = ["Wi-Fi", "Ethernet"]

# ----------------- Funciones de bloqueo -------------------
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def bloquear_hosts():
    if not os.path.exists(BACKUP_PATH):
        subprocess.call(f'copy "{HOSTS_PATH}" "{BACKUP_PATH}"', shell=True)

    with open(HOSTS_PATH, 'a') as f:
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
    for interface in INTERFACES:
        subprocess.call(f'netsh interface ip set dns name="{interface}" static {DNS_GOOD[0]}', shell=True)
        subprocess.call(f'netsh interface ip add dns name="{interface}" {DNS_GOOD[1]} index=2', shell=True)

# ----------------- Persistencia -------------------
def hash_file(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

def restaurar_hosts_si_fue_modificado():
    if os.path.exists(BACKUP_PATH) and hash_file(HOSTS_PATH) != hash_file(BACKUP_PATH):
        subprocess.call(f'copy "{BACKUP_PATH}" "{HOSTS_PATH}" /Y', shell=True)

def restaurar_dns_si_fue_modificado():
    for interface in INTERFACES:
        try:
            result = subprocess.check_output(
                f'netsh interface ip show dns "{interface}"', shell=True, text=True
            )
            if not all(dns in result for dns in DNS_GOOD):
                configurar_dns()
        except:
            pass

# ----------------- Auto inicio -------------------
def agregar_a_inicio():
    ruta_script = os.path.realpath(sys.argv[0])
    nombre = os.path.splitext(os.path.basename(ruta_script))[0] + ".lnk"
    carpeta_inicio = os.path.join(os.getenv('APPDATA'), r"Microsoft\Windows\Start Menu\Programs\Startup")
    acceso_directo = os.path.join(carpeta_inicio, nombre)

    if not os.path.exists(acceso_directo):
        import winshell
        from win32com.client import Dispatch

        shell = Dispatch('WScript.Shell')
        shortcut = shell.CreateShortCut(acceso_directo)
        shortcut.Targetpath = ruta_script
        shortcut.WorkingDirectory = os.path.dirname(ruta_script)
        shortcut.save()

# ----------------- Ventana UI -------------------
def mostrar_ventana_donacion():
    ventana = tk.Tk()
    ventana.title("Bloqueador NoMore")
    ventana.geometry("640x480")

    # Título
    label = tk.Label(ventana, text="NoMore porno en tu vida", font=("Helvetica", 14, "bold"), pady=10)
    label.pack()

    # Párrafo adicional
    parrafo = tk.Label(
        ventana,
        text="Digo, pues: Andad en el Espíritu, y no satisfagáis los deseos de la carne.\n\nGálatas 5:16\n\nEste programa bloquea automáticamente el acceso a contenido explícito.\n\nGracias por usar NoMore.",
        font=("Helvetica", 10),
        wraplength=350,
        justify="center",
        fg="gray"
    )
    parrafo.pack()

    # Enlace de donación
    enlace = tk.Label(ventana, text="Haz tu donación aquí", fg="blue", cursor="hand2", font=("Helvetica", 10, "underline"))
    enlace.pack(pady=10)

    # Función para abrir la URL
    import webbrowser
    def abrir_donacion(event):
        webbrowser.open("paypal.me/Avmich")

    enlace.bind("<Button-1>", abrir_donacion)

    ventana.mainloop()

# ----------------- Programa principal -------------------
if __name__ == "__main__":
    if not is_admin():
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 1)
        sys.exit()

    bloquear_hosts()
    configurar_dns()
    agregar_a_inicio()
    mostrar_ventana_donacion()

    while True:
        restaurar_hosts_si_fue_modificado()
        restaurar_dns_si_fue_modificado()
        time.sleep(60)  # cada 60 segundos