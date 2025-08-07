import os
import subprocess
import tkinter as tk
import webbrowser

DOMINIOS = [
    "pornhub.com", "xvideos.com", "xnxx.com", "redtube.com",
    "youporn.com", "xhamster.com", "onlyfans.com", "www.pornhub.com",
    "www.xvideos.com", "www.xnxx.com"
]

def bloquear_hosts():
    ruta_hosts = "/etc/hosts"
    bloqueos = "\n# BLOQUEADOR PORNO\n" + "\n".join([f"127.0.0.1 {dom}" for dom in DOMINIOS]) + "\n"

    try:
        with open(ruta_hosts, "a") as f:
            f.write(bloqueos)
    except PermissionError:
        subprocess.call(["osascript", "-e", f'do shell script "echo \'{bloqueos}\' >> {ruta_hosts}" with administrator privileges'])

def configurar_dns():
    # Requiere interfaz activa: en macOS suele ser "Wi-Fi" o similar
    subprocess.call(['networksetup', '-setdnsservers', 'Wi-Fi', '185.228.168.168', '185.228.169.168'])

def agregar_a_inicio():
    script_path = os.path.abspath(__file__)
    plist_path = os.path.expanduser("~/Library/LaunchAgents/com.nomore.blocker.plist")

    plist_content = f"""
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN"
    "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.nomore.blocker</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/python3</string>
        <string>{script_path}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
"""
    with open(plist_path, "w") as f:
        f.write(plist_content)



def mostrar_ventana_donacion():
    ventana = tk.Tk()
    ventana.title("Bloqueador NoMore")
    ventana.geometry("640x480")

    # Título
    label = tk.Label(
        ventana,
        text="NoMore porno en tu vida",
        font=("Helvetica", 14, "bold"),
        pady=10
    )
    label.pack()

    # Párrafo adicional
    parrafo = tk.Label(
        ventana,
        text="Digo, pues: Andad en el Espíritu, y no satisfagáis los deseos de la carne.\n\n"
             "Gálatas 5:16\n\n"
             "Este programa bloquea automáticamente el acceso a contenido explícito.\n\n"
             "Gracias por usar NoMore.",
        font=("Helvetica", 10),
        wraplength=500,
        justify="center",
        fg="gray"
    )
    parrafo.pack(pady=10)

    # Enlace de donación
    enlace = tk.Label(
        ventana,
        text="Haz tu donación aquí",
        fg="blue",
        cursor="hand2",
        font=("Helvetica", 10, "underline")
    )
    enlace.pack(pady=10)

    def abrir_donacion(event):
        webbrowser.open("https://paypal.me/Avmich")

    enlace.bind("<Button-1>", abrir_donacion)

    ventana.mainloop()


if __name__ == "__main__":
    bloquear_hosts()
    configurar_dns()
    agregar_a_inicio()
    mostrar_ventana_donacion()
