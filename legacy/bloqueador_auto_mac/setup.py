from setuptools import setup

APP = ['nomore_mac.py']

OPTIONS = {
    'argv_emulation': True,
    'packages': ['tkinter'],
    'iconfile': 'nomore.icns'  # Solo si tienes un icono .icns
}

setup(
    app=APP,
    options={'py2app': OPTIONS},
    setup_requires=['py2app'],
)
