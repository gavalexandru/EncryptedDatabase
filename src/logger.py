"""Modul pentru jurnalizarea activitatii aplicatiei.

Ofera functii pentru scrierea mesajelor de stare si a erorilor intr-un fisier
log persistent numit app.log.
"""

import time
import os

def log_message(message, level="INFO"):
    """Scrie un mesaj formatat in fisierul de log cu timestamp inclus."""

    timestamp = time.ctime()
    log_line = f"[{timestamp}] {level}: {message}\n"
    log_file = "app.log"
    
    try:
        with open(log_file, "at", encoding="utf-8") as f:
            f.write(log_line)
    except Exception as e:
        print(f"Eroare la scrierea in log: {e}")

def log_error(message):
    """Functie ajutatoare pentru inregistrarea erorilor in sistem."""

    log_message(message, level="ERROR")