import os
import time
from src.database_manager import DatabaseManager
from src.crypto import CryptoManager

def add(file_path, crypto, db):
    try:
        if not os.path.exists(file_path):
            print(f"[EROARE] Fisierul '{file_path}' nu exista.")
            return
    
        with open(file_path, "rb") as f:
            data = f.read()

        encrypted_data = crypto.encrypt_data(data)
        encrypted_filename = f"enc_{int(time.time())}_{os.path.basename(file_path)}"
            
        vault_file_path = os.path.join(db.vault_path, encrypted_filename)
        with open(vault_file_path, "wb") as f:
            f.write(encrypted_data)
            
        uid = db.add_file_entry(file_path, encrypted_filename, "RSA_KEY_2048")
        print(f"[OK] Fisier securizat cu succes. ID: ({uid})")
    except Exception as e:
        print(f"[EROARE] A apărut o problema neprevazuta la adaugarea fisierului criptat: {file_path} in baza de date: {e}")


def main():
    db = DatabaseManager()
    db.setup_storage()

    if db.validate_connectivity():
        print("[OK] Conexiunea la baza de date a fost validata.")
    else:
        print("[EROARE] Conexiunea la baza de date a esuat.")

    crypto = CryptoManager()

    if not crypto.keys_exist():
        print("[!] Cheile RSA lipsesc. Generam o pereche noua.")
        password = input("Setati parola pentru protejarea cheii private: ")
        crypto.generate_key_pair(password)
        print("[OK] Perechea de chei a fost generata si salvata.")
    else:
        print("[INFO] Cheile RSA au fost detectate.")

    file = input("Introdu numele unui fisier: ")
    add(file,crypto,db)

if __name__ == "__main__":
    main()