from src.database_manager import DatabaseManager
from src.crypto import CryptoManager

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

if __name__ == "__main__":
    main()