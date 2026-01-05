from src.database_manager import DatabaseManager

def main():
    db = DatabaseManager()
    db.setup_storage()

    if db.validate_connectivity():
        print("[OK] Conexiunea la baza de date a fost validata.")
    else:
        print("[EROARE] Conexiunea la baza de date a esuat.")

if __name__ == "__main__":
    main()