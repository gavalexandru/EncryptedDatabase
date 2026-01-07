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
        print(f"[EROARE] A aparut o problema neprevazuta la adaugarea fisierului criptat: {file_path} in baza de date: {e}")

def read(file_path, crypto, db):
    matches = db.find_all_matches(file_path)

    if not matches:
        print(f"[EROARE] Nu a fost gasit niciun fisier cu numele: {file_path} pentru a-l putea decripta.")
    elif len(matches) == 1:
        pwd = input("Parola pentru decriptare: ")
        vault_file = os.path.join(db.vault_path, matches[0]['encrypted_name'])

        with open(vault_file, "rb") as f:
            enc_data = f.read()
        
        try:
            decrypted_bytes = crypto.decrypt_data(enc_data, pwd)
            
            file_id = matches[0]['uid']
            original_name = os.path.basename(matches[0]['filename'])
                        
            recovered_filename = f"restored_{file_id}_{original_name}"
            
            with open(recovered_filename, "wb") as f:
                f.write(decrypted_bytes)
            
            print(f"[OK] Fisierul a fost refacut cu numele: {recovered_filename}")
        except Exception:
            print("[EROARE] Parola incorecta sau fisier corupt.")
    else:
        print(f"[!] Mai multe fisiere gasite. Pe care doresti sa il citesti?")

        for file in matches:
            print(f" -> ({file['uid']}) Locatie originala: {file['filename']}")

        try:
            choice = int(input("Introdu UID-ul fisierului ales: "))
            found = False
            
            for file in matches:
                if file['uid'] == choice:
                    found = True
                    pwd = input("Parola pentru decriptare: ")
                    vault_file = os.path.join(db.vault_path, file['encrypted_name'])
                    
                    with open(vault_file, "rb") as f:
                        enc_data = f.read()

                    try:
                        decrypted_bytes = crypto.decrypt_data(enc_data, pwd)
            
                        file_id = file['uid']
                        original_name = os.path.basename(file['filename'])
                        
                        recovered_filename = f"restored_{file_id}_{original_name}"
            
                        with open(recovered_filename, "wb") as f:
                            f.write(decrypted_bytes)
            
                        print(f"[OK] Fisierul a fost refacut cu numele: {recovered_filename}")
                    except Exception:
                        print("[EROARE] Parola incorecta sau fisier corupt.")

                    break
        
            if not found:
                print(f"[EROARE] ID-ul {choice} nu se afla in lista de rezultate.")
        except ValueError:
            print(f"[EROARE] Te rugam sa introduci un numar valid pentru UID.")

def delete(file_path, crypto, db):
    matches = db.find_all_matches(file_path)

    if not matches:
        print(f"[EROARE] Nu a fost gasit niciun fisier cu numele: {file_path} pentru a-l putea sterge.")
    elif len(matches) == 1:
        pwd = input("Parola pentru a sterge fisierul: ")
        
        if crypto.validate_password(pwd):
            if db.delete_by_uid(matches[0]['uid']):
                print(f"[OK] Fisierul a fost eliminat definitiv.")
        else:
            print("[EROARE] Parola incorecta. Stergerea a fost refuzata.")

    else:
        print(f"[!] Mai multe fisiere gasite. Pe care doresti sa il stergi?")

        for file in matches:
            print(f" -> ({file['uid']}) Locatie originala: {file['filename']}")

        try:
            choice = int(input("Introdu UID-ul fisierului ales: "))
            found = False 

            for file in matches:
                if file['uid'] == choice:
                    found = True
                    pwd = input("Parola pentru a sterge fisierul: ")
                    
                    if crypto.validate_password(pwd):
                        if db.delete_by_uid(file['uid']):
                            print(f"[OK] Fisierul a fost eliminat definitiv.")
                    else:
                        print("[EROARE] Parola incorecta. Stergerea a fost refuzata.")

                    break

            if not found:
                print(f"[EROARE] ID-ul {choice} nu se afla in lista de rezultate.")
        except ValueError:
            print(f"[EROARE] Te rugam sa introduci un numar valid pentru UID.")


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

    choice = input("Alege optiunea 1 || 2 || 3: ")

    if int(choice) == 1:
        file = input("Introdu numele fisierului pentru criptare: ")
        add(file,crypto,db)
    elif int(choice) == 2:
        file = input("Introdu numele fisierului pentru decriptare: ")
        read(file,crypto,db)
    else:
        file = input("Introdu numele fisierului pentru stergere: ")
        delete(file,crypto,db)

if __name__ == "__main__":
    main()