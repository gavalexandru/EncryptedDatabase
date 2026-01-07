"""Modul principal pentru interfata in linie de comanda (CLI).

Acest script permite utilizatorului sa gestioneze un seif de fisiere criptate
prin comenzi simple. Coordoneaza initializarea bazei de date, verificarea
cheilor RSA si executia operatiunilor de adaugare, citire si stergere.
"""

import os
import time
import sys
from src.database_manager import DatabaseManager
from src.crypto import CryptoManager
from src.logger import log_message, log_error

def add(file_path, crypto, db):
    """Cripteaza si adauga un fisier in baza de date si in vault.
    
    Citeste continutul brut al fisierului, il cripteaza folosind cheia publica
    si salveaza rezultatul intr-un fisier nou in directorul vault. Inregistreaza
    metadatele necesare in metadata.json.
    """
    try:
        if not os.path.exists(file_path):
            print(f"[EROARE] Fisierul '{file_path}' nu exista.")
            log_error(f"Nu s-a putut adauga fisierul: {file_path} in db fiindca nu exista.")
            return
    
        with open(file_path, "rb") as f:
            data = f.read()

        encrypted_data = crypto.encrypt_data(data)
        encrypted_filename = f"enc_{int(time.time())}_{os.path.basename(file_path)}"
            
        vault_file_path = os.path.join(db.vault_path, encrypted_filename)
        with open(vault_file_path, "wb") as f:
            f.write(encrypted_data)
            
        uid = db.add_file_entry(file_path, encrypted_filename, crypto.key_id)
        print(f"[OK] Fisier securizat cu succes. ID: ({uid})")
        log_message(f"Fisier adaugat cu succes. ID: {uid}, Cale: {file_path}")

    except Exception as e:
        print(f"[EROARE] A aparut o problema neprevazuta la adaugarea fisierului criptat: {file_path} in baza de date: {e}")
        log_error(f"A aparut o problema neprevazuta la adaugarea fisierului criptat: {file_path} in baza de date: {e}")

def read(file_path, crypto, db):
    """Recupereaza si decripteaza un fisier pe baza numelui sau.
    
    Cauta fisierul in metadate. Daca exista mai multe versiuni sau fisiere cu
    acelasi nume, solicita utilizatorului alegerea unui ID specific. Dupa
    validarea parolei si a cheii, restaureaza fisierul original.
    """

    matches = db.find_all_matches(file_path)

    if not matches:
        print(f"[EROARE] Nu a fost gasit niciun fisier cu numele: {file_path} pentru a-l putea decripta.")
        log_error(f"Fisierul: {file_path} nu exista pentru a putea fi decriptat")
    elif len(matches) == 1:
        if matches[0]["key_id"] != crypto.key_id:
            print("[EROARE CRITICA] Cheia asociata fisierului nu este disponibila.")
            log_error(
                f"Cheie nepotrivita pentru fisierul cu ID-ul: {matches[0]['uid']}. "
                f"Cheia asteptata pentru fisier: {matches[0]['key_id']}, Cheia curenta={crypto.key_id}"
            )
            return

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
            log_message(f"Fisier decriptat: {original_name}, ID: {file_id}")

        except Exception:
            print("[EROARE] Parola incorecta sau fisier corupt.")
            log_error(f"Nu s-a putut citi fisierul cu numele: {os.path.basename(matches[0]['filename'])}, ID: {matches[0]['uid']}, deoarece parola este incorecta sau fisierul este corupt.")
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

                    if file["key_id"] != crypto.key_id:
                        print("[EROARE CRITICA] Cheia asociata fisierului nu este disponibila.")
                        log_error(
                        f"Cheie nepotrivita pentru fisierul cu ID-ul: {file['uid']}. "
                        f"Cheia asteptata pentru fisier: {file['key_id']}, Cheia curenta={crypto.key_id}"
                        )
                        return

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
                        log_message(f"Fisier decriptat: {original_name}, ID: {file_id}")

                    except Exception:
                        print(f"[EROARE] Parola incorecta sau fisier corupt.")
                        log_error(f"Nu s-a putut citi fisierul cu numele: {os.path.basename(file['filename'])}, ID: {file['uid']}, deoarece parola este incorecta sau fisierul este corupt.")

                    break
        
            if not found:
                print(f"[EROARE] ID-ul {choice} nu se afla in lista de rezultate.")
                log_error(f"ID-ul {choice} nu se afla in lista de rezultate.")
        except ValueError:
            print(f"[EROARE] Te rugam sa introduci un numar valid pentru UID.")
            log_error(f"UID invalid")

def delete(file_path, crypto, db):
    """Sterge un fisier din sistemul securizat.
    
    Solicita parola de protectie a cheii private pentru a valida identitatea
    utilizatorului inainte de a elimina definitiv fisierul din vault si
    intrarea acestuia din metadate.
    """

    matches = db.find_all_matches(file_path)

    if not matches:
        print(f"[EROARE] Nu a fost gasit niciun fisier cu numele: {file_path} pentru a-l putea sterge.")
        log_error(f"Fisierul: {file_path} nu exista pentru a putea fi decriptat")
    elif len(matches) == 1:
        pwd = input("Parola pentru a sterge fisierul: ")
        
        if crypto.validate_password(pwd):
            if db.delete_by_uid(matches[0]['uid']):
                print(f"[OK] Fisierul a fost eliminat definitiv.")
                log_message(f"Fisierul: {matches[0]['filename']}, avand ID: {matches[0]['uid']} a fost eliminat definitiv.")
        else:
            print("[EROARE] Parola incorecta. Stergerea a fost refuzata.")
            log_error(f"Nu s-a putut citi fisierul cu numele: {os.path.basename(matches[0]['filename'])}, ID: {matches[0]['uid']}, deoarece parola este incorecta sau fisierul este corupt.")
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
                            log_message(f"Fisierul: {file['filename']}, avand ID: {file['uid']} a fost eliminat definitiv.")

                    else:
                        print("[EROARE] Parola incorecta. Stergerea a fost refuzata.")
                        log_error(f"Nu s-a putut citi fisierul cu numele: {os.path.basename(file['filename'])}, ID: {file['uid']}, deoarece parola este incorecta sau fisierul este corupt.")

                    break

            if not found:
                print(f"[EROARE] ID-ul {choice} nu se afla in lista de rezultate.")
                log_error(f"ID-ul {choice} nu se afla in lista de rezultate.")
        except ValueError:
            print(f"[EROARE] Te rugam sa introduci un numar valid pentru UID.")
            log_error(f"UID invalid")

def help():
    """Afiseaza instructiunile de utilizare si comenzile disponibile in CLI."""

    print("""
    Encrypted Database CLI - Comenzi disponibile:
    add <fisier>    - Cripteaza si adaugă un fisier
    read <nume>     - Decripteaza si afisează continutul
    delete <nume>   - Sterge fisierul si metadatele
    list            - Afisează toate fisierele protejate
    """)

def main():
    """Punctul de intrare principal in aplicatie.
    
    Se ocupa de setup-ul initial, validarea conectivitatii la baza de date,
    detectarea sau generarea cheilor RSA si rutarea comenzilor din linia
    de comanda catre functiile corespunzatoare.
    """
    
    db = DatabaseManager()
    db.setup_storage()

    if db.validate_connectivity():
        print("[OK] Conexiunea la baza de date a fost validata.")
    else:
        print("[EROARE] Conexiunea la baza de date a esuat.")

    crypto = CryptoManager()

    if not crypto.keys_exist():
        if db.get_all_files():
            print("[EROARE CRITICA] Cheia privata lipseste, dar exista fisiere criptate.")
            print("Datele NU mai pot fi recuperate.")
            log_error("Cheia privata lipseste. Date criptate existente. Operatie oprita.")
            return
        else:
            print("[!] Cheile RSA lipsesc. Generam o pereche noua.")
            log_message("Cheile RSA lipsesc. Generam o pereche noua.", "Warning")

            password = input("Setati parola pentru protejarea cheii private: ")
            crypto.generate_key_pair(password)

            print("[OK] Perechea de chei a fost generata si salvata.")
            log_message("Pereche noua de chei RSA generata")
    else:
        print("[INFO] Cheile RSA au fost detectate.")
        log_message("Cheile RSA au fost detectate.")

    if len(sys.argv) < 2:
        help()
        return
    
    command = sys.argv[1]

    if command == "list":
        files = db.get_all_files()
        if not files:
            print("[INFO] Baza de date este goala.")
        else:
            print("[INFO] Fisiere protejate in vault:")
            for file in files:
                name = os.path.basename(file['filename'])
                print(f" ({file['uid']}) {name} -> {file['filename']}")
    elif command == "add":
        if len(sys.argv) < 3:
            print("[Eroare] Specificati fisierul.")
            return
        add(sys.argv[2],crypto,db)
    elif command == "read":
        if len(sys.argv) < 3:
            print("[Eroare] Specificati fisierul.")
            return
        read(sys.argv[2],crypto,db)
    elif command == "delete":
        if len(sys.argv) < 3:
            print("[Eroare] Specificati fisierul.")
            return
        delete(sys.argv[2],crypto,db)
    else:
        print("[Eroare] Comanda invalida.")
        help()

if __name__ == "__main__":
    main()