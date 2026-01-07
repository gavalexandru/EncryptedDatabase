"""Modul pentru testarea automata a aplicatiei EncryptedDatabase.

Acest fisier contine suite de teste unitare si de integrare care verifica:
1. Logica interna a componentelor de criptare si baza de date.
2. Interfata CLI prin simularea comenzilor in terminal.
3. Gestionarea erorilor si a cazurilor limita.
"""

import unittest
import os
import shutil
import json
import subprocess  
import sys         
import re
from src.database_manager import DatabaseManager
from src.crypto import CryptoManager

class TestEncryptedDatabase(unittest.TestCase):
    """Suita de teste unitare pentru componentele logice ale sistemului.
    
    Verifica functionarea izolata a metodelor din CryptoManager si 
    DatabaseManager fara a depinde de interfata CLI.
    """

    def setUp(self):
        """Pregateste mediul de testare inainte de fiecare test.
        
        Creeaza directoare temporare pentru stocare, chei, si initializeaza
        instantele managerilor.
        """

        self.test_dir = "test_db_storage"
        self.keys_dir = "test_keys"
        self.db = DatabaseManager(base_dir=self.test_dir)
        self.crypto = CryptoManager(keys_dir=self.keys_dir)
        self.password = "test_password"

    def tearDown(self):
        """Curata mediul de testare dupa finalizarea fiecarui test.
        
        Sterge directoarele temporare si fisierele create in timpul testelor
        pentru a asigura un mediu curat pentru urmatoarea rulare.
        """

        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
        if os.path.exists(self.keys_dir):
            shutil.rmtree(self.keys_dir)
        if os.path.exists("test_file.txt"):
            os.remove("test_file.txt")
        if os.path.exists("restored_1_test_file.txt"):
            os.remove("restored_1_test_file.txt")

    def test_setup_storage(self):
        """Verifica daca infrastructura de stocare este creata corect.
        
        Asigura existenta directorului vault si a fisierului metadata.json
        cu schema initiala corecta.
        """

        self.db.setup_storage()
        self.assertTrue(os.path.exists(self.db.vault_path)) 
        self.assertTrue(os.path.exists(self.db.metadata_file)) 
        
        with open(self.db.metadata_file, 'r') as f:
            data = json.load(f)
            self.assertEqual(data["next_id"], 1) 

    def test_key_generation(self):
        """Verifica generarea si salvarea perechii de chei RSA.
        
        Asigura ca fisierele .pem sunt create si ca managerul recunoaste
        existenta acestora.
        """

        self.crypto.generate_key_pair(self.password)
        self.assertTrue(os.path.exists(self.crypto.private_key_path)) 
        self.assertTrue(os.path.exists(self.crypto.public_key_path))  
        self.assertTrue(self.crypto.keys_exist()) 

    def test_add_file_to_db(self):
        """Verifica inregistrarea corecta a unui fisier in metadate.
        
        Testeaza daca UID-ul este generat incremental si daca calea fisierului
        este salvata in format absolut.
        """

        self.db.setup_storage()
        self.crypto.generate_key_pair(self.password)
        
        content = b"Ana are mere"
        with open("test_file.txt", "wb") as f:
            f.write(content)
            
        encrypted_data = self.crypto.encrypt_data(content) 
        uid = self.db.add_file_entry("test_file.txt", "enc_test_file", self.crypto.key_id)
        
        self.assertEqual(uid, 1) 
        files = self.db.get_all_files()
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0]["filename"], os.path.abspath("test_file.txt")) 

    def test_decryption_integrity(self):
        """Verifica daca datele decriptate sunt identice cu cele originale.
        
        Acesta este un test critic pentru integritatea procesului de 
        criptare/decriptare RSA-OAEP.
        """

        self.crypto.generate_key_pair(self.password)
        original_data = b"Ana are mere"
        
        ciphertext = self.crypto.encrypt_data(original_data)
        
        decrypted_data = self.crypto.decrypt_data(ciphertext, self.password)
        
        self.assertEqual(original_data, decrypted_data) 

    def test_secure_deletion(self):
        """Verifica stergerea completa a unui fisier si a metadatelor sale.
        
        Asigura ca fisierul criptat dispare de pe disc si intrarea este
        eliminata din metadata.json.
        """

        self.db.setup_storage()
        uid = self.db.add_file_entry("dummy.txt", "enc_dummy", self.crypto.key_id)
        
        dummy_vault_path = os.path.join(self.db.vault_path, "enc_dummy")
        with open(dummy_vault_path, "w") as f: f.write("data")
        
        success = self.db.delete_by_uid(uid)
        
        self.assertTrue(success)
        self.assertFalse(os.path.exists(dummy_vault_path)) 
        self.assertEqual(len(self.db.get_all_files()), 0) 

    def test_incorrect_password(self):
        """Verifica comportamentul sistemului la introducerea unei parole gresite.
        
        Asigura ca decriptarea esueaza si ridica o exceptie atunci cand
        parola nu poate debloca cheia privata.
        """

        self.crypto.generate_key_pair(self.password)

        self.assertFalse(self.crypto.validate_password("parola_gresita"))
    
        content = b"Ana are mere"
        ciphertext = self.crypto.encrypt_data(content) 
    
        with self.assertRaises(Exception):
            self.crypto.decrypt_data(ciphertext, "parola_gresita")

    def test_non_existent_source_file(self):
        """Verifica comportamentul sistemului in cazul unui fisier sursa lipsa.
        
        Asigura ca path-ul definit pentru test nu este prezent pe disc, 
        prevenind astfel erori de citire in timpul testelor de adaugare.
        """

        file_path = "fisier_inexistent.txt"
        self.assertFalse(os.path.exists(file_path))

    def test_corrupted_metadata(self):
        """Verifica rezilienta sistemului la fisiere de metadate invalide.
        
        Asigura ca aplicatia nu crapa daca JSON-ul de metadate este corupt,
        returnand o lista goala de fisiere.
        """

        self.db.setup_storage() 

        with open(self.db.metadata_file, "w") as f:
            f.write("{ invalid json content ...")
    
        files = self.db.get_all_files()
        self.assertEqual(files, [])

    def test_missing_keys(self):
        """Verifica detectarea si gestionarea lipsei cheilor RSA de pe disc.
        
        Simuleaza o stare de eroare prin stergerea manuala a cheii private 
        dupa generare. Verifica daca managerul recunoaste lipsa cheilor si 
        daca metoda de decriptare arunca corect FileNotFoundError.
        """

        self.crypto.generate_key_pair(self.password)
        
        if os.path.exists(self.crypto.private_key_path):
            os.remove(self.crypto.private_key_path)
            
        self.assertFalse(self.crypto.keys_exist())
        
        with self.assertRaises(FileNotFoundError):
            self.crypto.decrypt_data(b"date_criptate", self.password)


class TestEncryptedDatabaseCLI(unittest.TestCase):
    """Suita de teste de integrare pentru interfata CLI.
    
    Aceasta clasa simuleaza interactiunea reala a unui utilizator cu scriptul
    main.py, verificand daca modulele crypto, database si logger colaboreaza
    corect in urma comenzilor primite.
    """

    def setUp(self):
        """Pregateste mediul pentru un nou test CLI.
        
        Asigura un punct de plecare curat prin eliminarea urmelor anterioare
        si definirea constantelor de test precum numele fisierului si parola.
        """

        self.cleanup_env()
        self.filename = "cli_test.txt"
        self.content = "Ana are mere"
        self.password = "parola123"

    def tearDown(self):
        """Finalizeaza testul CLI prin curatarea mediului.
        
        Garanteaza ca dupa executia testelor nu raman fisiere reziduale sau
        directoare de test pe disc.
        """

        self.cleanup_env()

    def cleanup_env(self):
        """Metoda utilitara pentru eliminarea tuturor resurselor de test.
        
        Sterge directoarele 'db_storage' si 'keys', fisierul 'app.log', precum
        si orice fisier temporar sau restaurat generat in timpul rularii.
        """

        for path in ["db_storage", "keys", "app.log"]:
            if os.path.exists(path):
                if os.path.isdir(path): shutil.rmtree(path)
                else: os.remove(path)
        
        for f in os.listdir("."):
            if f.startswith("cli_test") or f.startswith("restored_"):
                os.remove(f)

    def test_cli_complete_workflow(self):
        """Verifica fluxul complet de utilizare a aplicatiei prin terminal.
        
        Executa secvential urmatorii pasi:
        1. 'add' - Verifica daca fisierul este criptat si salvat.
        2. 'list' - Confirma prezenta fisierului in lista de metadate.
        3. 'read' - Testeaza restaurarea continutului original prin parola.
        4. 'delete' - Verifica eliminarea definitiva a datelor.
        5. 'log' - Valideaza inregistrarea actiunilor in app.log.
        """
        
        with open(self.filename, "w") as f:
            f.write(self.content)

        
        add_result = subprocess.run(
            [sys.executable, 'main.py', 'add', self.filename],
            input=f"{self.password}\n",
            capture_output=True, text=True, encoding='utf-8'
        )
        
        self.assertIn("[OK] Fisier securizat cu succes.", add_result.stdout)
        
        match = re.search(r"ID: \((\d+)\)", add_result.stdout)
        self.assertIsNotNone(match, "ID-ul nu a putut fi extras din output-ul ADD")
        file_id = match.group(1)

        list_proc = subprocess.run(
            [sys.executable, 'main.py', 'list'],
            capture_output=True, text=True, encoding='utf-8'
        )
        self.assertIn("[INFO] Fisiere protejate in vault:", list_proc.stdout)
        self.assertIn(self.filename, list_proc.stdout)

        expected_restored_name = f"restored_{file_id}_{self.filename}"
        
        read_proc = subprocess.run(
            [sys.executable, 'main.py', 'read', self.filename],
            input=f"{self.password}\n",
            capture_output=True, text=True, encoding='utf-8'
        )
        
        self.assertIn(f"[OK] Fisierul a fost refacut cu numele: {expected_restored_name}", read_proc.stdout)
        
        self.assertTrue(os.path.exists(expected_restored_name), "Fisierul restaurat nu exista pe disc")
        with open(expected_restored_name, "r") as f:
            restored_content = f.read()
        self.assertEqual(self.content, restored_content, "Continutul decriptat difera de cel original")

        delete_proc = subprocess.run(
            [sys.executable, 'main.py', 'delete', self.filename],
            input=f"{self.password}\n",
            capture_output=True, text=True, encoding='utf-8'
        )
        self.assertIn("[OK] Fisierul a fost eliminat definitiv.", delete_proc.stdout)

        final_list = subprocess.run(
            [sys.executable, 'main.py', 'list'],
            capture_output=True, text=True, encoding='utf-8'
        )
        self.assertIn("[INFO] Baza de date este goala.", final_list.stdout)
        self.assertNotIn(self.filename, final_list.stdout)

        log_file = "app.log"
        self.assertTrue(os.path.exists(log_file), "Fisierul de log 'app.log' nu a fost creat.")
        
        with open(log_file, "r", encoding='utf-8') as f:
            log_content = f.read()
            
        expected_log_message = f"Fisier decriptat: {self.filename}, ID: {file_id}"
        
        self.assertIn(expected_log_message, log_content, f"Mesajul de log asteptat '{expected_log_message}' nu a fost gasit")
        

if __name__ == "__main__":
    unittest.main()