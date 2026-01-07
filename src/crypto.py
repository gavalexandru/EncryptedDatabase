"""Modul pentru gestionarea operatiunilor criptografice RSA.

Acest modul ofera functionalitati pentru generarea perechilor de chei,
stocarea securizata a acestora si procesarea criptarii/decriptarii datelor
folosind algoritmul RSA cu padding OAEP.
"""

import os 
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

class CryptoManager:
    """Gestioneaza ciclul de viata al cheilor RSA si transformarile criptografice.

    Atribute:
        keys_dir (str): Directorul unde sunt stocate fisierele .pem.
        private_key_path (str): Calea catre cheia privata.
        public_key_path (str): Calea catre cheia publica.
        key_id (str): Hash-ul SHA-256 al cheii publice pentru identificare.
    """

    def __init__(self, keys_dir="keys"):
        """Initializeaza managerul si verifica existenta directorului de chei."""

        self.keys_dir = keys_dir
        self.private_key_path = os.path.join(self.keys_dir, "private_key.pem")
        self.public_key_path = os.path.join(self.keys_dir, "public_key.pem")

        if not os.path.exists(self.keys_dir):
            os.makedirs(self.keys_dir)

        if os.path.exists(self.public_key_path):
            self.key_id = self.compute_key_id()
        else:
            self.key_id = None

    def generate_key_pair(self, password):
        """Genereaza o pereche de chei RSA de 2048 biti si le salveaza pe disc.

        Cheia privata este criptata folosind parola furnizata de utilizator.
        """

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        pem_private = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
        )

        with open(self.private_key_path, "wb") as f:
            f.write(pem_private)

        public_key = private_key.public_key()

        pem_public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        with open(self.public_key_path, "wb") as f:
            f.write(pem_public)

        self.key_id = self.compute_key_id()

    def keys_exist(self):
        """Verifica daca ambele fisiere de chei exista pe disc."""

        return os.path.exists(self.private_key_path) and os.path.exists(self.public_key_path)
    
    def validate_password(self, password):
        """Valideaza daca parola furnizata poate decripta cheia privata."""

        try:
            with open(self.private_key_path, "rb") as f:
                serialization.load_pem_private_key(
                    f.read(), 
                    password=password.encode()
                )
            return True
        except Exception:
            return False
        
    def encrypt_data(self, plaintext_bytes):
        """Cripteaza datele brute in bucati folosind cheia publica RSA."""

        with open(self.public_key_path, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())

        chunk_size = 190  
        encrypted_chunks = []

        for i in range(0, len(plaintext_bytes), chunk_size):
            chunk = plaintext_bytes[i : i + chunk_size]
            enc_chunk = public_key.encrypt(
                chunk,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            encrypted_chunks.append(enc_chunk)
        
        return b"".join(encrypted_chunks)
    
    def decrypt_data(self, ciphertext, password):
        """Decripteaza datele folosind cheia privata si parola asociata."""

        with open(self.private_key_path, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(), 
                password=password.encode()
            )
        chunk_size = 256  
        decrypted_chunks = []

        for i in range(0, len(ciphertext), chunk_size):
            chunk = ciphertext[i : i + chunk_size]
            dec_chunk = private_key.decrypt(
                chunk,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            decrypted_chunks.append(dec_chunk)

        return b"".join(decrypted_chunks)
    
    def compute_key_id(self):
        """Calculeaza un identificator unic bazat pe hash-ul cheii publice."""
        
        with open(self.public_key_path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()