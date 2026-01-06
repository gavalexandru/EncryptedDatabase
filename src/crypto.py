import os 
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

class CryptoManager:
    def __init__(self, keys_dir="keys"):
        self.keys_dir = keys_dir
        self.private_key_path = os.path.join(self.keys_dir, "private_key.pem")
        self.public_key_path = os.path.join(self.keys_dir, "public_key.pem")

        if not os.path.exists(self.keys_dir):
            os.makedirs(self.keys_dir)

    def generate_key_pair(self, password):
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

    def keys_exist(self):
        return os.path.exists(self.private_key_path) and os.path.exists(self.public_key_path)
    
    def validate_password(self, password):
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