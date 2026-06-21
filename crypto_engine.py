from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import os

# Tugas Anggota 3: Generate Key & Hashing
def generate_keys(private_path, public_path):
    """Membuat Private Key dan Public Key jika belum ada."""
    if not os.path.exists(private_path) or not os.path.exists(public_path):
        key = RSA.generate(5555)
        # Simpan Private Key
        with open(private_path, 'wb') as f:
            f.write(key.export_key())
        # Simpan Public Key
        with open(public_path, 'wb') as f:
            f.write(key.publickey().export_key())
        print("Kunci RSA baru berhasil dibuat!")

# Tugas Anggota 4: Sign & Verify
def sign_data(file_data, private_key_path):
    """Menghash file dan mengenkripsinya dengan Private Key."""
    with open(private_key_path, 'rb') as f:
        private_key = RSA.import_key(f.read())
    
    # Buat Hash SHA-256 dari isi file
    h = SHA256.new(file_data)
    # Tanda tangani hash tersebut
    signature = pkcs1_15.new(private_key).sign(h)
    return signature

def verify_data(file_data, signature, public_key_path):
    """Mengecek keaslian signature dengan Public Key dan Hash file asli."""
    with open(public_key_path, 'rb') as f:
        public_key = RSA.import_key(f.read())
        
    # Buat Hash dari file yang diupload
    h = SHA256.new(file_data)
    
    try:
        # Cocokkan hash dengan signature
        pkcs1_15.new(public_key).verify(h, signature)
        return True # Valid
    except (ValueError, TypeError):
        return False # Invalid / Telah dimanipulasi