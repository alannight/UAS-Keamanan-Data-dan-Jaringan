from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import os


def generate_keys(private_path, public_path):
    """
    Membuat pasangan Private Key dan Public Key RSA jika belum ada.
    Menggunakan ukuran kunci 2048 bit (standar industri yang aman).
    """
    if not os.path.exists(private_path) or not os.path.exists(public_path):
        # FIX: 5555 tidak valid — RSA key harus kelipatan 256.
        # Gunakan 2048 (cepat) atau 4096 (lebih aman tapi lebih lambat).
        key = RSA.generate(2048)

        with open(private_path, 'wb') as f:
            f.write(key.export_key())

        with open(public_path, 'wb') as f:
            f.write(key.publickey().export_key())

        print("[INFO] Pasangan kunci RSA-2048 baru berhasil dibuat.")
    else:
        print("[INFO] Kunci RSA sudah ada, menggunakan kunci yang tersimpan.")


def sign_data(file_data: bytes, private_key_path: str) -> bytes:
    """
    Membuat digital signature dari data file menggunakan Private Key.
    Algoritma: RSA-PKCS#1 v1.5 dengan hash SHA-256.
    """
    with open(private_key_path, 'rb') as f:
        private_key = RSA.import_key(f.read())

    # Hash isi file dengan SHA-256
    h = SHA256.new(file_data)

    # Tanda tangani hash dengan private key
    signature = pkcs1_15.new(private_key).sign(h)
    return signature


def verify_data(file_data: bytes, signature: bytes, public_key_path: str) -> bool:
    """
    Memverifikasi digital signature menggunakan Public Key.
    Return True jika valid, False jika tidak valid atau sudah dimodifikasi.
    """
    with open(public_key_path, 'rb') as f:
        public_key = RSA.import_key(f.read())

    # Hash file yang diupload
    h = SHA256.new(file_data)

    try:
        # Bandingkan hash dengan signature menggunakan public key
        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False
