from flask import Flask, render_template, request, send_file, flash, redirect, url_for
from werkzeug.utils import secure_filename
import os
from crypto_engine import generate_keys, sign_data, verify_data

app = Flask(__name__)
app.secret_key = "kunci_rahasia_untuk_flash_message" # Bebas diisi apa saja

# Konfigurasi Folder
UPLOAD_FOLDER = 'uploads'
KEYS_FOLDER = 'keys'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

PRIVATE_KEY = os.path.join(KEYS_FOLDER, 'private.pem')
PUBLIC_KEY = os.path.join(KEYS_FOLDER, 'public.pem')

# Pastikan folder dan kunci tersedia saat server berjalan
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(KEYS_FOLDER, exist_ok=True)
generate_keys(PRIVATE_KEY, PUBLIC_KEY)

# --- ROUTING (Tugas Anggota 5 & 6) ---

@app.route('/', methods=['GET', 'POST'])
def sign_page():
    if request.method == 'POST':
        if 'pdf_file' not in request.files:
            return redirect(request.url)
        
        file = request.files['pdf_file']
        if file.filename == '' or not file.filename.endswith('.pdf'):
            flash("Harap unggah file berformat PDF!", "danger")
            return redirect(request.url)

        # Proses Sign
        file_data = file.read()
        signature = sign_data(file_data, PRIVATE_KEY)
        
        # Simpan file signature sementara untuk didownload
        sig_filename = secure_filename(file.filename) + ".sig"
        sig_path = os.path.join(app.config['UPLOAD_FOLDER'], sig_filename)
        with open(sig_path, 'wb') as f:
            f.write(signature)
            
        return send_file(sig_path, as_attachment=True)

    return render_template('index.html')

@app.route('/verify', methods=['GET', 'POST'])
def verify_page():
    if request.method == 'POST':
        pdf_file = request.files.get('pdf_file')
        sig_file = request.files.get('sig_file')
        
        if not pdf_file or not sig_file:
            flash("Harap unggah kedua file (PDF dan .sig)!", "warning")
            return redirect(request.url)
            
        # Baca data dari kedua file
        pdf_data = pdf_file.read()
        sig_data = sig_file.read()
        
        # Proses Verify
        is_valid = verify_data(pdf_data, sig_data, PUBLIC_KEY)
        
        if is_valid:
            flash("DOKUMEN VALID: Dokumen asli dan belum dimodifikasi.", "success")
        else:
            flash("DOKUMEN INVALID: Dokumen palsu atau telah dimodifikasi!", "danger")
            
        return redirect(url_for('verify_page'))

    return render_template('verify.html')

if __name__ == '__main__':
    app.run(debug=True) 