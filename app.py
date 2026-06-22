from flask import Flask, render_template, request, send_file, flash, redirect, url_for
from werkzeug.utils import secure_filename
import os
from crypto_engine import generate_keys, sign_data, verify_data

app = Flask(__name__)
app.secret_key = "kunci_rahasia_uas_keamanan_data_2024"

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


@app.route('/', methods=['GET', 'POST'])
def sign_page():
    if request.method == 'POST':
        if 'pdf_file' not in request.files:
            flash("Tidak ada file yang diunggah.", "danger")
            return redirect(request.url)

        file = request.files['pdf_file']

        if file.filename == '':
            flash("Harap pilih file terlebih dahulu.", "danger")
            return redirect(request.url)

        if not file.filename.lower().endswith('.pdf'):
            flash("Harap unggah file berformat PDF!", "danger")
            return redirect(request.url)

        # Proses Sign
        file_data = file.read()
        signature = sign_data(file_data, PRIVATE_KEY)

        # Simpan file signature untuk didownload
        original_name = os.path.splitext(secure_filename(file.filename))[0]
        sig_filename = original_name + ".sig"
        sig_path = os.path.join(app.config['UPLOAD_FOLDER'], sig_filename)
        with open(sig_path, 'wb') as f:
            f.write(signature)

        return send_file(sig_path, as_attachment=True, download_name=sig_filename)

    return render_template('index.html')


@app.route('/verify', methods=['GET', 'POST'])
def verify_page():
    if request.method == 'POST':
        pdf_file = request.files.get('pdf_file')
        sig_file = request.files.get('sig_file')

        if not pdf_file or not sig_file:
            flash("Harap unggah kedua file (PDF dan .sig)!", "warning")
            return redirect(request.url)

        if not pdf_file.filename.lower().endswith('.pdf'):
            flash("File pertama harus berformat PDF!", "danger")
            return redirect(request.url)

        if not sig_file.filename.lower().endswith('.sig'):
            flash("File kedua harus berformat .sig!", "danger")
            return redirect(request.url)

        # Baca data dari kedua file
        pdf_data = pdf_file.read()
        sig_data = sig_file.read()

        # Proses Verify
        is_valid = verify_data(pdf_data, sig_data, PUBLIC_KEY)

        if is_valid:
            flash("VALID — Dokumen asli dan belum dimodifikasi.", "success")
        else:
            flash("TIDAK VALID — Dokumen telah dimodifikasi atau tanda tangan tidak cocok.", "danger")

        return redirect(url_for('verify_page'))

    return render_template('verify.html')


if __name__ == '__main__':
    # PENTING: Jalankan dengan `python app.py`, BUKAN dengan VSCode Live Server!
    app.run(debug=True, port=5000)
