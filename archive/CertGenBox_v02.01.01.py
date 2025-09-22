#!/usr/bin/env python
"""
CertGenBox with Tkinter GUI (cryptography + pyOpenSSL version)
This file replaces M2Crypto with cryptography and pyOpenSSL.

Usage:
    python CertGenBox_v03.00.00_gui.py

The GUI lets you: set output path, key size, signature algorithm, CA fields (CN, Email),
certificate subject CN/Email, choose whether to use existing keys, and run generation.
Logs are shown in the GUI and files are written into the chosen directory.
"""

import os, sys, time, threading
import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

DEFAULT_KEYSIZE = 2048
DEFAULT_HASH = 'sha256'
DEFAULT_PATH = "./certs/"

HASH_ALGORITHMS = {
    'sha1': hashes.SHA1(),
    'sha224': hashes.SHA224(),
    'sha256': hashes.SHA256(),
    'sha384': hashes.SHA384(),
    'sha512': hashes.SHA512(),
    'md5': hashes.MD5(),
}

def ensure_path(path):
    try:
        os.makedirs(path, exist_ok=True)
        return True, f"Directory '{path}' ready." 
    except Exception as e:
        return False, str(e)

def save_cert_and_key(cert, key, cert_path, key_path):
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

def mkcert(subject_name, issuer_name=None, issuer_key=None, key=None, sign_alg='sha256',
           not_before=None, not_after=None, serial=1, is_ca=False, key_size=2048):
    if key is None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

    if not_before is None:
        not_before = x509.datetime.datetime.utcnow()
    if not_after is None:
        not_after = not_before + x509.datetime.timedelta(days=365*5)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, subject_name.get('C','AU')),
        x509.NameAttribute(NameOID.COMMON_NAME, subject_name.get('CN','TEST')),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, subject_name.get('Email','demo@example.com')),
    ])

    if issuer_name is None:
        issuer_name = subject

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer_name)
    builder = builder.public_key(key.public_key())
    builder = builder.serial_number(serial)
    builder = builder.not_valid_before(not_before)
    builder = builder.not_valid_after(not_after)

    if is_ca:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)

    if issuer_key is None:
        issuer_key = key

    cert = builder.sign(private_key=issuer_key, algorithm=HASH_ALGORITHMS[sign_alg], backend=default_backend())

    return cert, key

def generate_all(output_path, log_cb=print, use_existing=False, keysize=2048, sign_alg='sha256', ca_cn="TESTCA", ca_email="demo@example.com"):
    ok, msg = ensure_path(output_path)
    log_cb(msg)

    serial = 1000

    # CA
    log_cb("Generating CA certificate")
    ca_subject = {"C":"AU","CN":ca_cn,"Email":ca_email}
    ca_cert, ca_key = mkcert(ca_subject, serial=serial, is_ca=True, key_size=keysize, sign_alg=sign_alg)
    save_cert_and_key(ca_cert, ca_key, os.path.join(output_path,"ca-cert.pem"), os.path.join(output_path,"ca-cert.key"))
    serial += 1

    # Server cert signed by CA
    log_cb("Generating server certificate signed by CA")
    server_subject = {"C":"AU","CN":"server","Email":ca_email}
    server_cert, server_key = mkcert(server_subject, issuer_name=ca_cert.subject, issuer_key=ca_key, serial=serial, key_size=keysize, sign_alg=sign_alg)
    save_cert_and_key(server_cert, server_key, os.path.join(output_path,"server-cert.pem"), os.path.join(output_path,"server-cert.key"))
    serial += 1

    # Expired cert
    log_cb("Generating expired certificate")
    expired_subject = {"C":"AU","CN":"expired","Email":ca_email}
    not_before = x509.datetime.datetime.utcnow() - x509.datetime.timedelta(days=730)
    not_after = x509.datetime.datetime.utcnow() - x509.datetime.timedelta(days=365)
    expired_cert, expired_key = mkcert(expired_subject, issuer_name=ca_cert.subject, issuer_key=ca_key, serial=serial, key_size=keysize, sign_alg=sign_alg, not_before=not_before, not_after=not_after)
    save_cert_and_key(expired_cert, expired_key, os.path.join(output_path,"expired-cert.pem"), os.path.join(output_path,"expired-cert.key"))
    serial += 1

    # Not yet valid cert
    log_cb("Generating not-yet-valid certificate")
    future_subject = {"C":"AU","CN":"future","Email":ca_email}
    not_before = x509.datetime.datetime.utcnow() + x509.datetime.timedelta(days=365)
    not_after = not_before + x509.datetime.timedelta(days=365)
    future_cert, future_key = mkcert(future_subject, issuer_name=ca_cert.subject, issuer_key=ca_key, serial=serial, key_size=keysize, sign_alg=sign_alg, not_before=not_before, not_after=not_after)
    save_cert_and_key(future_cert, future_key, os.path.join(output_path,"future-cert.pem"), os.path.join(output_path,"future-cert.key"))
    serial += 1

    log_cb("Certificate generation finished.")

class CertGenGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('CertGenBox GUI (cryptography)')
        self.geometry('780x520')
        self.create_widgets()

    def create_widgets(self):
        frm = ttk.Frame(self, padding=8)
        frm.pack(fill=tk.BOTH, expand=True)

        left = ttk.Frame(frm)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=(0,10))

        ttk.Label(left, text='Output directory:').pack(anchor='w')
        self.path_var = tk.StringVar(value=DEFAULT_PATH)
        ttk.Entry(left, textvariable=self.path_var, width=40).pack(anchor='w')
        ttk.Button(left, text='Browse...', command=self.browse_path).pack(anchor='w', pady=4)

        ttk.Label(left, text='Key size:').pack(anchor='w', pady=(8,0))
        self.keysize_var = tk.IntVar(value=DEFAULT_KEYSIZE)
        ttk.Entry(left, textvariable=self.keysize_var, width=10).pack(anchor='w')

        ttk.Label(left, text='Signature algorithm:').pack(anchor='w', pady=(8,0))
        self.signalg_var = tk.StringVar(value=DEFAULT_HASH)
        ttk.Combobox(left, textvariable=self.signalg_var, values=list(HASH_ALGORITHMS.keys()), width=12).pack(anchor='w')

        ttk.Label(left, text='CA Common Name:').pack(anchor='w')
        self.ca_cn_var = tk.StringVar(value="TESTCA")
        ttk.Entry(left, textvariable=self.ca_cn_var, width=30).pack(anchor='w')

        ttk.Label(left, text='CA Email:').pack(anchor='w')
        self.ca_email_var = tk.StringVar(value="demo@example.com")
        ttk.Entry(left, textvariable=self.ca_email_var, width=30).pack(anchor='w')

        ttk.Button(left, text='Run Generation', command=self.on_run).pack(anchor='w', pady=10)
        ttk.Button(left, text='Open Output Folder', command=self.open_output).pack(anchor='w')

        right = ttk.Frame(frm)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        ttk.Label(right, text='Log:').pack(anchor='w')
        self.logbox = scrolledtext.ScrolledText(right, state='disabled', width=80, height=30)
        self.logbox.pack(fill=tk.BOTH, expand=True)

    def browse_path(self):
        p = filedialog.askdirectory(initialdir='.', title='Select output directory')
        if p:
            self.path_var.set(p)

    def open_output(self):
        p = os.path.abspath(self.path_var.get())
        if os.path.isdir(p):
            if sys.platform.startswith('win'):
                os.startfile(p)
            elif sys.platform.startswith('darwin'):
                os.system(f'open "{p}"')
            else:
                os.system(f'xdg-open "{p}"')
        else:
            messagebox.showerror('Error','Output directory does not exist')

    def log(self, msg):
        self.logbox.configure(state='normal')
        self.logbox.insert(tk.END, str(msg) + '\n')
        self.logbox.see(tk.END)
        self.logbox.configure(state='disabled')
        print(msg)

    def on_run(self):
        out = self.path_var.get() or DEFAULT_PATH
        keysize = int(self.keysize_var.get())
        signalg = self.signalg_var.get()
        ca_cn = self.ca_cn_var.get()
        ca_email = self.ca_email_var.get()

        t = threading.Thread(target=self._run_thread, args=(out, keysize, signalg, ca_cn, ca_email), daemon=True)
        t.start()

    def _run_thread(self, out, keysize, signalg, ca_cn, ca_email):
        try:
            self.log(f'Starting generation into: {out}')
            generate_all(out, log_cb=self.log, keysize=keysize, sign_alg=signalg, ca_cn=ca_cn, ca_email=ca_email)
            self.log('Done')
            messagebox.showinfo('Finished','Certificate generation finished. See log for details.')
        except Exception as e:
            self.log(f'Error during generation: {e}')
            messagebox.showerror('Error', f'Generation failed: {e}')

if __name__ == '__main__':
    app = CertGenGUI()
    app.mainloop()
