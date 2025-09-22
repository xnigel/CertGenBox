#!/usr/bin/env python
"""
CertGenBox with Tkinter GUI (cryptography version)
This file generates various types of digital certificates (CA, server, expired, not-yet-valid, etc.)
and provides a user-friendly Tkinter GUI to configure the generation parameters.
"""

import os, sys, time, threading
import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# 导入 Python 标准库的 datetime 模块
import datetime

DEFAULT_KEYSIZE = 2048
DEFAULT_HASH = 'sha256'
DEFAULT_PATH = "./certs/"
DEFAULT_COMMON_NAME = "example.com"
DEFAULT_EMAIL = "admin@example.com"
DEFAULT_CERT_COUNT = 5 # 新增：默认生成证书数量

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
        not_before = datetime.datetime.utcnow()
    if not_after is None:
        not_after = not_before + datetime.timedelta(days=365*5)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, subject_name.get('C','AU')),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, subject_name.get('ST', 'Victoria')),
        x509.NameAttribute(NameOID.LOCALITY_NAME, subject_name.get('L', 'Melbourne')),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, subject_name.get('O', 'CertGenBox')),
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

def generate_all(output_path, log_cb=print, keysize=2048, sign_alg='sha256', ca_cn="TESTCA", ca_email="demo@example.com", cert_count=DEFAULT_CERT_COUNT):
    ok, msg = ensure_path(output_path)
    log_cb(msg)

    serial = 1000

    # CA
    log_cb("Generating CA certificate")
    ca_subject = {"C":"AU","CN":ca_cn,"Email":ca_email}
    ca_cert, ca_key = mkcert(ca_subject, serial=serial, is_ca=True, key_size=keysize, sign_alg=sign_alg)
    save_cert_and_key(ca_cert, ca_key, os.path.join(output_path,"ca-cert.pem"), os.path.join(output_path,"ca-cert.key"))
    serial += 1

    # 生成指定数量的普通证书
    log_cb(f"Generating {cert_count} regular certificates signed by CA")
    for i in range(cert_count):
        subject = {"CN": f"{ca_cn}-cert-{i:02d}", "Email": f"cert-{i:02d}@{ca_email.split('@')[-1]}"}
        cert, key = mkcert(subject, issuer_name=ca_cert.subject, issuer_key=ca_key, serial=serial, key_size=keysize, sign_alg=sign_alg)
        save_cert_and_key(cert, key, os.path.join(output_path, f"regular-cert-{i:02d}.pem"), os.path.join(output_path, f"regular-cert-{i:02d}.key"))
        serial += 1

    # 生成过期证书
    log_cb("Generating expired certificates")
    for i in range(cert_count):
        subject = {"CN": f"expired-cert-{i:02d}", "Email": f"expired-{i:02d}@{ca_email.split('@')[-1]}"}
        not_before = datetime.datetime.utcnow() - datetime.timedelta(days=730)
        not_after = datetime.datetime.utcnow() - datetime.timedelta(days=365)
        cert, key = mkcert(subject, issuer_name=ca_cert.subject, issuer_key=ca_key, serial=serial, key_size=keysize, sign_alg=sign_alg, not_before=not_before, not_after=not_after)
        save_cert_and_key(cert, key, os.path.join(output_path, f"expired-cert-{i:02d}.pem"), os.path.join(output_path, f"expired-cert-{i:02d}.key"))
        serial += 1

    # 生成尚未生效的证书
    log_cb("Generating not-yet-valid certificates")
    for i in range(cert_count):
        subject = {"CN": f"future-cert-{i:02d}", "Email": f"future-{i:02d}@{ca_email.split('@')[-1]}"}
        not_before = datetime.datetime.utcnow() + datetime.timedelta(days=365)
        not_after = not_before + datetime.timedelta(days=365)
        cert, key = mkcert(subject, issuer_name=ca_cert.subject, issuer_key=ca_key, serial=serial, key_size=keysize, sign_alg=sign_alg, not_before=not_before, not_after=not_after)
        save_cert_and_key(cert, key, os.path.join(output_path, f"future-cert-{i:02d}.pem"), os.path.join(output_path, f"future-cert-{i:02d}.key"))
        serial += 1
    
    log_cb("Certificate generation finished.")

class CertGenGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('CertGenBox GUI (cryptography)')
        self.geometry('780x550')
        self.create_widgets()

    def create_widgets(self):
        frm = ttk.Frame(self, padding=10)
        frm.pack(fill=tk.BOTH, expand=True)

        # 顶部的配置区
        top_frame = ttk.Frame(frm)
        top_frame.pack(side=tk.TOP, fill=tk.X, pady=(0, 10))

        # Output Path
        ttk.Label(top_frame, text='Output directory:').grid(row=0, column=0, sticky='w')
        self.path_var = tk.StringVar(value=DEFAULT_PATH)
        ttk.Entry(top_frame, textvariable=self.path_var, width=40).grid(row=1, column=0, sticky='w')
        ttk.Button(top_frame, text='Browse...', command=self.browse_path).grid(row=1, column=1, padx=5, sticky='w')

        # Key Size and Signature Algorithm
        ttk.Label(top_frame, text='Key size:').grid(row=2, column=0, sticky='w', pady=(8,0))
        self.keysize_var = tk.IntVar(value=DEFAULT_KEYSIZE)
        ttk.Entry(top_frame, textvariable=self.keysize_var, width=10).grid(row=3, column=0, sticky='w')

        ttk.Label(top_frame, text='Signature algorithm:').grid(row=2, column=1, sticky='w', padx=(10,0), pady=(8,0))
        self.signalg_var = tk.StringVar(value=DEFAULT_HASH)
        ttk.Combobox(top_frame, textvariable=self.signalg_var, values=list(HASH_ALGORITHMS.keys()), width=12).grid(row=3, column=1, sticky='w', padx=(10,0))

        # Certificate Count
        ttk.Label(top_frame, text='Number of certs to generate (per type):').grid(row=4, column=0, sticky='w', pady=(8,0))
        self.cert_count_var = tk.IntVar(value=DEFAULT_CERT_COUNT)
        ttk.Entry(top_frame, textvariable=self.cert_count_var, width=10).grid(row=5, column=0, sticky='w')

        # CA Fields
        ttk.Label(top_frame, text='CA Common Name:').grid(row=6, column=0, sticky='w', pady=(8,0))
        self.ca_cn_var = tk.StringVar(value="TESTCA")
        ttk.Entry(top_frame, textvariable=self.ca_cn_var, width=30).grid(row=7, column=0, sticky='w')

        ttk.Label(top_frame, text='CA Email:').grid(row=6, column=1, sticky='w', padx=(10,0), pady=(8,0))
        self.ca_email_var = tk.StringVar(value="demo@example.com")
        ttk.Entry(top_frame, textvariable=self.ca_email_var, width=30).grid(row=7, column=1, sticky='w', padx=(10,0))
        
        # Buttons
        button_frame = ttk.Frame(frm)
        button_frame.pack(side=tk.TOP, fill=tk.X, pady=(10,0))
        ttk.Button(button_frame, text='Run Generation', command=self.on_run).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text='Open Output Folder', command=self.open_output).pack(side=tk.LEFT, padx=5)

        # Log
        ttk.Label(frm, text='Log:').pack(anchor='w', pady=(10,0))
        self.logbox = scrolledtext.ScrolledText(frm, state='disabled', wrap=tk.WORD, width=90, height=20)
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
        try:
            keysize = int(self.keysize_var.get())
            cert_count = int(self.cert_count_var.get())
            if keysize < 1024 or keysize > 4096:
                raise ValueError("Key size must be between 1024 and 4096 bits.")
            if cert_count < 1 or cert_count > 100:
                raise ValueError("Certificate count must be between 1 and 100.")
        except ValueError as e:
            messagebox.showerror('Input Error', str(e))
            return
            
        signalg = self.signalg_var.get()
        ca_cn = self.ca_cn_var.get()
        ca_email = self.ca_email_var.get()

        t = threading.Thread(target=self._run_thread, args=(out, keysize, signalg, ca_cn, ca_email, cert_count), daemon=True)
        t.start()

    def _run_thread(self, out, keysize, signalg, ca_cn, ca_email, cert_count):
        try:
            self.log(f'Starting generation into: {out}')
            self.log(f'Parameters: KeySize={keysize}, SignAlg={signalg}, CA_CN={ca_cn}, CertCount={cert_count}')
            generate_all(out, log_cb=self.log, keysize=keysize, sign_alg=signalg, ca_cn=ca_cn, ca_email=ca_email, cert_count=cert_count)
            self.log('Done')
            messagebox.showinfo('Finished','Certificate generation finished. See log for details.')
        except Exception as e:
            self.log(f'Error during generation: {e}')
            messagebox.showerror('Error', f'Generation failed: {e}')

if __name__ == '__main__':
    app = CertGenGUI()
    app.mainloop()