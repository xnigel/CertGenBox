# ________/\\\\\\\\\________________________________________________/\\\\\\\\\\\\_______________________________/\\\\\\\\\\\\\_______________________________
#  _____/\\\////////_______________________________________________/\\\//////////_______________________________\/\\\/////////\\\_____________________________
#   ___/\\\/____________________________________________/\\\_______/\\\__________________________________________\/\\\_______\/\\\_____________________________
#    __/\\\_________________/\\\\\\\\___/\\/\\\\\\\___/\\\\\\\\\\\_\/\\\____/\\\\\\\_____/\\\\\\\\___/\\/\\\\\\___\/\\\\\\\\\\\\\\______/\\\\\_____/\\\____/\\\_
#     _\/\\\_______________/\\\/////\\\_\/\\\/////\\\_\////\\\////__\/\\\___\/////\\\___/\\\/////\\\_\/\\\////\\\__\/\\\/////////\\\___/\\\///\\\__\///\\\/\\\/__
#      _\//\\\_____________/\\\\\\\\\\\__\/\\\___\///_____\/\\\______\/\\\_______\/\\\__/\\\\\\\\\\\__\/\\\__\//\\\_\/\\\_______\/\\\__/\\\__\//\\\___\///\\\/____
#       __\///\\\__________\//\\///////___\/\\\____________\/\\\_/\\__\/\\\_______\/\\\_\//\\///////___\/\\\___\/\\\_\/\\\_______\/\\\_\//\\\__/\\\_____/\\\/\\\___
#        ____\////\\\\\\\\\__\//\\\\\\\\\\_\/\\\____________\//\\\\\___\//\\\\\\\\\\\\/___\//\\\\\\\\\\_\/\\\___\/\\\_\/\\\\\\\\\\\\\/___\///\\\\\/____/\\\/\///\\\_
#         _______\/////////____\//////////__\///______________\/////_____\////////////______\//////////__\///____\///__\/////////////_______\/////_____\///____\///__
#          ____/\\\\\_____/\\\____________________________________/\\\\\\_____________________________________________________________________________________________
#           ___\/\\\\\\___\/\\\___________________________________\////\\\_____________________________________________________________________________________________
#            ___\/\\\/\\\__\/\\\__/\\\___/\\\\\\\\____________________\/\\\_____________________________________________________________________________________________
#             ___\/\\\//\\\_\/\\\_\///___/\\\////\\\_____/\\\\\\\\_____\/\\\_____________________________________________________________________________________________
#              ___\/\\\\//\\\\/\\\__/\\\_\//\\\\\\\\\___/\\\/////\\\____\/\\\_____________________________________________________________________________________________
#               ___\/\\\_\//\\\/\\\_\/\\\__\///////\\\__/\\\\\\\\\\\_____\/\\\_____________________________________________________________________________________________
#                ___\/\\\__\//\\\\\\_\/\\\__/\\_____\\\_\//\\///////______\/\\\_____________________________________________________________________________________________
#                 ___\/\\\___\//\\\\\_\/\\\_\//\\\\\\\\___\//\\\\\\\\\\__/\\\\\\\\\__________________________________________________________________________________________
#                  ___\///_____\/////__\///___\////////_____\//////////__\/////////___________________________________________________________________________________________
#!/usr/bin/env python

"""
python script for creating ca and derived certificates
based on: http://svn.osafoundation.org/m2crypto/trunk/tests/test_x509.py
"""

import os, time, base64, sys, random
from M2Crypto import X509, EVP, RSA, Rand, ASN1, m2, util, BIO

RSA_KEY_LEN = 2048
# can be: sha1, sha224, sha256, sha384, sha512, md5
KEY_SIGN_ALG = 'sha256'

PATH = "./certs/"

# 0 = generate all new keys
# 1 = use exisiting CA/server/device certificates to generate new test certs
USE_EXISTING_KEYS = 0

DEFAULT_KEYSIZE = 2048
EXT_CA = ('basicConstraints', 'CA:TRUE')

CA_NAME = X509.X509_Name()
CA_NAME.C = 'AU' 
CA_NAME.CN = 'TESTCA'
CA_NAME.Email = 'todearnigel@gmail.com'
CA_NAME.serialNumber = '4321'
CA_NAME.SN = 'Zhai'
CA_NAME.GN = 'Nigel'

CERTIFICATE_NAME = X509.X509_Name()
CERTIFICATE_NAME.C = 'AU' 
CERTIFICATE_NAME.CN = 'TEST'
CERTIFICATE_NAME.Email = 'todearnigel@gmail.com'
CERTIFICATE_NAME.serialNumber = '1234'
CERTIFICATE_NAME.SN = 'Zhai'
CERTIFICATE_NAME.GN = 'Nigel'

CERTIFICATE1_NAME = X509.X509_Name()
CERTIFICATE1_NAME.C = 'AU' 
CERTIFICATE1_NAME.CN = 'test_1'
CERTIFICATE1_NAME.Email = 'todearnigel@gmail.com'
CERTIFICATE1_NAME.serialNumber = '5678'
CERTIFICATE1_NAME.SN = 'Zhai'
CERTIFICATE1_NAME.GN = 'Nigel'

CERTIFICATE2_NAME = X509.X509_Name()
CERTIFICATE2_NAME.C = 'AU' 
CERTIFICATE2_NAME.CN = 'test_2'
CERTIFICATE2_NAME.Email = 'todearnigel@gmail.com'
CERTIFICATE2_NAME.serialNumber = '9012'
CERTIFICATE2_NAME.SN = 'Zhai'
CERTIFICATE2_NAME.GN = 'Nigel'

CERTIFICATE3_NAME = X509.X509_Name()
CERTIFICATE3_NAME.C = 'AU' 
CERTIFICATE3_NAME.CN = 'test_3'
CERTIFICATE3_NAME.Email = 'todearnigel@gmail.com'
CERTIFICATE3_NAME.serialNumber = '3456'
CERTIFICATE3_NAME.SN = 'Zhai'
CERTIFICATE3_NAME.GN = 'Nigel'

CERTIFICATE4_NAME = X509.X509_Name()
CERTIFICATE4_NAME.C = 'AU' 
CERTIFICATE4_NAME.CN = 'test_4'
CERTIFICATE4_NAME.Email = 'todearnigel@gmail.com'
CERTIFICATE4_NAME.serialNumber = '7890'
CERTIFICATE4_NAME.SN = 'Zhai'
CERTIFICATE4_NAME.GN = 'Nigel'

SERIAL_NUM_CTR = 200


#   Nigel: Creating a directory
try:
    os.mkdir(PATH)
    print(f"\nDirectory '{PATH}' created successfully!")
except FileExistsError:
    print(f"\nDirectory '{PATH}' already exists!!")
except PermissionError:
    print(f"\nPermission denied: Unable to create '{PATH}'!!!")
except Exception as e:
    print(f"\nAn error occurred: {e} ?!?!")
#   Nigel: created a directory - DONE


def mkcert(sign_key=None, sign_ca=None, key=None,
           sign_alg=KEY_SIGN_ALG, sub_name=CERTIFICATE_NAME,
           extensions=[], version=2,
           start_date=None, end_date=None):
    global SERIAL_NUM_CTR

    #Create private key if not specified
    if (key is None):
        rsa = RSA.gen_key(DEFAULT_KEYSIZE, 65537)
        key = EVP.PKey()
        key.assign_rsa(rsa)
    
    #Create certificate object and fill it out
    cert = X509.X509()
    cert.set_serial_number(SERIAL_NUM_CTR)
    SERIAL_NUM_CTR += 1
    cert.set_version(version)
    cert.set_subject(sub_name)

    # If not set make the start day today and end date 1 year from now
    t = int(time.time()) + time.timezone
    if start_date==None:
        start_date = ASN1.ASN1_UTCTIME()
        start_date.set_time(t)
        
    cert.set_not_before(start_date)
        
    if end_date==None:
        end_date = ASN1.ASN1_UTCTIME()
        # end_date.set_time(t + 60 * 60 * 24 * 365)   # Expired in 1 Year 
        end_date.set_time(t + 60 * 60 * 24 * 365 * 5)   # Expired in 5 Year 

    cert.set_not_after(end_date)

    #if sign_cert is none then this will be self signed
    if (sign_ca is None):
        cert.set_issuer(sub_name) 
    # The issuer must be the CA cert subject field
    else:
        issuer = sign_ca.get_subject()
        cert.set_issuer(issuer)

    # Load any specified extensions
    for ext in extensions:
        ext = X509.new_extension(ext[0], ext[1])
        cert.add_ext(ext)
    
    cert.set_pubkey(key)

    #If sign key is unspecified then self-sign
    if (sign_key is None):
        cert.sign(key, sign_alg)
    else:
        cert.sign(sign_key, sign_alg)

    return cert, key
        
if __name__ == '__main__':
    Rand.load_file('randpool.dat', -1)
    
    # Generate all new certificates or load from exisiting CA depending on variable setting
    # If using the first option, you need to ensure all required files are in the ./certs/ directory
    # This includes ca-cert.pem, ca-cert.key, server-cert.pem, server-cert.key, device-cert.pem, device-cert.key
    # This option is mainly required when test certs must be regenerated, but loading a new CA certificate on the 
    #     device is a hassle, so the old one must be used. Common when CAs are hardcoded in firmware/application or 
    #     need to be signed by vendor
    # Ensure clock/time on machine is correct. If CA generated long time ago, adjust clock on the PC to avoid 
    #     expiry issues. Change back once done
    if USE_EXISTING_KEYS==1:
        #----- Load good root CA 
        print("Loading good root CA")
        cacert = X509.load_cert(PATH + 'ca-cert.pem')
        ca_priv_key = EVP.load_key(PATH + 'ca-cert.key')
    else:
        #----- Generate good root CA 
        print("Generating good root CA")
        cacert, ca_priv_key = mkcert(extensions=[EXT_CA], sub_name=CA_NAME)
        cacert.save(PATH + 'ca-cert.pem')
        ca_priv_key.save_key(PATH + 'ca-cert.key', None)

        #----- Generate good server cert 
        print("Generating valid server certificate")
        cert, cert_priv_key = mkcert(ca_priv_key, cacert)
        cert.save(PATH + 'server-cert.pem')
        cert_priv_key.save_key(PATH + 'server-cert.key', None)

        #---- generate good device cert
        print("Generating valid device certificate")
        cert, cert_priv_key = mkcert(ca_priv_key, cacert)
        cert.save(PATH + 'device-cert.pem')
        cert_priv_key.save_key(PATH + 'device-cert.key', None)

    # Run all of the following tests in the ./certs/ directory.
    # OpenSSL code for each test certificate is provided below


  #----- GOOD Cert --------------------------------------------------------------------------------------------------------------
  #----- SSL001 Server has self signed certificate
    # $ sudo openssl s_server -accept 443 -cert SSL001-signed-cert.pem -key SSL001-signed-cert.key -CAfile ca-cert.pem
    print("Generating SSL001 Server has self signed certificate")
    cert, cert_priv_key = mkcert()
    cert.save(PATH + 'SSL001-signed-cert.pem')
    cert_priv_key.save_key(PATH + 'SSL001-signed-cert.key', None)


  #----- BAD Cert --------------------------------------------------------------------------------------------------------------
  #----- SSL002 Server has certificate signed by non trusted CA
    # $ sudo openssl s_server -accept 443 -cert SSL002-signed-cert.pem -key SSL002-signed-cert.key -CAfile SSL002-ca-cert.pem 
    print("Generating SSL002 Server has certificate signed by non trusted CA")
    SSL002_cacert, SSL002_ca_priv_key = mkcert(extensions=[EXT_CA], sub_name=CA_NAME)
    SSL002_cacert.save(PATH + 'SSL002-ca-cert.pem')
    SSL002_ca_priv_key.save_key(PATH + 'SSL002-ca-cert.key', None)

    SSL002_cert, SSL002_cert_priv_key = mkcert(SSL002_ca_priv_key,\
        SSL002_cacert)
    SSL002_cert.save(PATH + 'SSL002-signed-cert.pem')
    SSL002_cert_priv_key.save_key(PATH + 'SSL002-signed-cert.key', None)


  #----- BAD Cert --------------------------------------------------------------------------------------------------------------
  #----- SSL003 Server certificate has expired
    # $ sudo openssl s_server -accept 443 -cert SSL003-signed-cert.pem -key SSL003-signed-cert.key -CAfile ca-cert.pem 
    print("Generating SSL003 Server certificate has expired")
    t = int(time.time()) + time.timezone

    start_date = ASN1.ASN1_UTCTIME()
    start_date.set_time(t - 60 * 60 * 24 * 365)     # means:One year expired

    end_date = ASN1.ASN1_UTCTIME()
    end_date.set_time(t - 60 * 60 * 24 * 364)       # means:One year expired

    SSL003_cert, SSL003_cert_priv_key = mkcert(ca_priv_key, cacert,\
        start_date=start_date, end_date=end_date)
    SSL003_cert.save(PATH + 'SSL003-signed-cert.pem')
    SSL003_cert_priv_key.save_key(PATH + 'SSL003-signed-cert.key', None)


  #----- BAD Cert --------------------------------------------------------------------------------------------------------------
  #----- SSL004 Server certificate is not yet valid
    # $ sudo openssl s_server -accept 443 -cert SSL004-signed-cert.pem -key SSL004-signed-cert.key -CAfile ca-cert.pem   
    print("Generating SSL004 Server certificate is not yet valid")
    t = int(time.time()) + time.timezone

    start_date = ASN1.ASN1_UTCTIME()
    start_date.set_time(t + 60 * 60 * 24 * 365)

    end_date = ASN1.ASN1_UTCTIME()
    end_date.set_time(t + 60 * 60 * 24 * 365 * 2)

    SSL004_cert, SSL004_cert_priv_key = mkcert(ca_priv_key, cacert,\
        start_date=start_date, end_date=end_date)
    SSL004_cert.save(PATH + 'SSL004-signed-cert.pem')
    SSL004_cert_priv_key.save_key(PATH + 'SSL004-signed-cert.key', None)


  #----- BAD Cert --------------------------------------------------------------------------------------------------------------
  #----- SSL005 CA has expired
    # $ sudo openssl s_server -accept 443 -cert SSL005-signed-cert.pem -key SSL005-signed-cert.key -CAfile SSL005-ca-cert.pem    
    print("Generating SSL005 CA has expired")
    t = int(time.time()) + time.timezone

    start_date = ASN1.ASN1_UTCTIME()
    start_date.set_time(t - 60 * 60 * 24 * 365)

    end_date = ASN1.ASN1_UTCTIME()
    end_date.set_time(t - 60 * 60 * 24 * 358)

    SSL005_cacert, SSL005_ca_priv_key = mkcert(start_date=start_date,\
        end_date=end_date, extensions=[EXT_CA], sub_name=CA_NAME)
    SSL005_cacert.save(PATH + 'SSL005-ca-cert.pem')
    SSL005_ca_priv_key.save_key(PATH + 'SSL005-ca-cert.key', None)

    SSL005_cert, SSL005_cert_priv_key = mkcert(SSL005_ca_priv_key,\
        SSL005_cacert)
    SSL005_cert.save(PATH + 'SSL005-signed-cert.pem')
    SSL005_cert_priv_key.save_key(PATH + 'SSL005-signed-cert.key', None)


  #----- BAD Cert --------------------------------------------------------------------------------------------------------------
  #----- SSL006 CA is not yet valid
    # $ sudo openssl s_server -accept 443 -cert SSL006-signed-cert.pem -key SSL006-signed-cert.key -CAfile SSL006-ca-cert.pem       
    print("Generating SSL006 CA is not yet valid")
    t = int(time.time()) + time.timezone

    start_date = ASN1.ASN1_UTCTIME()
    start_date.set_time(t + 60 * 60 * 24 * 365)

    end_date = ASN1.ASN1_UTCTIME()
    end_date.set_time(t + 60 * 60 * 24 * 366)

    SSL006_cacert, SSL006_ca_priv_key = mkcert(start_date=start_date,\
        end_date=end_date, extensions=[EXT_CA], sub_name=CA_NAME)
    SSL006_cacert.save(PATH + 'SSL006-ca-cert.pem')
    SSL006_ca_priv_key.save_key(PATH + 'SSL006-ca-cert.key', None)

    SSL006_cert, SSL006_cert_priv_key = mkcert(SSL006_ca_priv_key,\
        SSL006_cacert)
    SSL006_cert.save(PATH + 'SSL006-signed-cert.pem')
    SSL006_cert_priv_key.save_key(PATH + 'SSL006-signed-cert.key', None)


  #----- BAD Cert --------------------------------------------------------------------------------------------------------------
  #----- SSL007 Server certificate has unsupported digest type
    # can be: sha1, sha224, sha256, sha384, sha512, md5

    # $ sudo openssl s_server -accept 443 -cert SSL007-signed-cert-sha1.pem -key SSL007-signed-cert.key -CAfile ca-cert.pem   
    print("Generating SSL007 Server certificate has unsupported digest type")
    SSL007_cert, SSL007_cert_priv_key = mkcert(ca_priv_key, cacert,\
        sign_alg='sha1')
    SSL007_cert.save(PATH + 'SSL007-signed-cert-sha1.pem')
    SSL007_cert_priv_key.save_key(PATH + 'SSL007-signed-cert.key', None)

    # $ sudo openssl s_server -accept 443 -cert SSL007-signed-cert-sha224.pem -key SSL007-signed-cert.key -CAfile ca-cert.pem   
    SSL007_cert, SSL007_cert_priv_key = mkcert(ca_priv_key, cacert,\
        sign_alg='sha224', key=SSL007_cert_priv_key)
    SSL007_cert.save(PATH + 'SSL007-signed-cert-sha224.pem')

    # $ sudo openssl s_server -accept 443 -cert SSL007-signed-cert-sha256.pem -key SSL007-signed-cert.key -CAfile ca-cert.pem   
    SSL007_cert, SSL007_cert_priv_key = mkcert(ca_priv_key, cacert,\
        sign_alg='sha256', key=SSL007_cert_priv_key)
    SSL007_cert.save(PATH + 'SSL007-signed-cert-sha256.pem')

    # $ sudo openssl s_server -accept 443 -cert SSL007-signed-cert-sha384.pem -key SSL007-signed-cert.key -CAfile ca-cert.pem 
    SSL007_cert, SSL007_cert_priv_key = mkcert(ca_priv_key, cacert,\
        sign_alg='sha384', key=SSL007_cert_priv_key)
    SSL007_cert.save(PATH + 'SSL007-signed-cert-sha384.pem')

    # $ sudo openssl s_server -accept 443 -cert SSL007-signed-cert-sha512.pem -key SSL007-signed-cert.key -CAfile ca-cert.pem 
    SSL007_cert, SSL007_cert_priv_key = mkcert(ca_priv_key, cacert,\
        sign_alg='sha512', key=SSL007_cert_priv_key)
    SSL007_cert.save(PATH + 'SSL007-signed-cert-sha512.pem')

    # $ sudo openssl s_server -accept 443 -cert SSL007-signed-cert-md5.pem -key SSL007-signed-cert.key -CAfile ca-cert.pem 
    SSL007_cert, SSL007_cert_priv_key = mkcert(ca_priv_key, cacert,\
        sign_alg='md5', key=SSL007_cert_priv_key)
    SSL007_cert.save(PATH + 'SSL007-signed-cert-md5.pem')

    # $ sudo openssl s_server -accept 443 -cert SSL007-signed-cert-ripemd160.pem -key SSL007-signed-cert.key -CAfile ca-cert.pem 
    SSL007_cert, SSL007_cert_priv_key = mkcert(ca_priv_key, cacert,\
        sign_alg='ripemd160', key=SSL007_cert_priv_key)
    SSL007_cert.save(PATH + 'SSL007-signed-cert-ripemd160.pem')


  #----- BAD Cert --------------------------------------------------------------------------------------------------------------
  #----- SSL008 Server has a private key < 1024 bits 
    # $ sudo openssl s_server -accept 443 -cert SSL008-signed-cert-512.pem -key SSL008-signed-cert-512.key -CAfile ca-cert.pem 
    print("Generating SSL008 Server has a small private key")
    rsa = RSA.gen_key(512, 65537)
    key = EVP.PKey()
    key.assign_rsa(rsa)

    SSL008_cert, SSL008_cert_priv_key = mkcert(ca_priv_key, cacert, \
        key=key)
    SSL008_cert.save(PATH + 'SSL008-signed-cert-512.pem')
    SSL008_cert_priv_key.save_key(PATH + 'SSL008-signed-cert-512.key', None)

    # $ sudo openssl s_server -accept 443 -cert SSL008-signed-cert-768.pem -key SSL008-signed-cert-768.key -CAfile ca-cert.pem 
    rsa = RSA.gen_key(768, 65537)
    key = EVP.PKey()
    key.assign_rsa(rsa)

    SSL008_cert, SSL008_cert_priv_key = mkcert(ca_priv_key, cacert, \
        key=key)
    SSL008_cert.save(PATH + 'SSL008-signed-cert-768.pem')
    SSL008_cert_priv_key.save_key(PATH + 'SSL008-signed-cert-768.key', None)

    # $ sudo openssl s_server -accept 443 -cert SSL008-signed-cert-1024.pem -key SSL008-signed-cert-1024.key -CAfile ca-cert.pem 
    rsa = RSA.gen_key(1024, 65537)
    key = EVP.PKey()
    key.assign_rsa(rsa)

    SSL008_cert, SSL008_cert_priv_key = mkcert(ca_priv_key, cacert, \
        key=key)
    SSL008_cert.save(PATH + 'SSL008-signed-cert-1024.pem')
    SSL008_cert_priv_key.save_key(PATH + 'SSL008-signed-cert-1024.key', None)


  #----- BAD Cert --------------------------------------------------------------------------------------------------------------
  #----- SSL009 Server certificate is corrupted
    # modify manually using editing tool
	# $ sudo openssl s_server -accept 443 -cert SSL009-signed-cert.pem -key SSL009-signed-cert.key -CAfile ca-cert.pem
    print("Generating SSL009 Server certificate is corrupted ")
    print("(You will need to edit this by hand) ")
    SSL009_cert, SSL009_cert_priv_key = mkcert(ca_priv_key, cacert)
    SSL009_cert.save(PATH + 'SSL009-signed-cert.pem')
    SSL009_cert_priv_key.save_key(PATH + 'SSL009-signed-cert.key', None)


  #----- BAD Cert --------------------------------------------------------------------------------------------------------------
  #----- SSL010 Valid Chaining certificate (Length 5)
    # Need to concatinate manually using the following line in a terminal window: 
    # $ cat ca-cert.pem SSL010-server-cert-chain-1.pem SSL010-server-cert-chain-2.pem SSL010-server-cert-chain-3.pem > SSL010-server-cert-chained-cert.pem
    # $ sudo openssl s_server -accept 443 -cert SSL010-server-cert-chain-4.pem -key SSL010-server-cert-chain-4.key -CAfile SSL010-server-cert-chained-cert.pem 
    print("Generating SSL010 Valid chained certificates. Need to concatinate manually using the following line $ cat ca-cert.pem SSL010-server-cert-chain-1.pem SSL010-server-cert-chain-2.pem SSL0110-server-cert-chain-3.pem > SSL010-server-cert-chained-cert.pem")

    cert_c1, cert_priv_key_c1 = mkcert(ca_priv_key, cacert, extensions=[EXT_CA], sub_name=CERTIFICATE1_NAME)
    cert_c1.save(PATH + 'SSL010-server-cert-chain-1.pem')
    cert_priv_key_c1.save_key(PATH + 'SSL010-server-cert-chain-1.key', None)

    cert_c2, cert_priv_key_c2 = mkcert(cert_priv_key_c1, cert_c1, extensions=[EXT_CA], sub_name=CERTIFICATE2_NAME)
    cert_c2.save(PATH + 'SSL010-server-cert-chain-2.pem')
    cert_priv_key_c2.save_key(PATH + 'SSL010-server-cert-chain-2.key', None)

    cert_c3, cert_priv_key_c3 = mkcert(cert_priv_key_c2, cert_c2, extensions=[EXT_CA], sub_name=CERTIFICATE3_NAME)
    cert_c3.save(PATH + 'SSL010-server-cert-chain-3.pem')
    cert_priv_key_c3.save_key(PATH + 'SSL010-server-cert-chain-3.key', None)

    cert_c4, cert_priv_key_c4 = mkcert(cert_priv_key_c3, cert_c3, sub_name=CERTIFICATE4_NAME)
    cert_c4.save(PATH + 'SSL010-server-cert-chain-4.pem')
    cert_priv_key_c4.save_key(PATH + 'SSL010-server-cert-chain-4.key', None)


  #----- BAD Cert --------------------------------------------------------------------------------------------------------------
  #----- SSL011 Chaining certificate with expired middle cert (Length 5)
    # Need to concatinate manually using the following line in a terminal window:
    # $ cat ca-cert.pem SSL011-server-cert-chain-1.pem SSL011-server-cert-chain-2.pem SSL011-server-cert-chain-3.pem > SSL011-server-cert-chained-cert.pem
    # $ sudo openssl s_server -accept 443 -cert SSL011-server-cert-chain-4.pem -key SSL011-server-cert-chain-4.key -CAfile SSL011-server-cert-chained-cert.pem 
    print("Generating SSL011 chained certificates with expired 2nd cert. Need to concatinate manually using the following line $ cat ca-cert.pem SSL011-server-cert-chain-1.pem SSL011-server-cert-chain-2.pem SSL011-server-cert-chain-3.pem > SSL011-server-cert-chained-cert.pem")

    cert_c1, cert_priv_key_c1 = mkcert(ca_priv_key, cacert, extensions=[EXT_CA], sub_name=CERTIFICATE1_NAME)
    cert_c1.save(PATH + 'SSL011-server-cert-chain-1.pem')
    cert_priv_key_c1.save_key(PATH + 'SSL011-server-cert-chain-1.key', None)

    t = int(time.time()) + time.timezone

    start_date = ASN1.ASN1_UTCTIME()
    start_date.set_time(t - 60 * 60 * 24 * 365)

    end_date = ASN1.ASN1_UTCTIME()
    end_date.set_time(t - 60 * 60 * 24 * 358)

    cert_c2, cert_priv_key_c2 = mkcert(cert_priv_key_c1, cert_c1, extensions=[EXT_CA], sub_name=CERTIFICATE2_NAME, start_date=start_date, end_date=end_date)
    cert_c2.save(PATH + 'SSL011-server-cert-chain-2.pem')
    cert_priv_key_c2.save_key(PATH + 'SSL011-server-cert-chain-2.key', None)

    cert_c3, cert_priv_key_c3 = mkcert(cert_priv_key_c2, cert_c2, extensions=[EXT_CA], sub_name=CERTIFICATE3_NAME)
    cert_c3.save(PATH + 'SSL011-server-cert-chain-3.pem')
    cert_priv_key_c3.save_key(PATH + 'SSL011-server-cert-chain-3.key', None)

    cert_c4, cert_priv_key_c4 = mkcert(cert_priv_key_c3, cert_c3, sub_name=CERTIFICATE4_NAME)
    cert_c4.save(PATH + 'SSL011-server-cert-chain-4.pem')
    cert_priv_key_c4.save_key(PATH + 'SSL011-server-cert-chain-4.key', None)


  #----- BAD Cert --------------------------------------------------------------------------------------------------------------
  #----- SSL012 Chaining certificate with no yet valid middle cert (Length 5)
    # Need to concatinate manually using the following line in a terminal window:
    # $ cat ca-cert.pem SSL012-server-cert-chain-1.pem SSL012-server-cert-chain-2.pem SSL012-server-cert-chain-3.pem > SSL012-server-cert-chained-cert.pem
    # $ sudo openssl s_server -accept 443 -cert SSL012-server-cert-chain-4.pem -key SSL012-server-cert-chain-4.key -CAfile SSL012-server-cert-chained-cert.pem
    print("Generating SSL012 chained certificates with not yet valid 2nd cert. Need to concatinate manually using the following line $ cat ca-cert.pem SSL012-server-cert-chain-1.pem SSL012-server-cert-chain-2.pem SSL012-server-cert-chain-3.pem > SSL012-server-cert-chained-cert.pem")

    cert_c1, cert_priv_key_c1 = mkcert(ca_priv_key, cacert, extensions=[EXT_CA], sub_name=CERTIFICATE1_NAME)
    cert_c1.save(PATH + 'SSL012-server-cert-chain-1.pem')
    cert_priv_key_c1.save_key(PATH + 'SSL012-server-cert-chain-1.key', None)

    t = int(time.time()) + time.timezone

    start_date = ASN1.ASN1_UTCTIME()
    start_date.set_time(t + 60 * 60 * 24 * 365)

    end_date = ASN1.ASN1_UTCTIME()
    end_date.set_time(t + 60 * 60 * 24 * 366)

    cert_c2, cert_priv_key_c2 = mkcert(cert_priv_key_c1, cert_c1, extensions=[EXT_CA], sub_name=CERTIFICATE2_NAME, start_date=start_date, end_date=end_date)
    cert_c2.save(PATH + 'SSL012-server-cert-chain-2.pem')
    cert_priv_key_c2.save_key(PATH + 'SSL012-server-cert-chain-2.key', None)

    cert_c3, cert_priv_key_c3 = mkcert(cert_priv_key_c2, cert_c2, extensions=[EXT_CA], sub_name=CERTIFICATE3_NAME)
    cert_c3.save(PATH + 'SSL012-server-cert-chain-3.pem')
    cert_priv_key_c3.save_key(PATH + 'SSL012-server-cert-chain-3.key', None)

    cert_c4, cert_priv_key_c4 = mkcert(cert_priv_key_c3, cert_c3, sub_name=CERTIFICATE4_NAME)
    cert_c4.save(PATH + 'SSL012-server-cert-chain-4.pem')
    cert_priv_key_c4.save_key(PATH + 'SSL012-server-cert-chain-4.key', None)


  #----- BAD Cert --------------------------------------------------------------------------------------------------------------
  #----- SSL013 Chaining certificate with self-signed middle cert (Length 5)
    # Need to concatinate manually using the following line in a terminal window 
    # $ cat ca-cert.pem SSL013-server-cert-chain-1.pem SSL013-server-cert-chain-2.pem SSL013-server-cert-chain-3.pem > SSL013-server-cert-chained-cert.pem
    # $ sudo openssl s_server -accept 443 -cert SSL013-server-cert-chain-4.pem -key SSL013-server-cert-chain-4.key -CAfile SSL013-server-cert-chained-cert.pem
    print("Generating SSL013 chained certificates with self-signed middle cert. Need to concatinate manually using the following line $ cat ca-cert.pem SSL013-server-cert-chain-1.pem SSL013-server-cert-chain-2.pem SSL013-server-cert-chain-3.pem > SSL013-server-cert-chained-cert.pem")

    cert_c1, cert_priv_key_c1 = mkcert(ca_priv_key, cacert, extensions=[EXT_CA], sub_name=CERTIFICATE1_NAME)
    cert_c1.save(PATH + 'SSL013-server-cert-chain-1.pem')
    cert_priv_key_c1.save_key(PATH + 'SSL013-server-cert-chain-1.key', None)

    cert_c2, cert_priv_key_c2 = mkcert(cert_priv_key_c1, cert_c1, extensions=[EXT_CA], sub_name=CERTIFICATE2_NAME)
    cert_c2.save(PATH + 'SSL013-server-cert-chain-2.pem')
    cert_priv_key_c2.save_key(PATH + 'SSL013-server-cert-chain-2.key', None)

    cert_c3, cert_priv_key_c3 = mkcert(extensions=[EXT_CA], sub_name=CERTIFICATE3_NAME)
    cert_c3.save(PATH + 'SSL013-server-cert-chain-3.pem')
    cert_priv_key_c3.save_key(PATH + 'SSL013-server-cert-chain-3.key', None)

    cert_c4, cert_priv_key_c4 = mkcert(cert_priv_key_c3, cert_c3, sub_name=CERTIFICATE4_NAME)
    cert_c4.save(PATH + 'SSL013-server-cert-chain-4.pem')
    cert_priv_key_c4.save_key(PATH + 'SSL013-server-cert-chain-4.key', None)


  #----- BAD Cert --------------------------------------------------------------------------------------------------------------
  #----- SSL014 Chaining certificate with weak digest for middle cert (Length 5)
    # Need to concatinate manually using the following line in a terminal window 
    # $ cat ca-cert.pem SSL014-server-cert-chain-1.pem SSL014-server-cert-chain-2.pem SSL014-server-cert-chain-3.pem > SSL014-server-cert-chained-cert.pem
    # $ sudo openssl s_server -accept 443 -cert SSL014-server-cert-chain-4.pem -key SSL014-server-cert-chain-4.key -CAfile SSL014-server-cert-chained-cert.pem 
    print("Generating SSL014  chained certificates with md5 middle cert digest. Need to concatinate manually using the following line $ cat ca-cert.pem SSL014-server-cert-chain-1.pem SSL014-server-cert-chain-2.pem SSL014-server-cert-chain-3.pem > SSL014-server-cert-chained-cert.pem")

    cert_c1, cert_priv_key_c1 = mkcert(ca_priv_key, cacert, extensions=[EXT_CA], sub_name=CERTIFICATE1_NAME)
    cert_c1.save(PATH + 'SSL014-server-cert-chain-1.pem')
    cert_priv_key_c1.save_key(PATH + 'SSL014-server-cert-chain-1.key', None)

    cert_c2, cert_priv_key_c2 = mkcert(cert_priv_key_c1, cert_c1, sign_alg='md5', key=cert_priv_key_c2, extensions=[EXT_CA], sub_name=CERTIFICATE2_NAME)
    cert_c2.save(PATH + 'SSL014-server-cert-chain-2.pem')
    cert_priv_key_c2.save_key(PATH + 'SSL014-server-cert-chain-2.key', None)

    cert_c3, cert_priv_key_c3 = mkcert(cert_priv_key_c2, cert_c2, extensions=[EXT_CA], sub_name=CERTIFICATE3_NAME)
    cert_c3.save(PATH + 'SSL014-server-cert-chain-3.pem')
    cert_priv_key_c3.save_key(PATH + 'SSL014-server-cert-chain-3.key', None)

    cert_c4, cert_priv_key_c4 = mkcert(cert_priv_key_c3, cert_c3, sub_name=CERTIFICATE4_NAME)
    cert_c4.save(PATH + 'SSL014-server-cert-chain-4.pem')
    cert_priv_key_c4.save_key(PATH + 'SSL014-server-cert-chain-4.key', None)


  #----- BAD Cert --------------------------------------------------------------------------------------------------------------
  #----- SSL015  Chaining certificate with weak private key size (Length 5)
    # Need to concatinate manually using the following line in a terminal window:
    # $ cat ca-cert.pem SSL015-server-cert-chain-1.pem SSL015-server-cert-chain-2.pem SSL015-server-cert-chain-3.pem > SSL015-server-cert-chained-cert.pem
    # $ sudo openssl s_server -accept 443 -cert SSL015-server-cert-chain-4.pem -key SSL015-server-cert-chain-4.key -CAfile SSL015-server-cert-chained-cert.pem 
    print("Generating SSL015 chained certificates with weak private key size. Need to concatinate manually using the following line $ cat ca-cert.pem SSL015-server-cert-chain-1.pem SSL015-server-cert-chain-2.pem SSL015-server-cert-chain-3.pem > SSL015-server-cert-chained-cert.pem")

    cert_c1, cert_priv_key_c1 = mkcert(ca_priv_key, cacert, extensions=[EXT_CA], sub_name=CERTIFICATE1_NAME)
    cert_c1.save(PATH + 'SSL015-server-cert-chain-1.pem')
    cert_priv_key_c1.save_key(PATH + 'SSL015-server-cert-chain-1.key', None)

    rsa = RSA.gen_key(1024, 65537)
    key = EVP.PKey()
    key.assign_rsa(rsa)

    cert_c2, cert_priv_key_c2 = mkcert(cert_priv_key_c1, cert_c1, key=key, extensions=[EXT_CA], sub_name=CERTIFICATE2_NAME)
    cert_c2.save(PATH + 'SSL015-server-cert-chain-2.pem')
    cert_priv_key_c2.save_key(PATH + 'SSL015-server-cert-chain-2.key', None)

    cert_c3, cert_priv_key_c3 = mkcert(cert_priv_key_c2, cert_c2, extensions=[EXT_CA], sub_name=CERTIFICATE3_NAME)
    cert_c3.save(PATH + 'SSL015-server-cert-chain-3.pem')
    cert_priv_key_c3.save_key(PATH + 'SSL015-server-cert-chain-3.key', None)

    cert_c4, cert_priv_key_c4 = mkcert(cert_priv_key_c3, cert_c3, sub_name=CERTIFICATE4_NAME)
    cert_c4.save(PATH + 'SSL015-server-cert-chain-4.pem')
    cert_priv_key_c4.save_key(PATH + 'SSL015-server-cert-chain-4.key', None)


  #----- BAD Cert --------------------------------------------------------------------------------------------------------------
  #----- SSL016 Valid Chaining certificate (Length 4)
    # Need to concatinate manually using the following line in a terminal window 
    # $ cat ca-cert.pem SSL016-server-cert-chain-1.pem SSL016-server-cert-chain-2.pem > SSL016-server-cert-chained-cert.pem
    # $ sudo openssl s_server -accept 443 -cert SSL016-server-cert-chain-3.pem -key SSL016-server-cert-chain-3.key -CAfile SSL016-server-cert-chained-cert.pem 
    print("Generating SSL016 Valid chained certificates. Need to concatinate manually using the following line $ cat ca-cert.pem SSL016-server-cert-chain-1.pem SSL016-server-cert-chain-2.pem > SSL016-server-cert-chained-cert.pem")

    cert_c1, cert_priv_key_c1 = mkcert(ca_priv_key, cacert, extensions=[EXT_CA], sub_name=CERTIFICATE1_NAME)
    cert_c1.save(PATH + 'SSL016-server-cert-chain-1.pem')
    cert_priv_key_c1.save_key(PATH + 'SSL016-server-cert-chain-1.key', None)

    cert_c2, cert_priv_key_c2 = mkcert(cert_priv_key_c1, cert_c1, extensions=[EXT_CA], sub_name=CERTIFICATE2_NAME)
    cert_c2.save(PATH + 'SSL016-server-cert-chain-2.pem')
    cert_priv_key_c2.save_key(PATH + 'SSL016-server-cert-chain-2.key', None)

    cert_c3, cert_priv_key_c3 = mkcert(cert_priv_key_c2, cert_c2, sub_name=CERTIFICATE3_NAME)
    cert_c3.save(PATH + 'SSL016-server-cert-chain-3.pem')
    cert_priv_key_c3.save_key(PATH + 'SSL016-server-cert-chain-3.key', None)


  #----- BAD Cert --------------------------------------------------------------------------------------------------------------
  #----- SSL017 Chaining certificate with expired middle cert (Length 4)
    # Need to concatinate manually using the following line in a terminal window 
    # $ cat ca-cert.pem SSL017-server-cert-chain-1.pem SSL017-server-cert-chain-2.pem > SSL017-server-cert-chained-cert.pem
    # $ sudo openssl s_server -accept 443 -cert SSL017-server-cert-chain-3.pem -key SSL017-server-cert-chain-3.key -CAfile SSL017-server-cert-chained-cert.pem 
    print("Generating SSL017 chained certificates with expired 2nd cert. Need to concatinate manually using the following line $ cat ca-cert.pem SSL017-server-cert-chain-1.pem SSL017-server-cert-chain-2.pem > SSL017-server-cert-chained-cert.pem")

    cert_c1, cert_priv_key_c1 = mkcert(ca_priv_key, cacert, extensions=[EXT_CA], sub_name=CERTIFICATE1_NAME)
    cert_c1.save(PATH + 'SSL017-server-cert-chain-1.pem')
    cert_priv_key_c1.save_key(PATH + 'SSL017-server-cert-chain-1.key', None)

    t = int(time.time()) + time.timezone

    start_date = ASN1.ASN1_UTCTIME()
    start_date.set_time(t - 60 * 60 * 24 * 365)

    end_date = ASN1.ASN1_UTCTIME()
    end_date.set_time(t - 60 * 60 * 24 * 358)


    cert_c2, cert_priv_key_c2 = mkcert(cert_priv_key_c1, cert_c1, extensions=[EXT_CA], sub_name=CERTIFICATE2_NAME, start_date=start_date, end_date=end_date)
    cert_c2.save(PATH + 'SSL017-server-cert-chain-2.pem')
    cert_priv_key_c2.save_key(PATH + 'SSL017-server-cert-chain-2.key', None)

    cert_c3, cert_priv_key_c3 = mkcert(cert_priv_key_c2, cert_c2, sub_name=CERTIFICATE3_NAME)
    cert_c3.save(PATH + 'SSL017-server-cert-chain-3.pem')
    cert_priv_key_c3.save_key(PATH + 'SSL017-server-cert-chain-3.key', None)


  #----- BAD Cert --------------------------------------------------------------------------------------------------------------
  #----- SSL018 Chaining certificate with no yet valid middle cert (Length 4)
    # Need to concatinate manually using the following line in a terminal window 
    # $ cat ca-cert.pem SSL018-server-cert-chain-1.pem SSL018-server-cert-chain-2.pem > SSL018-server-cert-chained-cert.pem
    # $ sudo openssl s_server -accept 443 -cert SSL018-server-cert-chain-3.pem -key SSL018-server-cert-chain-3.key -CAfile SSL018-server-cert-chained-cert.pem 
    print("Generating SSL018 chained certificates with not yet valid 2nd cert. Need to concatinate manually using the following line $ cat ca-cert.pem SSL018-server-cert-chain-1.pem SSL018-server-cert-chain-2.pem > SSL018-server-cert-chained-cert.pem")

    cert_c1, cert_priv_key_c1 = mkcert(ca_priv_key, cacert, extensions=[EXT_CA], sub_name=CERTIFICATE1_NAME)
    cert_c1.save(PATH + 'SSL018-server-cert-chain-1.pem')
    cert_priv_key_c1.save_key(PATH + 'SSL018-server-cert-chain-1.key', None)

    t = int(time.time()) + time.timezone

    start_date = ASN1.ASN1_UTCTIME()
    start_date.set_time(t + 60 * 60 * 24 * 365)

    end_date = ASN1.ASN1_UTCTIME()
    end_date.set_time(t + 60 * 60 * 24 * 366)


    cert_c2, cert_priv_key_c2 = mkcert(cert_priv_key_c1, cert_c1, extensions=[EXT_CA], sub_name=CERTIFICATE2_NAME, start_date=start_date, end_date=end_date)
    cert_c2.save(PATH + 'SSL018-server-cert-chain-2.pem')
    cert_priv_key_c2.save_key(PATH + 'SSL018-server-cert-chain-2.key', None)

    cert_c3, cert_priv_key_c3 = mkcert(cert_priv_key_c2, cert_c2, sub_name=CERTIFICATE3_NAME)
    cert_c3.save(PATH + 'SSL018-server-cert-chain-3.pem')
    cert_priv_key_c3.save_key(PATH + 'SSL018-server-cert-chain-3.key', None)


  #----- BAD Cert --------------------------------------------------------------------------------------------------------------
  #----- SSL019 Chaining certificate with self-signed middle cert (Length 4)
    # Need to concatinate manually using the following line in a terminal window 
    # $ cat ca-cert.pem SSL019-server-cert-chain-1.pem SSL019-server-cert-chain-2.pem > SSL019-server-cert-chained-cert.pem
    # $ sudo openssl s_server -accept 443 -cert SSL019-server-cert-chain-3.pem -key SSL019-server-cert-chain-3.key -CAfile SSL019-server-cert-chained-cert.pem 
    print("Generating SSL019 chained certificates with self-signed middle cert. Need to concatinate manually using the following line $ cat ca-cert.pem SSL019-server-cert-chain-1.pem SSL019-server-cert-chain-2.pem > SSL019-server-cert-chained-cert.pem")

    cert_c1, cert_priv_key_c1 = mkcert(ca_priv_key, cacert, extensions=[EXT_CA], sub_name=CERTIFICATE1_NAME)
    cert_c1.save(PATH + 'SSL019-server-cert-chain-1.pem')
    cert_priv_key_c1.save_key(PATH + 'SSL019-server-cert-chain-1.key', None)

    cert_c2, cert_priv_key_c2 = mkcert(extensions=[EXT_CA], sub_name=CERTIFICATE2_NAME)
    cert_c2.save(PATH + 'SSL019-server-cert-chain-2.pem')
    cert_priv_key_c2.save_key(PATH + 'SSL019-server-cert-chain-2.key', None)

    cert_c3, cert_priv_key_c3 = mkcert(cert_priv_key_c2, cert_c2, sub_name=CERTIFICATE3_NAME)
    cert_c3.save(PATH + 'SSL019-server-cert-chain-3.pem')
    cert_priv_key_c3.save_key(PATH + 'SSL019-server-cert-chain-3.key', None)


  #----- BAD Cert --------------------------------------------------------------------------------------------------------------
  #----- SSL020 Chaining certificate with weak digest for middle cert (Length 4)
    # Need to concatinate manually using the following line in a terminal window 
    # $ cat ca-cert.pem SSL020-server-cert-chain-1.pem SSL020-server-cert-chain-2.pem > SSL020-server-cert-chained-cert.pem
    # $ sudo openssl s_server -accept 443 -cert SSL020-server-cert-chain-3.pem -key SSL020-server-cert-chain-3.key -CAfile SSL020-server-cert-chained-cert.pem 
    print("Generating SSL020 chained certificates with md5 middle cert digest. Need to concatinate manually using the following line $ cat ca-cert.pem SSL020-server-cert-chain-1.pem SSL020-server-cert-chain-2.pem > SSL020-server-cert-chained-cert.pem")

    cert_c1, cert_priv_key_c1 = mkcert(ca_priv_key, cacert, extensions=[EXT_CA], sub_name=CERTIFICATE1_NAME)
    cert_c1.save(PATH + 'SSL020-server-cert-chain-1.pem')
    cert_priv_key_c1.save_key(PATH + 'SSL020-server-cert-chain-1.key', None)

    cert_c2, cert_priv_key_c2 = mkcert(cert_priv_key_c1, cert_c1, sign_alg='md5', key=cert_priv_key_c2, extensions=[EXT_CA], sub_name=CERTIFICATE2_NAME)
    cert_c2.save(PATH + 'SSL020-server-cert-chain-2.pem')
    cert_priv_key_c2.save_key(PATH + 'SSL020-server-cert-chain-2.key', None)

    cert_c3, cert_priv_key_c3 = mkcert(cert_priv_key_c2, cert_c2, sub_name=CERTIFICATE3_NAME)
    cert_c3.save(PATH + 'SSL020-server-cert-chain-3.pem')
    cert_priv_key_c3.save_key(PATH + 'SSL020-server-cert-chain-3.key', None)


  #----- BAD Cert --------------------------------------------------------------------------------------------------------------
  #----- SSL021 Chaining certificate with weak private key size (Length 4)
    # Need to concatinate manually using the following line in a terminal window 
    # $ cat ca-cert.pem SSL021-server-cert-chain-1.pem SSL021-server-cert-chain-2.pem > SSL021-server-cert-chained-cert.pem
    # $ sudo openssl s_server -accept 443 -cert SSL021-server-cert-chain-3.pem -key SSL021-server-cert-chain-3.key -CAfile SSL021-server-cert-chained-cert.pem 
    print("Generating SSL021 chained certificates with weak private key size. Need to concatinate manually using the following line $ cat ca-cert.pem SSL021-server-cert-chain-1.pem SSL021-server-cert-chain-2.pem > SSL021-server-cert-chained-cert.pem")

    cert_c1, cert_priv_key_c1 = mkcert(ca_priv_key, cacert, extensions=[EXT_CA], sub_name=CERTIFICATE1_NAME)
    cert_c1.save(PATH + 'SSL021-server-cert-chain-1.pem')
    cert_priv_key_c1.save_key(PATH + 'SSL021-server-cert-chain-1.key', None)

    rsa = RSA.gen_key(1024, 65537)
    key = EVP.PKey()
    key.assign_rsa(rsa)

    cert_c2, cert_priv_key_c2 = mkcert(cert_priv_key_c1, cert_c1, key=key, extensions=[EXT_CA], sub_name=CERTIFICATE2_NAME)
    cert_c2.save(PATH + 'SSL021-server-cert-chain-2.pem')
    cert_priv_key_c2.save_key(PATH + 'SSL021-server-cert-chain-2.key', None)

    cert_c3, cert_priv_key_c3 = mkcert(cert_priv_key_c2, cert_c2, sub_name=CERTIFICATE3_NAME)
    cert_c3.save(PATH + 'SSL021-server-cert-chain-3.pem')
    cert_priv_key_c3.save_key(PATH + 'SSL021-server-cert-chain-3.key', None)


  #----- BAD Cert --------------------------------------------------------------------------------------------------------------
  #----- SSL022 Valid Chaining certificate (Length 3)
    # Need to concatinate manually using the following line in a terminal window 
    # $ cat ca-cert.pem SSL022-server-cert-chain-1.pem > SSL022-server-cert-chained-cert.pem
    # $ sudo openssl s_server -accept 443 -cert SSL022-server-cert-chain-2.pem -key SSL022-server-cert-chain-2.key -CAfile SSL022-server-cert-chained-cert.pem 
    print("Generating SSL022 Valid chained certificates. Need to concatinate manually using the following line $ cat ca-cert.pem SSL022-server-cert-chain-1.pem > SSL022-server-cert-chained-cert.pem")

    cert_c1, cert_priv_key_c1 = mkcert(ca_priv_key, cacert, extensions=[EXT_CA], sub_name=CERTIFICATE1_NAME)
    cert_c1.save(PATH + 'SSL022-server-cert-chain-1.pem')
    cert_priv_key_c1.save_key(PATH + 'SSL022-server-cert-chain-1.key', None)

    cert_c2, cert_priv_key_c2 = mkcert(cert_priv_key_c1, cert_c1, sub_name=CERTIFICATE2_NAME)
    cert_c2.save(PATH + 'SSL022-server-cert-chain-2.pem')
    cert_priv_key_c2.save_key(PATH + 'SSL022-server-cert-chain-2.key', None)


  #----- BAD Cert --------------------------------------------------------------------------------------------------------------
  #----- SSL023 Chaining certificate with expired middle cert (Length 3)
    # Need to concatinate manually using the following line in a terminal window 
    # $ cat ca-cert.pem SSL023-server-cert-chain-1.pem > SSL023-server-cert-chained-cert.pem
    # $ sudo openssl s_server -accept 443 -cert SSL023-server-cert-chain-2.pem -key SSL023-server-cert-chain-2.key -CAfile SSL023-server-cert-chained-cert.pem 
    print("Generating SSL023 chained certificates with expired 1st cert. Need to concatinate manually using the following line $ cat ca-cert.pem SSL023-server-cert-chain-1.pem > SSL023-server-cert-chained-cert.pem")

    t = int(time.time()) + time.timezone

    start_date = ASN1.ASN1_UTCTIME()
    start_date.set_time(t - 60 * 60 * 24 * 365)

    end_date = ASN1.ASN1_UTCTIME()
    end_date.set_time(t - 60 * 60 * 24 * 358)


    cert_c1, cert_priv_key_c1 = mkcert(ca_priv_key, cacert, extensions=[EXT_CA], sub_name=CERTIFICATE1_NAME, start_date=start_date, end_date=end_date)
    cert_c1.save(PATH + 'SSL023-server-cert-chain-1.pem')
    cert_priv_key_c1.save_key(PATH + 'SSL023-server-cert-chain-1.key', None)

    cert_c2, cert_priv_key_c2 = mkcert(cert_priv_key_c1, cert_c1, sub_name=CERTIFICATE2_NAME)
    cert_c2.save(PATH + 'SSL023-server-cert-chain-2.pem')
    cert_priv_key_c2.save_key(PATH + 'SSL023-server-cert-chain-2.key', None)


  #----- BAD Cert --------------------------------------------------------------------------------------------------------------
  #----- SSL024 Chaining certificate with no yet valid middle cert (Length 3)
    # Need to concatinate manually using the following line in a terminal window 
    # $ cat ca-cert.pem SSL024-server-cert-chain-1.pem > SSL024-server-cert-chained-cert.pem
    # $ sudo openssl s_server -accept 443 -cert SSL024-server-cert-chain-2.pem -key SSL024-server-cert-chain-2.key -CAfile SSL024-server-cert-chained-cert.pem 
    print("Generating SSL024 chained certificates with not yet valid 1st cert. Need to concatinate manually using the following line $ cat ca-cert.pem SSL024-server-cert-chain-1.pem > SSL024-server-cert-chained-cert.pem")

    t = int(time.time()) + time.timezone

    start_date = ASN1.ASN1_UTCTIME()
    start_date.set_time(t + 60 * 60 * 24 * 365)

    end_date = ASN1.ASN1_UTCTIME()
    end_date.set_time(t + 60 * 60 * 24 * 366)


    cert_c1, cert_priv_key_c1 = mkcert(ca_priv_key, cacert, extensions=[EXT_CA], sub_name=CERTIFICATE1_NAME, start_date=start_date, end_date=end_date)
    cert_c1.save(PATH + 'SSL024-server-cert-chain-1.pem')
    cert_priv_key_c1.save_key(PATH + 'SSL024-server-cert-chain-1.key', None)

    cert_c2, cert_priv_key_c2 = mkcert(cert_priv_key_c1, cert_c1, sub_name=CERTIFICATE2_NAME)
    cert_c2.save(PATH + 'SSL024-server-cert-chain-2.pem')
    cert_priv_key_c2.save_key(PATH + 'SSL024-server-cert-chain-2.key', None)


  #----- BAD Cert --------------------------------------------------------------------------------------------------------------
  #----- SSL025 Chaining certificate with self-signed middle cert (Length 3)
    # Need to concatinate manually using the following line in a terminal window 
    # $ cat ca-cert.pem SSL025-server-cert-chain-1.pem > SSL025-server-cert-chained-cert.pem
    # $ sudo openssl s_server -accept 443 -cert SSL025-server-cert-chain-2.pem -key SSL025-server-cert-chain-2.key -CAfile SSL025-server-cert-chained-cert.pem 
    print("Generating SSL025 chained certificates with self-signed middle cert. Need to concatinate manually using the following line $ cat ca-cert.pem SSL025-server-cert-chain-1.pem > SSL025-server-cert-chained-cert.pem")

    cert_c1, cert_priv_key_c1 = mkcert(extensions=[EXT_CA], sub_name=CERTIFICATE1_NAME)
    cert_c1.save(PATH + 'SSL025-server-cert-chain-1.pem')
    cert_priv_key_c1.save_key(PATH + 'SSL025-server-cert-chain-1.key', None)

    cert_c2, cert_priv_key_c2 = mkcert(cert_priv_key_c1, cert_c1, sub_name=CERTIFICATE2_NAME)
    cert_c2.save(PATH + 'SSL025-server-cert-chain-2.pem')
    cert_priv_key_c2.save_key(PATH + 'SSL025-server-cert-chain-2.key', None)


  #----- BAD Cert --------------------------------------------------------------------------------------------------------------
  #----- SSL026 Chaining certificate with weak digest for middle cert (Length 3)
    # Need to concatinate manually using the following line in a terminal window 
    # $ cat ca-cert.pem SSL026-server-cert-chain-1.pem > SSL026-server-cert-chained-cert.pem
    # $ sudo openssl s_server -accept 443 -cert SSL026-server-cert-chain-2.pem -key SSL026-server-cert-chain-2.key -CAfile SSL026-server-cert-chained-cert.pem 
    print("Generating SSL026 chained certificates with md5 middle cert digest. Need to concatinate manually using the following line $ cat ca-cert.pem SSL026-server-cert-chain-1.pem > SSL026-server-cert-chained-cert.pem")

    cert_c1, cert_priv_key_c1 = mkcert(ca_priv_key, cacert, sign_alg='md5', key=cert_priv_key_c1, extensions=[EXT_CA], sub_name=CERTIFICATE1_NAME)
    cert_c1.save(PATH + 'SSL026-server-cert-chain-1.pem')
    cert_priv_key_c1.save_key(PATH + 'SSL026-server-cert-chain-1.key', None)

    cert_c2, cert_priv_key_c2 = mkcert(cert_priv_key_c1, cert_c1, sub_name=CERTIFICATE2_NAME)
    cert_c2.save(PATH + 'SSL026-server-cert-chain-2.pem')
    cert_priv_key_c2.save_key(PATH + 'SSL026-server-cert-chain-2.key', None)


  #----- BAD Cert --------------------------------------------------------------------------------------------------------------
  #----- SSL027 Chaining certificate with weak private key size (Length 3)
    # Need to concatinate manually using the following line in a terminal window 
    # $ cat ca-cert.pem SSL027-server-cert-chain-1.pem > SSL027-server-cert-chained-cert.pem
    # $ sudo openssl s_server -accept 443 -cert SSL027-server-cert-chain-2.pem -key SSL027-server-cert-chain-2.key -CAfile SSL027-server-cert-chained-cert.pem 
    print("Generating SSL027 chained certificates with weak private key size. Need to concatinate manually using the following line $ cat ca-cert.pem SSL027-server-cert-chain-1.pem > SSL027-server-cert-chained-cert.pem")

    rsa = RSA.gen_key(1024, 65537)
    key = EVP.PKey()
    key.assign_rsa(rsa)

    cert_c1, cert_priv_key_c1 = mkcert(ca_priv_key, cacert, key=key, extensions=[EXT_CA], sub_name=CERTIFICATE1_NAME)
    cert_c1.save(PATH + 'SSL027-server-cert-chain-1.pem')
    cert_priv_key_c1.save_key(PATH + 'SSL027-server-cert-chain-1.key', None)

    cert_c2, cert_priv_key_c2 = mkcert(cert_priv_key_c1, cert_c1, sub_name=CERTIFICATE2_NAME)
    cert_c2.save(PATH + 'SSL027-server-cert-chain-2.pem')
    cert_priv_key_c2.save_key(PATH + 'SSL027-server-cert-chain-2.key', None)


  #----- BAD Cert --------------------------------------------------------------------------------------------------------------
  #----- SSL028 Valid Chaining certificate (Length 3, but removed CA extension from cert 1)
    # Not 100% why i had this in. 
    # Need to concatinate manually using the following line in a terminal window 
    # $ cat ca-cert.pem SSL028-server-cert-chain-1.pem > SSL028-server-cert-chained-cert.pem
    # $ sudo openssl s_server -accept 443 -cert SSL028-server-cert-chain-2.pem -key SSL028-server-cert-chain-2.key -CAfile SSL028-server-cert-chained-cert.pem 
    print("Generating SSL028 Valid chained certificates. Need to concatinate manually using the following line $ cat ca-cert.pem SSL028-server-cert-chain-1.pem > SSL028-server-cert-chained-cert.pem")

    cert_c1, cert_priv_key_c1 = mkcert(ca_priv_key, cacert, sub_name=CERTIFICATE1_NAME)
    cert_c1.save(PATH + 'SSL028-server-cert-chain-1.pem')
    cert_priv_key_c1.save_key(PATH + 'SSL028-server-cert-chain-1.key', None)

    cert_c2, cert_priv_key_c2 = mkcert(cert_priv_key_c1, cert_c1, sub_name=CERTIFICATE2_NAME)
    cert_c2.save(PATH + 'SSL028-server-cert-chain-2.pem')
    cert_priv_key_c2.save_key(PATH + 'SSL028-server-cert-chain-2.key', None)


    # To 'cat' all the chained certs in one go, use the following command
    # $ cat ca-cert.pem SSL010-server-cert-chain-1.pem SSL010-server-cert-chain-2.pem SSL010-server-cert-chain-3.pem > SSL010-server-cert-chained-cert.pem | cat ca-cert.pem SSL011-server-cert-chain-1.pem SSL011-server-cert-chain-2.pem SSL011-server-cert-chain-3.pem > SSL011-server-cert-chained-cert.pem | cat ca-cert.pem SSL012-server-cert-chain-1.pem SSL012-server-cert-chain-2.pem SSL012-server-cert-chain-3.pem > SSL012-server-cert-chained-cert.pem | cat ca-cert.pem SSL013-server-cert-chain-1.pem SSL013-server-cert-chain-2.pem SSL013-server-cert-chain-3.pem > SSL013-server-cert-chained-cert.pem | cat ca-cert.pem SSL014-server-cert-chain-1.pem SSL014-server-cert-chain-2.pem SSL014-server-cert-chain-3.pem > SSL014-server-cert-chained-cert.pem | cat ca-cert.pem SSL015-server-cert-chain-1.pem SSL015-server-cert-chain-2.pem SSL015-server-cert-chain-3.pem > SSL015-server-cert-chained-cert.pem | cat ca-cert.pem SSL016-server-cert-chain-1.pem SSL016-server-cert-chain-2.pem > SSL016-server-cert-chained-cert.pem | cat ca-cert.pem SSL017-server-cert-chain-1.pem SSL017-server-cert-chain-2.pem > SSL017-server-cert-chained-cert.pem | cat ca-cert.pem SSL018-server-cert-chain-1.pem SSL018-server-cert-chain-2.pem > SSL018-server-cert-chained-cert.pem | cat ca-cert.pem SSL019-server-cert-chain-1.pem SSL019-server-cert-chain-2.pem > SSL019-server-cert-chained-cert.pem | cat ca-cert.pem SSL020-server-cert-chain-1.pem SSL020-server-cert-chain-2.pem > SSL020-server-cert-chained-cert.pem | cat ca-cert.pem SSL021-server-cert-chain-1.pem SSL021-server-cert-chain-2.pem > SSL021-server-cert-chained-cert.pem | cat ca-cert.pem SSL022-server-cert-chain-1.pem > SSL022-server-cert-chained-cert.pem | cat ca-cert.pem SSL023-server-cert-chain-1.pem > SSL023-server-cert-chained-cert.pem | cat ca-cert.pem SSL024-server-cert-chain-1.pem > SSL024-server-cert-chained-cert.pem | cat ca-cert.pem SSL025-server-cert-chain-1.pem > SSL025-server-cert-chained-cert.pem | cat ca-cert.pem SSL026-server-cert-chain-1.pem > SSL026-server-cert-chained-cert.pem | cat ca-cert.pem SSL027-server-cert-chain-1.pem > SSL027-server-cert-chained-cert.pem | cat ca-cert.pem SSL028-server-cert-chain-1.pem > SSL028-server-cert-chained-cert.pem


#ToDo
# implement proper certificate revokation so i can actaully test it