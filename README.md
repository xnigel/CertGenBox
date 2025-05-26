# Introduction
CertGenBox is a tool that generates a series asymetric keys, CA, and certificates with valid and non-valid parameters. The purposes of creating this tool is that tester could use these various certificate-n-key conbinations to verify the TLS connections, mutual authentications, or even the MITM attacks.

# Deployment
The reconmmended testing environment is in a Debian Linux (Ubuntu or Kali). Since the Python program involks m2crypto library, you may also need to install it before use.

## Step 1 - install python3
```
sudo apt-get update && upgrade -y
sudo apt-get install python3
```
## Step 2 - install pip3
```
sudo apt-get install python3-pip
pip install --upgrade pip
```
## Step 3 - install m2crypto
```
sudo apt-get install python3-dev
sudo apt-get install python3-m2crypto
```
# Program execution
```
python3 CertGenBox_v2.1.py
```

# Conclusion

