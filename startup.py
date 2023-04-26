import os
import subprocess


if __name__ == '__main__':
    # pass

    # Make sure openssl conf is in the pki directory
    if not os.path.exists("/pki/openssl-easyrsa.cnf"):
        subprocess.run("cp /usr/share/easy-rsa/easyrsa3/openssl-easyrsa.cnf /pki/openssl-easyrsa.cnf", shell=True, check=True)
        subprocess.run("cp -R /usr/share/easy-rsa/easyrsa3/x509-types /pki/x509-types", shell=True, check=True)

    # Make sure vars file in pki directory is synced with the vars file being used by EasyRSA ( /vars )
    if not os.path.exists("/pki/vars"):
        try:
            subprocess.run("cp /vars /pki/vars", shell=True, check=True)
        except Exception as e:
            print(e)

    # Init pki if not already
    if not os.path.exists("/pki/pki/"):
        subprocess.run("easyrsa init-pki", shell=True, check=True)

    # Build the Certificate Authority if not already
    if not os.path.exists("/pki/pki/ca.crt"):
        try:
            subprocess.run("cd /pki && /usr/bin/easyrsa build-ca nopass", shell=True, check=True)
        except Exception as e:
            print(e)

    # Create cert for HTTPS for connections to this CA (must be self signed since this IS the CA)
    if not os.path.exists("/pki/pki/issued/ca-server.crt") or not os.path.exists("/pki/pki/private/ca-server.key"):
        try:
            subprocess.run("cd /pki && /usr/bin/easyrsa gen-req ca-server nopass", shell=True, check=True)
            subprocess.run("cd /pki && /usr/bin/easyrsa sign-req server ca-server", shell=True, check=True)
        except Exception as e:
            print(e)

    subprocess.run("python -m uvicorn main:app --host 0.0.0.0 --port 8089 --ssl-certfile '/pki/pki/issued/ca-server.crt' --ssl-keyfile '/pki/pki/private/ca-server.key'",
                   shell=True, check=True)