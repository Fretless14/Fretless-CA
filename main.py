import os
from typing import List
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel
import subprocess
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class RequestData(BaseModel):
    common_name: str
    country: str
    state: str
    locality: str
    organization: str
    email: str
    alt_names: List[bytes] = None

    # Not implemented yet
    passphrase: str = None


app = FastAPI(docs_url=None, redoc_url=None)
app.add_middleware(ProxyHeadersMiddleware, trusted_hosts="*")


@app.post("/create-cert")
def create_cert(data: RequestData):
    try:
        # Generate the certificate request
        subprocess.run(["easyrsa", "gen-req", data.common_name, "nopass"], input=b"\n".join(data.alt_names), check=True)

        # Sign the certificate request
        subprocess.run(["easyrsa", "sign-req", "server", data.common_name], check=True)

        # Bundle the certificate and key into a PKCS12 file
        subprocess.run(["openssl", "pkcs12", "-export", "-inkey", f"pki/private/{data.common_name}.key", "-in",
                        f"pki/issued/{data.common_name}.crt", "-out", f"{data.common_name}.p12", "-passout",
                        "pass:"], check=True)

        # Return the PKCS12 file
        with open(f"{data.common_name}.p12", "rb") as f:
            return {"data": str(f.read())}

    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

@app.post("/generate_server_cert")
async def generate_server_cert(data: RequestData):
    try:
        subprocess.run(["/usr/bin/easyrsa", "gen-req", data.common_name, "nopass"], check=True,
                    input=f"{data.country}\n{data.state}\n{data.locality}\n{data.organization}\n{data.email}\n.\n.\n".encode('utf-8'),
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.run(["/usr/bin/easyrsa", "sign-req", "server", data.common_name, "nopass"], check=True,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        

        cert_path = f"/pki/pki/issued/{data.common_name}.crt"
        with open(cert_path, "r") as f:
            cert = str(f.read())
        
        key_path = f"/pki/pki/private/{data.common_name}.key"
        with open(key_path, "r") as f:
            key = str(f.read())

        return {"message": "Server cert generated successfully", "cert": cert, "key": key}
    
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
    


@app.post("/generate_client_cert")
async def generate_client_cert(data: RequestData):
    try:
        subprocess.run(["/usr/bin/easyrsa", "gen-req", data.common_name, "nopass"], check=True,
                    input=f"{data.country}\n{data.state}\n{data.locality}\n{data.organization}\n{data.email}\n.\n.\n".encode('utf-8'),
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.run(["/usr/bin/easyrsa", "sign-req", "client", data.common_name, "nopass"], check=True,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        cert_path = f"/pki/pki/issued/{data.common_name}.crt"
        with open(cert_path, "r") as f:
            cert = str(f.read())
        
        key_path = f"/pki/pki/private/{data.common_name}.pem"
        with open(key_path, "r") as f:
            key = str(f.read())

        return {"message": "Server cert generated successfully", "cert": cert, "key": key}
    

    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

@app.post("/renew_cert/")
async def renew_cert(data: RequestData):
    subprocess.run(["/usr/bin/easyrsa", "renew", data.common_name, "nopass"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    cert_path = f"/pki/pki/issued/{data.common_name}.crt"
    with open(cert_path, "r") as f:
        cert = str(f.read())
    return {"message": "Cert renewed successfully", "cert": cert}

@app.post("/check-cert-revoked/")
async def check_cert_status(data: dict):
    '''
    data: {'serial_number: ____ }
    '''

    crl_path = "/pki/pki/crl.pem"

    serial_number = str(data.get("serial_number"))


    # Check if the CRL file exists
    if not os.path.exists(crl_path):
        subprocess.run(["/usr/bin/easyrsa", "gen-crl"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    # Get the CRL data using the easyrsa show-crl command
    crl_data = subprocess.run(["/usr/bin/easyrsa", "show-crl"], stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.decode()

    # Extract the revoked serial numbers from the CRL output
    revoked_serial_numbers = set()
    for line in crl_data.splitlines():
        if "Serial Number: " in line:
            serial_number_str = line.strip().split(": ")[1]
            revoked_serial_numbers.add(str(int(serial_number_str, 16)))

    # Check if the certificate has been revoked
    if serial_number in revoked_serial_numbers: 
        return {"message": "Certificate has been revoked", "is_revoked": True}

    return {"message": "Certificate is valid", "is_revoked": False}

@app.post("/verify-cert/")
async def verify_cert(data: dict):
    cert_path = f"/pki/pki/issued/{data.get('common_name')}.crt"
    ca_path = "/pki/pki/ca.crt" 

    # Check if the certificate exists
    if not os.path.exists(cert_path):
         return check_cert_status({data.get('common_name')})

    # Check if the CA file exists
    if not os.path.exists(ca_path):
        return {"message": "ca.crt not found", "valid": False}

    # Check if the certificate is valid 
    try:
        subprocess.run(["openssl", "verify", "-CAfile", ca_path, cert_path], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        return HTTPException(status_code=e.returncode, detail=e.output.decode())

    return {"message": "Certificate is valid", "valid": True}

@app.post("/revoke_cert/")
async def revoke_cert(data: dict):
    try:
        subprocess.run(["/usr/bin/easyrsa", "revoke", data.get("common_name")], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.run(["/usr/bin/easyrsa", "gen-crl"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"Failed to revoke certificate: {e.stderr.decode()}")

    return {"message": "Cert revoked successfully"}
