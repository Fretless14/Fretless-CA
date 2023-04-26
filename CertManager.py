import os
import subprocess
import requests
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime
import urllib3
from fastapi import HTTPException, status
import json

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) # CA is self signed unless you want to hook it up to another CA.

class CertificateException(Exception): pass

class CertRequest(BaseModel):
    common_name: str
    country: str
    state: str
    locality: str
    organization: str
    email: str
    alt_names: List[str] = []


# TODO: implement passwords on certs. Need to modify 'fretless-ca' repo code unless already done.

class CertManager:
    def __init__(self, url: str = "https://host.docker.internal:8089", cert_dir: str = "default"):    # Replace with your url/ports. Set to default for FretlessCA
        self.url = url
        self.homedir = os.path.dirname(os.path.dirname(__file__))   # Replace with your home directory


        if cert_dir == 'default':
            self.cert_dir = os.path.join(self.homedir, "certs/")    # Replace with your certs directory

            if not os.path.exists(self.cert_dir):
                os.makedirs(self.cert_dir)
        else:
            self.cert_dir = cert_dir

    def get_cert(self, common_name:str):
        cert_path = os.path.join(self.cert_dir, common_name+".crt")
        cert = None

        if os.path.isfile(cert_path):
            with open(cert_path, "r") as f:
                cert = str(f.read())
        return cert

    def is_valid(self, common_name: str):
        resp = requests.post(f"{self.url}verify-cert", json={"common_name": common_name}, verify=False)
        if resp.status_code != 200:
            raise CertificateException(resp.json())

        cert_data = resp.json()
        if cert_data.get("message").lower() in ["certificate not found", "ca.crt not found"]:
            raise CertificateException(cert_data["message"])

        is_valid = cert_data.get("valid")

        return is_valid

    def is_revoked(self, serial_number: str):
        resp = requests.post(f"{self.url}check-cert-revoked", json={"serial_number": serial_number}, verify=False)
        if resp.status_code != 200:
            raise CertificateException(resp.json())
        cert_data = resp.json()
        is_revoked = cert_data.get("is_revoked")

        return is_revoked

    def is_expired(self, common_name: str) -> bool:
        """
            Checks if a certificate is expired.

            Args:
                cert_path (str): The path to the certificate file.

            Returns:
                bool: True if the certificate is expired, False otherwise.
            """
        cert_path = os.path.join(self.cert_dir, common_name + ".crt")
        with open(cert_path, "r") as f:
            cert = f.read()

        # Get the expiration date from the certificate
        expiry_date_str = subprocess.check_output(["openssl", "x509", "-noout", "-enddate"],
                                                  input=cert.encode()).decode().strip()[9:]
        expiry_date = datetime.strptime(expiry_date_str, "%b %d %H:%M:%S %Y %Z")

        # Return True if the certificate is expired
        return expiry_date < datetime.now()

    def needs_renewal(self, common_name:str, days_before_expire: int = 4) -> bool:
        """
        Checks if a certificate needs to be renewed based on the number of days before its expiration date.

        Args:
            cert_path (str): The path to the certificate file.
            days_before_expire (int): The number of days before the certificate's expiration date to check for renewal.

        Returns:
            bool: True if the certificate needs to be renewed, False otherwise.
        """

        cert_path = os.path.join(self.cert_dir, common_name + ".crt")
        with open(cert_path, "r") as f:
            cert = f.read()

        # Get the expiration date from the certificate
        expiry_date_str = subprocess.check_output(["openssl", "x509", "-noout", "-enddate"],
                                                  input=cert.encode()).decode().strip()[9:]
        expiry_date = datetime.strptime(expiry_date_str, "%b %d %H:%M:%S %Y %Z")

        # Calculate the number of days until the certificate expires
        days_until_expiry = (expiry_date - datetime.now()).days

        # Return True if the number of days until expiry is less than the given threshold
        return days_until_expiry <= days_before_expire

    def create_cert(self, cert_req: CertRequest):
        resp = requests.post(f"{self.url}create-cert", json=cert_req.dict(), verify=False)
        if resp.status_code != 200:
            try:
                self.revoke_cert(common_name=cert_req.common_name)
            except Exception as e:
                print(e)
            raise CertificateException(resp.json())
        cert_data = resp.json()
        cert_data = cert_data.get("cert")
        key_data = cert_data.get("key")
        self._save_cert(common_name=cert_req.common_name, cert_data=cert_data)
        self._save_key(common_name=cert_req.common_name, key_data=key_data)
        cert_data = cert_data.get("cert")
        key_data = cert_data.get("key")
        self._save_cert(common_name=cert_req.common_name, cert_data=cert_data)
        self._save_key(common_name=cert_req.common_name, key_data=key_data)
        return resp.json()

    def generate_server_cert(self, cert_req: CertRequest):
        resp = requests.post(f"{self.url}generate_server_cert", json=cert_req.dict(), verify=False)
        if resp.status_code != 200:
            try:
                self.revoke_cert(common_name=cert_req.common_name)
            except Exception as e:
                print(e)
            raise CertificateException(resp.json())
        cert_response = resp.json()
        print(cert_response)

        if cert_response is not None:
            if not isinstance(cert_response, str):
                key_data = cert_response.get("key")
                cert_data = cert_response.get("cert")
            else:
                cert_response = json.loads(cert_response)
                cert_data = cert_response.get("cert")
                key_data = cert_response.get("key")

            self._save_cert(common_name=cert_req.common_name, cert_data=cert_data)
            self._save_key(common_name=cert_req.common_name, key_data=key_data)
        return resp.json()

    def generate_client_cert(self, cert_req: CertRequest):
        resp = requests.post(f"{self.url}generate_client_cert", json=cert_req.dict(), verify=False)
        if resp.status_code != 200:
            raise CertificateException(resp.json())
        cert_data = resp.json()
        cert_data = cert_data.get("cert")
        key_data = cert_data.get("key")
        self._save_cert(common_name=cert_req.common_name, cert_data=cert_data)
        self._save_key(common_name=cert_req.common_name, key_data=key_data)
        return resp.json()

    def renew_cert(self, cert_req: CertRequest) -> None:
        resp = requests.post(f"{self.url}renew_cert", json=cert_req.dict(), verify=False)
        if resp.status_code != 200:
            raise CertificateException(resp.json())
        cert_data = resp.json()
        cert_data = cert_data.get("cert")
        key_data = cert_data.get("key")
        self._save_cert(common_name=cert_req.common_name, cert_data=cert_data)
        self._save_key(common_name=cert_req.common_name, key_data=key_data)
        return resp.json()

    def revoke_cert(self, common_name: str) -> None:
        resp = requests.post(f"{self.url}revoke_cert", json={"common_name": common_name}, verify=False)
        if resp.status_code != 200:
            raise CertificateException(resp.json())

        filename = os.path.join(self.cert_dir, f"{common_name}.crt")
        if os.path.exists(filename):
            os.remove(filename)
            print(f"Removed certificate for {common_name} from {filename}")
        else:
            print(f"Certificate file for {common_name} not found at {filename}")
        return resp.json()

    def _save_cert(self, common_name, cert_data: dict) -> None:
        if cert_data is not None:
            filename = os.path.join(self.cert_dir, f"{common_name}.crt")
            with open(filename, 'w') as f:
                f.write(cert_data)
            print(f"Saved certificate for {common_name} to {filename}")

    def _save_key(self, common_name, key_data: dict) -> None:
        if key_data is not None:
            filename = os.path.join(self.cert_dir, f"{common_name}.key")
            with open(filename, 'w') as f:
                f.write(key_data)
            print(f"Saved certificate for {common_name} to {filename}")

if __name__ == "__main__":
    print("Managing HTTPS cert...")
    Cert_Request = CertRequest(common_name="exampleCN", country="US", state="CA", locality="LosAngeles",
                       organization="Fretless-CA", email="test@test.com")
    # Change url to localhost if not running in docker container
    CM = CertManager(url="https://host.docker.internal:8089/", cert_dir="default")
    cert_path = os.path.join(CM.cert_dir, Cert_Request.common_name+".crt")


    is_expired = None
    needs_renewed = None
    new_cert = None

    cert = CM.get_cert(common_name=Cert_Request.common_name)
    if cert is None:
        print("Creating HTTPS server cert...")
        CM.generate_server_cert(cert_req=Cert_Request)
        new_cert = True
    else:
        # Get the serial number of the certificate
        serial_number = None
        if os.path.isfile(cert_path):
            with open(cert_path, "rb") as f:
                cert_data = f.read()
            serial_number = x509.load_pem_x509_certificate(cert_data).serial_number

        print("Checking if HTTPS cert is expired...")
        is_expired = CM.is_expired(common_name=Cert_Request.common_name)
        if is_expired:
            print("Cert expired, generating new server cert")
            CM.generate_server_cert(cert_req=Cert_Request)


        print("Checking if HTTPS cert is revoked...")
        is_revoked = CM.is_revoked(serial_number=serial_number)
        if is_revoked:
            raise CertificateException("Cert is revoked")


        print("Checking if HTTPS cert is valid...")
        is_valid = CM.is_valid(common_name=Cert_Request.common_name)
        if not is_valid:
            raise CertificateException("Cert is not valid")


        print("Checking if HTTPS cert needs renewed...")
        needs_renewed = CM.needs_renewal(common_name=Cert_Request.common_name, days_before_expire=4)    # Change days_before_expire if necessary
        if needs_renewed:
            print("Renewing server cert...")
            CM.renew_cert(cert_req=Cert_Request)
