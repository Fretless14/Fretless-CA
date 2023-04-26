FROM tiangolo/uvicorn-gunicorn-fastapi:python3.11-2023-03-27


RUN apt-get update && apt-get install -y git

# Cryptography pacakge
#=================================
RUN apt-get update && apt-get install -y build-essential libssl-dev libffi-dev \
    python3-dev cargo pkg-config

#=================================







RUN addgroup --system --gid 214 fretless-ca-group && \
    adduser --system --home /pki --uid 214 --gid 214 --shell /bin/sh fretless-ca-user && \
    chown fretless-ca-user:fretless-ca-group /pki


# EASY RSA
#=================================
RUN git clone https://github.com/OpenVPN/easy-rsa.git /usr/share/easy-rsa && \
    ln -s /usr/share/easy-rsa/easyrsa3/easyrsa /usr/bin/easyrsa && \
    chmod +x /usr/bin/easyrsa

COPY vars /vars
COPY . /pki


RUN chown fretless-ca-user:fretless-ca-group /vars && \
    chmod 700 /vars

RUN chown fretless-ca-user:fretless-ca-group /pki -R && \
    chmod 700 /pki -R


WORKDIR /pki

#====================================


COPY ./requirements.txt /pki/requirements.txt
RUN pip install --no-cache-dir --upgrade -r /pki/requirements.txt

USER fretless-ca-user

CMD ["python", "/pki/startup.py"]


