#FRETLESSCA

An internal CA you can use to issue certificates for HTTPS. Core is EasyRSA, with FastAPI for external interfacing.

##Getting Started

Make sure you install Docker Desktop and docker-compose.

To simply run the app, (if you have docker installed), click on the executable "deploy" to build the image and container.
You will want to have a 'vars' file, an example is included. 
Just take the vars_example file and rename it to 'vars', and edit the configuration to your own settings.

Defaults to run on both internal and host ports 8089.

Check out main.py for the endpoints you can call.

Included is "CertManager.py" as an example to manage certs and to interface with the container.


This is not fully built out, but it is functional and can be used as an internal CA and manage certificates.