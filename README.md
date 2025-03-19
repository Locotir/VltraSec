# VltraSec
Welcome to VltraSec, a robust and secure command-line chat application designed for encrypted communication between two parties. VltraSec leverages the Diffie-Hellman key exchange protocol to establish a shared secret key, ensuring that all messages and file transfers are encrypted end-to-end. Whether you're communicating directly over a local network or tunneling through a service like Serveo to bypass NAT restrictions, VltraSec provides a flexible and secure solution for private conversations.

# Introduction
The application uses a two-round Diffie-Hellman key exchange to generate a shared secret, the second round being encrypted with ```c-lcrypt``` which is then used to encrypt all communications. 

Key highlights include:
- **End-to-End Encryption**: Messages and files are encrypted using a shared secret, ensuring privacy.
- **Flexible Connectivity**: Supports both direct connections and tunneling via Serveo for scenarios where direct access is limited.
- **File Transfer**: Send files securely over the chat with encryption applied to every transfer.
- **Username Exchange**: Users can identify each other with custom usernames, exchanged securely at the start of a session.

# Requirements
- ```OS: Linux```
- ```Python3```
- ```c-lcrypt``` (github.com/Locotir/C-LCRYPT)
- ```SSH Client``` (Required for Serveo tunneling)

# Installation
```
git clone https://github.com/Locotir/VltraSec
cd VltraSec
yay -S c-lcrypt || (git clone https://github.com/Locotir/C-LCRYPT && cd C-LCRYPT && $(sudo pacman -Syu gcc base-devel || sudo apt install build-essential libgomp1) && g++ -std=c++17 -O3 -pipe -flto=$(nproc) -funroll-loops -fomit-frame-pointer -fno-plt -ffast-math -o C-LCRYPT C-LCRYPT.cpp -fopenmp && sudo cp C-LCRYPT /usr/bin/c-lcrypt)
which python >/dev/null || which pip >/dev/null || sudo pacman -S --needed python python-pip || (sudo apt update && sudo apt install -y python3 python3-pip) || (sudo apt update && sudo apt install -y python3 python3-pip)
pip install -r requirements.txt
```

# How to use

## Run with Direct Connection
### Server
```python3 -u vltrasec.py -s -H 0.0.0.0 -p 8080 -u Alice```
- ```-H 0.0.0.0```: Binds to all network interfaces.
- ```-p 8080```: Listens on port 8080.
- ```-u Alice```: Sets the server username to "Alice".

### Client
```python3 -u vltrasec.py -c -H 192.168.1.100 -p 8080 -u Bob```
- ```-H 192.168.1.100```: Server's IP address
- ```-p 8080```: Server's port.
- ```-u Bob```: Sets the client username to "Bob" 

## Run with Serveo Tunneling
### Server
```python3 -u vltrasec.py -d stealth -p 8080 -u Alice```
- ```-d stealth```: Creates a tunnel to stealth.serveo.net (custom subdomain)
- ```-p 8080```: Local/Remote port for the server

### Client
```python3 -u vltrasec.py -c -d stealth -p 8081:8080 -u Bob```
- ```-d stealth```: Connects to stealth.serveo.net (same server subdomain)
- ```-p 8081:8080```: localPort:RemotePort 


## Send File
```/send /path/to/file.txt```

- ```/send```: Specify file path
