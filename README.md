# VltraSec
Welcome to VltraSec, a robust and secure command-line chat application designed for encrypted communication between two parties. VltraSec leverages the Diffie-Hellman key exchange protocol to establish a shared secret key, ensuring that all messages and file transfers are encrypted end-to-end. Whether you're communicating directly over a local network or tunneling through a service like Global Socket to bypass NAT restrictions, VltraSec provides a flexible and secure solution for private conversations.

![gsocket_demo](https://github.com/user-attachments/assets/19313c87-238c-4419-b48d-bd74642c6383)

# Introduction
The application uses a two-round Diffie-Hellman key exchange to generate a shared secret, the second round being encrypted with ```c-lcrypt``` which is then used to encrypt all communications. 

Key highlights include:
- **End-to-End Encryption**: Messages and files are encrypted using a shared secret, ensuring privacy.
- **Flexible Connectivity**: Supports both direct connections and tunneling via Global Socket for scenarios where direct access is limited.
- **File Transfer**: Send files securely over the chat with encryption applied to every transfer.
- **Username Exchange**: Users can identify each other with custom usernames, exchanged securely at the start of a session.

# Requirements
- ```OS: Linux```
- ```c-lcrypt``` Optional (github.com/Locotir/C-LCRYPT)
- ```gsocket``` Optional (Required for Global Socket tunneling)

# Installation
```
git clone https://github.com/Locotir/VltraSec
cd VltraSec
which c-lcrypt || yay -S c-lcrypt || (git clone https://github.com/Locotir/C-LCRYPT && cd C-LCRYPT
sudo pacman -Syu gcc base-devel gmp gmpxx openssl || sudo apt install build-essential libgomp1 libgmp-dev libssl-dev libpthread-stubs0-dev
g++ -std=c++17 -O3 -pipe -flto=$(nproc) -funroll-loops -fomit-frame-pointer -fno-plt -ffast-math -o C-LCRYPT C-LCRYPT.cpp -fopenmp && sudo cp C-LCRYPT /usr/bin/c-lcrypt)
which gsocket >/dev/null || yay -S gsocket || /bin/bash -c "$(curl -fsSL gsocket.io/install.sh)"
```

# How to use
## Options
  - `-s, --server`        Run in server mode.
  - `-c, --client`        Run in client mode.
  - `-H, --host`          Specify the host address.
  - - For server: Address to bind to. With `-k`, binds to localhost; otherwise, to specified host or default "0.0.0.0".
  - - For client: Server's address. Required if `-k` is not provided; with `-k`, connects to localhost via gsocket.
  - `-p, --port`          Specify the port number (required).
  - `-u, --username`      Set the username (required).
  - `-k, --key`           Set the secret for gsocket tunneling (optional).
  - `-X`                  Specify the encryption method: `aes` or `clcrypt` (required).
  - `-h, --help`          Display this help menu.

## Commands
  - `/send /path/to/file` : Send a file to the connected peer.

## Run with gsocket Tunneling
### Server
```vltrasec -s -p 8080 -u Alice -k mysecret -X aes```
- ```-s```: Assign server role
- ```-p 8080```: Local/Remote port for the server
- ```-u```: Define username
- ```-k vltrasec```: Sets the secret for gsocket tunneling
- ```-X aes```: Uses AES-256 encryption :(aes/clcrypt)

### Client
```vltrasec -c -p 8080 -u Bob -k mysecret -X aes```
- ```-c```: Assign client role
- ```-p 8080```: Local/Remote port for the server
- ```-k vltrasec```: Sets the secret for gsocket tunneling
- ```-X aes```: Uses AES-256 encryption :(aes/clcrypt)

## Run with Direct Connection
### Server
```vltrasec -s -H 0.0.0.0 -p 8080 -u Alice -X clcrypt```
- ```-s```: Assign server role
- ```-H 0.0.0.0```: Binds to all network interfaces.
- ```-p 8080```: Listens on port 8080.
- ```-u Alice```: Sets the server username to "Alice".
- ```-X clcrypt```: Uses c-lcrypt encryption :(aes/clcrypt)

### Client
```vltrasec -s -H 192.168.1.100 -p 8080 -u Bob -X clcrypt```
- ```-c```: Assign client role
- ```-H 192.168.1.100```: Server's IP address
- ```-p 8080```: Server's port.
- ```-u Bob```: Sets the client username to "Bob" 
- ```-X clcrypt```: Uses c-lcrypt encryption :(aes/clcrypt)

## Send File
```/send /path/to/file.txt```

- ```/send```: Specify file path

![direct_demo](https://github.com/user-attachments/assets/0df18740-a361-49dc-9bc8-43f15c9fedee)