import socket
import base64
import argparse
import threading
import os
import subprocess
import signal
import sys
import tempfile
import shutil
import time
import datetime
import requests  
import shutil


# =============================================== Key Exchange Conf ===============================================
# Initial configuration for 8192-bit MODP Group
P_hex = """FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 
29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64
ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7
ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B
F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31
43DB5BFC E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7
88719A10 BDBA5B26 99C32718 6AF4E23C 1A946834 B6150BDA
2583E9CA 2AD44CE8 DBBBC2DB 04DE8EF9 2E8EFC14 1FBECAA6
287C5947 4E6BC05D 99B2964F A090C3A2 233BA186 515BE7ED
1F612970 CEE2D7AF B81BDD76 2170481C D0069127 D5B05AA9
93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34028492
36C3FAB4 D27C7026 C1D4DCB2 602646DE C9751E76 3DBA37BD
F8FF9406 AD9E530E E5DB382F 413001AE B06A53ED 9027D831
179727B0 865A8918 DA3EDBEB CF9B14ED 44CE6CBA CED4BB1B
DB7F1447 E6CC254B 33205151 2BD7AF42 6FB8F401 378CD2BF
5983CA01 C64B92EC F032EA15 D1721D03 F482D7CE 6E74FEF6
D55E702F 46980C82 B5A84031 900B1C9E 59E7C97F BEC7E8F3
23A97A7E 36CC88BE 0F1D45B7 FF585AC5 4BD407B2 2B4154AA
CC8F6D7E BF48E1D8 14CC5ED2 0F8037E0 A79715EE F29BE328
06A1D58B B7C5DA76 F550AA3D 8A1FBFF0 EB19CCB1 A313D55C
DA56C9EC 2EF29632 387FE8D7 6E3C0468 043E8F66 3F4860EE
12BF2D5B 0B7474D6 E694F91E 6DBE1159 74A3926F 12FEE5E4
38777CB6 A932DF8C D8BEC4D0 73B931BA 3BC832B6 8D9DD300
741FA7BF 8AFC47ED 2576F693 6BA42466 3AAB639C 5AE4F568
3423B474 2BF1C978 238F16CB E39D652D E3FDB8BE FC848AD9
22222E04 A4037C07 13EB57A8 1A23F0C7 3473FC64 6CEA306B
4BCBC886 2F8385DD FA9D4B7F A2C087E8 79683303 ED5BDD3A
062B3CF5 B3A278A6 6D2A13F8 3F44F82D DF310EE0 74AB6A36
4597E899 A0255DC1 64F31CC5 0846851D F9AB4819 5DED7EA1
B1D510BD 7EE74D73 FAF36BC3 1ECFA268 359046F4 EB879F92
4009438B 481C6CD7 889A002E D5EE382B C9190DA6 FC026E47
9558E447 5677E9AA 9E3050E2 765694DF C81F56E8 80B96E71
60C980DD 98EDD3DF FFFFFFFF FFFFFFFF"""

P = int(P_hex.replace("\n", "").replace(" ", ""), 16)
G = 2  # Generator
sys.set_int_max_str_digits(100000)  # Allow large strings
# =============================================================================================================================================

server_socket = None
client_socket = None
ssh_process = None
print_lock = threading.Lock()
stop_event = threading.Event()

# Terminal colors
class bcolors:
    PURPLE = '\033[95m'
    BLUE = '\033[94m'
    BLUEL = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    UNDERLINE = '\033[4m'
    WHITE = '\033[37m'
    ORANGE = '\33[33m'
    VIOLET = '\33[35m'
    GREY = '\033[90m'

def remove_print_line(): # Delete last print
    sys.stdout.write("\033[F")  # Move cursor up one line
    sys.stdout.write("\033[K")  # Clear current line
    sys.stdout.flush()

def get_timestamp(): # [hh:mm]
    now = datetime.datetime.now()
    return f"[{now.strftime('%H:%M')}]"

def get_available_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]

def print_lines(char): # print char across term width
    terminal_size = shutil.get_terminal_size()
    terminal_width = terminal_size.columns
    print(char*terminal_width)

def signal_handler(sig, frame):
    with print_lock:
        print("\nInterrupt received. Closing...")
    stop_event.set()
    if server_socket:
        server_socket.close()
    if client_socket:
        client_socket.close()
    if ssh_process:
        try:
            os.killpg(os.getpgid(ssh_process.pid), signal.SIGTERM)
        except Exception as e:
            with print_lock:
                print(f"Error terminating SSH process group: {e}")
    sys.exit(0)

def encode_message(message):
    # Save the message to a temporary file and encrypt it
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file.write(message.encode())
        temp_path = temp_file.name
    subprocess.run(["c-lcrypt", "-e", temp_path, "-P", PASSWORD],
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    with open(temp_path, "rb") as temp_file:
        encrypted_data = temp_file.read()
    os.remove(temp_path)
    return base64.b64encode(encrypted_data)

def decode_messages(encoded_base64):
    decoded_data = base64.b64decode(encoded_base64)
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file.write(decoded_data)
        temp_path = temp_file.name
    result = subprocess.run(["c-lcrypt", "-d", temp_path, "-P", PASSWORD],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != 0:
        raise ValueError(f"Decryption failed: {result.stderr.decode()}")
    with open(temp_path, "r") as temp_file:
        message = temp_file.read()
    os.remove(temp_path)
    return message

def send_large_data(conn, data):
    # Send large data (e.g., keys) with a length prefix
    data_bytes = data.encode()
    length = len(data_bytes)
    conn.sendall(length.to_bytes(4, 'big'))
    chunk_size = 16384
    for i in range(0, length, chunk_size):
        conn.sendall(data_bytes[i:i + chunk_size])

def recv_large_data(conn):
    length_bytes = conn.recv(4)
    if not length_bytes:
        with print_lock:
            print("Error: No data received for length prefix")
        return None
    length = int.from_bytes(length_bytes, 'big')
    data = b''
    while len(data) < length:
        chunk = conn.recv(min(16384, length - len(data)))
        if not chunk:
            with print_lock:
                print("Error: Connection closed while receiving data")
            raise ConnectionError("Connection closed while receiving data")
        data += chunk
    return data.decode()

def generate_dh_keys():
    private_key = int.from_bytes(os.urandom(4), 'big') % P
    public_key = pow(G, private_key, P)
    return private_key, public_key

def exchange_username(conn, username, is_server):
    if is_server:
        encoded_username = encode_message(username)
        conn.sendall(encoded_username)
        other_username_encoded = conn.recv(1024)
        other_username = decode_messages(other_username_encoded)
    else:
        other_username_encoded = conn.recv(1024)
        other_username = decode_messages(other_username_encoded)
        encoded_username = encode_message(username)
        conn.sendall(encoded_username)
    return other_username

def send_file(conn, file_path):
    remove_print_line()
    if not os.path.isfile(file_path):
        with print_lock:
            print(f"Error: {file_path} is not a valid file/directory.")
        return
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_path = temp_file.name
        with open(file_path, "rb") as original_file:
            temp_file.write(original_file.read())
    print(bcolors.WHITE + "[" + bcolors.RED + "🔥" + bcolors.WHITE + "]" + bcolors.WHITE + " Encrypting file...")
    result = subprocess.run(["c-lcrypt", "-e", temp_path, "-P", PASSWORD],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != 0:
        with print_lock:
            print(f"Error encrypting file: {result.stderr.decode()}")
        os.remove(temp_path)
        return

    with open(temp_path, "rb") as encrypted_file:
        encrypted_data = encrypted_file.read()
    os.remove(temp_path)
    remove_print_line()
    print(bcolors.WHITE + "[" + bcolors.YELLOW + "✈" + bcolors.WHITE + "]" + bcolors.WHITE + " Sending file...")
    conn.sendall(b"FILE")
    file_name = os.path.basename(file_path)
    encoded_file_name = encode_message(file_name)
    conn.sendall(len(encoded_file_name).to_bytes(4, 'big'))
    conn.sendall(encoded_file_name)
    conn.sendall(len(encrypted_data).to_bytes(8, 'big'))
    chunk_size = 16384
    for i in range(0, len(encrypted_data), chunk_size):
        conn.sendall(encrypted_data[i:i + chunk_size])
    with print_lock:
        remove_print_line()
        print(bcolors.WHITE + "[" + bcolors.GREEN + "↑" + bcolors.WHITE + "]" + bcolors.WHITE + " File " + bcolors.BLUEL + f"{file_name}" + bcolors.WHITE + " sent successfully.\n\n👤 > ", end="")

def send_file_in_thread(conn, file_path):
    threading.Thread(target=send_file, args=(conn, file_path), daemon=True).start()

def read_exactly(conn, n):
    data = b''
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Connection closed while reading")
        data += chunk
    return data

# =================================================================================== Manage Messages & Files ===================================================================================
def receive_data(conn, username):
    while not stop_event.is_set():
        try:
            indicator = read_exactly(conn, 4)
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Manage File Sending ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
            if indicator == b"FILE":
                remove_print_line()
                print(bcolors.WHITE + "\n[" + bcolors.BLUE + "✈" + bcolors.WHITE + "]" + bcolors.WHITE + " Receiving file...")
                name_length_bytes = read_exactly(conn, 4)
                name_length = int.from_bytes(name_length_bytes, 'big')
                encoded_file_name = read_exactly(conn, name_length)
                file_name = decode_messages(encoded_file_name) # Read filename
                remove_print_line()
                print(bcolors.WHITE + "[" + bcolors.BLUE + "?" + bcolors.WHITE + "]" + bcolors.YELLOW + " ✈ " + bcolors.VIOLET + f"{username} " + bcolors.WHITE + "is sending file: " + bcolors.BLUEL + f"{file_name}" + bcolors.WHITE + "\n👤 > ", end="")
                print(bcolors.WHITE + "[" + bcolors.GREEN + "~" + bcolors.WHITE + "]" + bcolors.WHITE + " Receiving file data...")
                content_length_bytes = read_exactly(conn, 8)
                content_length = int.from_bytes(content_length_bytes, 'big')
                encrypted_data = read_exactly(conn, content_length) # Recive Enc File
                remove_print_line()
                print(bcolors.WHITE + "[" + bcolors.RED + "@" + bcolors.WHITE + "]" + bcolors.WHITE + " Decrypting file...")
                with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                    temp_path = temp_file.name
                    temp_file.write(encrypted_data)
                result = subprocess.run(["c-lcrypt", "-d", temp_path, "-P", PASSWORD],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                if result.returncode != 0:
                    with print_lock:
                        print(f"Error decrypting file: {result.stderr.decode()}")
                    os.remove(temp_path)
                    continue
                output_path = os.path.join(os.getcwd(), file_name)
                shutil.move(temp_path, output_path)
                remove_print_line()
                print(bcolors.WHITE + "[" + bcolors.GREEN + "=" + bcolors.WHITE + "]" + bcolors.WHITE + f" File saved: {output_path}" + bcolors.WHITE + "\n👤 > ", end="")

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Manage Messages ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
            else:
                # The message length prefix is the indicator itself
                text_length = int.from_bytes(indicator, 'big')
                if text_length <= 0:
                    raise ValueError(f"Invalid message length: {text_length}, check conn")
                remove_print_line()
                print(bcolors.WHITE + "[" + bcolors.GREEN + "~" + bcolors.WHITE + "]" + bcolors.WHITE + " Receiving message data...")
                encoded_message = read_exactly(conn, text_length) # Recive Enc message
                remove_print_line()
                print(bcolors.WHITE + "[" + bcolors.RED + "@" + bcolors.WHITE + "]" + bcolors.WHITE + " Decrypting message...")
                message = decode_messages(encoded_message) # Dec message
                remove_print_line()
                with print_lock:
                    timestamp = get_timestamp()
                    print(f"\n{timestamp} " + bcolors.YELLOW + " ✈ " + bcolors.VIOLET + f"{username}: " + 
                          bcolors.GREEN + f"{message}" + bcolors.WHITE + "\n👤 > ", end="") # Print message recived
        except Exception as e:
            with print_lock:
                if "Connection closed" in str(e):
                    remove_print_line()
                    timestamp = get_timestamp()
                    print(f"\n{timestamp} " + bcolors.WHITE + "[" + bcolors.RED + "!" + bcolors.WHITE + "] " + bcolors.PURPLE + f"{username}" + bcolors.RED + " has left" + bcolors.WHITE)
                else:
                    print(f"Error receiving data: {e}")
            stop_event.set()
            break
# -=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=-

# ______________________________________________________________________________________________________________________________________________________________________________________________
# ===================================================================================== SERVER SIDE MANAGE =====================================================================================
# ``````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````
def run_server(host_or_domain, port, use_serveo=False):
    global server_socket, ssh_process, PASSWORD
    print_lines("=")

# ..................... Serveo.net Init .....................       
    if use_serveo:
        domain = host_or_domain if host_or_domain.endswith('.serveo.net') else host_or_domain + '.serveo.net'
        ssh_cmd = ["ssh", "-R", f"{domain}:{port}:localhost:{port}", "serveo.net"]
        
        # Open log file for SSH output
        with open("ssh_server_log.txt", "w") as log:
            # Run SSH tunnel in background with Popen
            ssh_process = subprocess.Popen(
                ssh_cmd,
                preexec_fn=os.setsid,  # Create a new process group for clean termination
                stdin=subprocess.PIPE,
                stdout=log,
                stderr=log
            )
        
        with print_lock:
            print(f"🖧 SSH Tunnel running in background: {' '.join(ssh_cmd)}")
        HOST = '0.0.0.0'

# ..................... Direct Conn ..................... 
    else:
        HOST = host_or_domain

# -------------------------- Start Conn -------------------------
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        server_socket = s
        s.bind((HOST, port))
        s.listen()
        with print_lock:
            print(f"📡 Listening on {HOST}:{port}")
        conn, addr = s.accept()
        with conn:
            with print_lock:
                print(f"🟢 Connected to {addr[0]}")

# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ First Round Key Exchange @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
            print(bcolors.WHITE + "[" + bcolors.ORANGE + "%" + bcolors.WHITE + "]" + bcolors.WHITE + " Starting Diffie-Hellman key exchange")
            a_private, a_public = generate_dh_keys() # Gen keys
            print(bcolors.WHITE + "         [" + bcolors.GREEN + "=" + bcolors.WHITE + "]" + bcolors.WHITE + " Public key generated")
            send_large_data(conn, str(a_public)) # Send PubKey
            print(bcolors.WHITE + "         [" + bcolors.YELLOW + "↑" + bcolors.WHITE + "]" + bcolors.WHITE + " Sent public key")
            b_public_str = recv_large_data(conn)
            b_public = int(b_public_str) # Recived PrivKey
            print(bcolors.WHITE + "         [" + bcolors.YELLOW + "↓" + bcolors.WHITE + "]" + bcolors.WHITE + " Received public key")
            shared_secret = pow(b_public, a_private, P) # Calc SS
            print(bcolors.WHITE + "         [" + bcolors.RED + "🔒" + bcolors.WHITE + "]" + bcolors.WHITE + " Shared secret calculated")
            PASSWORD = str(shared_secret) # SS as Passwd
            print(bcolors.WHITE + "[" + bcolors.RED + "🔒" + bcolors.WHITE + "]" + bcolors.WHITE + " First secret key set")

            print_lines("-")
# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ Second Round Key Exchange @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@            
            print(bcolors.WHITE + "[" + bcolors.ORANGE + "%" + bcolors.WHITE + "]" + bcolors.WHITE + " Starting second Diffie-Hellman key exchange")
            a_private2, a_public2 = generate_dh_keys() # Gen keys
            print(bcolors.WHITE + "         [" + bcolors.GREEN + "=" + bcolors.WHITE + "]" + bcolors.WHITE + " Second public key generated")
            a_public2_str = str(a_public2)
            encoded_a_public2 = encode_message(a_public2_str) # Enc PubKey
            print(bcolors.WHITE + "         [" + bcolors.RED + "🔥" + bcolors.WHITE + "]" + bcolors.WHITE + " Encrypting second public key")
            conn.sendall(len(encoded_a_public2).to_bytes(4, 'big'))
            conn.sendall(encoded_a_public2) # Send Enc PubKey
            print(bcolors.WHITE + "         [" + bcolors.YELLOW + "↑" + bcolors.WHITE + "]" + bcolors.WHITE + " Sent encrypted second public key")
            encoded_b_public2_length_bytes = read_exactly(conn, 4)
            encoded_b_public2_length = int.from_bytes(encoded_b_public2_length_bytes, 'big')
            encoded_b_public2 = read_exactly(conn, encoded_b_public2_length) # Recive Enc PubKey
            print(bcolors.WHITE + "         [" + bcolors.YELLOW + "↓" + bcolors.WHITE + "]" + bcolors.WHITE + " Received encrypted second public key")
            b_public2_str = decode_messages(encoded_b_public2) # Dec Pubkey
            print(bcolors.WHITE + "         [" + bcolors.RED + "@" + bcolors.WHITE + "]" + bcolors.WHITE + " Decrypting second public key")
            b_public2 = int(b_public2_str)
            shared_secret2 = pow(b_public2, a_private2, P) # Calc SS
            print(bcolors.WHITE + "         [" + bcolors.RED + "🔒" + bcolors.WHITE + "]" + bcolors.WHITE + " Second shared secret calculated")


            PASSWORD = str(shared_secret2) # SS as Passwd
            print(bcolors.WHITE + "[" + bcolors.RED + "🔒" + bcolors.WHITE + "]" + bcolors.WHITE + " Final secret key set")
            
            # ........................ Username Exchange ........................
            print(bcolors.GREY + "Waiting for client..." + bcolors.WHITE)
            client_username = exchange_username(conn, args.username, True)
            remove_print_line()
            print("🔗 Client: " + bcolors.VIOLET + f"{client_username}" + bcolors.WHITE)
            print_lines("=")

# $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ Communication Manager $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
            receive_thread = threading.Thread(target=receive_data, args=(conn, client_username), daemon=True)
            receive_thread.start()
            while not stop_event.is_set():
                print("\n👤 > ", end="", flush=True)
                message = sys.stdin.readline().strip()
                if message.startswith("/send "): # Intercept sendFile indicator
                    file_path = message.split(" ", 1)[1]
                    send_file_in_thread(conn, file_path)
                elif message:
                    print(bcolors.WHITE + "[" + bcolors.RED + "🔥" + bcolors.WHITE + "]" + bcolors.WHITE + " Encrypting message...")
                    encoded = encode_message(message)
                    remove_print_line()
                    print(bcolors.WHITE + "[" + bcolors.YELLOW + "✈" + bcolors.WHITE + "]" + bcolors.WHITE + " Sending message...")
                    conn.sendall(len(encoded).to_bytes(4, 'big'))
                    conn.sendall(encoded)
                    remove_print_line()
                    print(bcolors.GREY + "Message sent" + bcolors.GREEN + " ✔" + bcolors.WHITE)
            receive_thread.join()
# -=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=-

# ______________________________________________________________________________________________________________________________________________________________________________________________
# ===================================================================================== CLIENT SIDE MANAGE =====================================================================================
# ``````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````
def run_client(host_or_domain, port_or_local_port, external_port=None, use_serveo=False):
    global client_socket, ssh_process, PASSWORD
    print_lines("=")

# ..................... Serveo.net Init .....................   
    if use_serveo:
        domain = host_or_domain if host_or_domain.endswith('.serveo.net') else host_or_domain + '.serveo.net'
        local_port = port_or_local_port
        ssh_cmd = ["ssh", "-L", f"{local_port}:{domain}:{external_port}", "serveo.net"]
        with open("ssh_client_log.txt", "w") as log:
            ssh_process = subprocess.Popen(ssh_cmd, preexec_fn=os.setsid, stdin=subprocess.PIPE, stdout=log, stderr=log)
            time.sleep(1) # Wait for conn establishment
        with print_lock:
            print(f"🖧 Using SSH Tunnel: {' '.join(ssh_cmd)}")
        connect_host = 'localhost'
        connect_port = local_port

# ..................... Direct Conn .....................        
    else:
        connect_host = host_or_domain
        connect_port = port_or_local_port

# -------------------------- Start Conn -------------------------
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        client_socket = s
        max_attempts = 10
        for attempt in range(max_attempts):
            try:
                s.connect((connect_host, connect_port))
                with print_lock:
                    print(f"🟢 Connected to {connect_host}:{connect_port}")
                break
            except ConnectionRefusedError:
                with print_lock:
                    print(f"❌ Connection refused, waiting... (attempt {attempt+1}/{max_attempts})")
                time.sleep(1)
        else:
            with print_lock:
                print("Could not connect after several attempts. Exiting.")
            sys.exit(1)

# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ First Round Key Exchange @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
        print(bcolors.WHITE + "[" + bcolors.ORANGE + "%" + bcolors.WHITE + "]" + bcolors.WHITE + " Starting Diffie-Hellman key exchange")
        a_public_str = recv_large_data(s)
        a_public = int(a_public_str) # Recived PubKey
        print(bcolors.WHITE + "         [" + bcolors.YELLOW + "↓" + bcolors.WHITE + "]" + bcolors.WHITE + " Received public key")
        b_private, b_public = generate_dh_keys() # Gen keys
        print(bcolors.WHITE + "         [" + bcolors.GREEN + "=" + bcolors.WHITE + "]" + bcolors.WHITE + " Public key generated")
        send_large_data(s, str(b_public)) # Send PubKey
        print(bcolors.WHITE + "         [" + bcolors.YELLOW + "↑" + bcolors.WHITE + "]" + bcolors.WHITE + " Sent public key")
        shared_secret = pow(a_public, b_private, P) # Calc SS
        print(bcolors.WHITE + "         [" + bcolors.RED + "🔒" + bcolors.WHITE + "]" + bcolors.WHITE + " Shared secret calculated")
        PASSWORD = str(shared_secret) # SS as Passwd
        print(bcolors.WHITE + "[" + bcolors.RED + "🔒" + bcolors.WHITE + "]" + bcolors.WHITE + " First secret key set")

        print_lines("-")
# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ Second Round Key Exchange @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
        print(bcolors.WHITE + "[" + bcolors.ORANGE + "%" + bcolors.WHITE + "]" + bcolors.WHITE + " Starting second Diffie-Hellman key exchange")
        encoded_a_public2_length_bytes = read_exactly(s, 4)
        encoded_a_public2_length = int.from_bytes(encoded_a_public2_length_bytes, 'big')  
        encoded_a_public2 = read_exactly(s, encoded_a_public2_length) # Recive Enc PubKey
        print(bcolors.WHITE + "         [" + bcolors.YELLOW + "↓" + bcolors.WHITE + "]" + bcolors.WHITE + " Received encrypted second public key")
        a_public2_str = decode_messages(encoded_a_public2)
        print(bcolors.WHITE + "         [" + bcolors.RED + "@" + bcolors.WHITE + "]" + bcolors.WHITE + " Decrypting second public key")
        a_public2 = int(a_public2_str)
        b_private2, b_public2 = generate_dh_keys() # Gen keys
        print(bcolors.WHITE + "         [" + bcolors.GREEN + "=" + bcolors.WHITE + "]" + bcolors.WHITE + " Second public key generated")
        b_public2_str = str(b_public2)
        encoded_b_public2 = encode_message(b_public2_str) # Enc PubKey
        print(bcolors.WHITE + "         [" + bcolors.RED + "🔥" + bcolors.WHITE + "]" + bcolors.WHITE + " Encrypting second public key")
        s.sendall(len(encoded_b_public2).to_bytes(4, 'big'))
        s.sendall(encoded_b_public2) # Send Enc PubKey
        print(bcolors.WHITE + "         [" + bcolors.YELLOW + "↑" + bcolors.WHITE + "]" + bcolors.WHITE + " Sent encrypted second public key")
        shared_secret2 = pow(a_public2, b_private2, P) # Calc SS
        print(bcolors.WHITE + "         [" + bcolors.RED + "🔒" + bcolors.WHITE + "]" + bcolors.WHITE + " Second shared secret calculated")


        PASSWORD = str(shared_secret2) # Key as Passwd
        print(bcolors.WHITE + "[" + bcolors.RED + "🔒" + bcolors.WHITE + "]" + bcolors.WHITE + " Final secret key set")

        # ........................ Username Exchange ........................
        print(bcolors.GREY + "Waiting for server..." + bcolors.WHITE)
        server_username = exchange_username(s, args.username, False)
        remove_print_line()
        print("🛰 Server: " + bcolors.VIOLET + f"{server_username}" + bcolors.WHITE)
        print_lines("=")

# $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ Communication Manager $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
        receive_thread = threading.Thread(target=receive_data, args=(s, server_username), daemon=True)
        receive_thread.start()
        while not stop_event.is_set():
            try:
                with print_lock:
                    print("\n👤 > ", end="", flush=True)
                message = sys.stdin.readline().strip()
                if message.startswith("/send "): # Intercept sendFile indicator
                    file_path = message.split(" ", 1)[1]
                    send_file_in_thread(s, file_path)
                elif message:
                    print(bcolors.WHITE + "[" + bcolors.RED + "🔥" + bcolors.WHITE + "]" + bcolors.WHITE + " Encrypting message...")
                    encoded = encode_message(message)
                    remove_print_line()
                    print(bcolors.WHITE + "[" + bcolors.YELLOW + "✈" + bcolors.WHITE + "]" + bcolors.WHITE + " Sending message...")
                    s.sendall(len(encoded).to_bytes(4, 'big'))
                    s.sendall(encoded)
                    remove_print_line()
                    print(bcolors.GREY + "Message sent" + bcolors.GREEN + " ✔" + bcolors.WHITE)
            except Exception as e:
                with print_lock:
                    print(f"Error sending: {e}\n NOT DELIVERED 📩")
                stop_event.set()
                break
        receive_thread.join()
# -=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=-

# ________________________________________________________________________________________________________________________________________________________________________________
# ===================================================================================== MAIN =====================================================================================
if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler) # Manage CTRL + C
    parser = argparse.ArgumentParser(description="Secure Chat with optional Serveo tunneling")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-s', '--server', action='store_true', help="Run as server")
    group.add_argument('-c', '--client', action='store_true', help="Run as client")
    parser.add_argument('-d', '--domain', default=None, help="Serveo domain (e.g., 'stealth' for stealth.serveo.net)")
    parser.add_argument('-H', '--host', default=None, help="Host for direct connection (e.g., '0.0.0.0' or server IP)")
    parser.add_argument('-p', '--port', required=True, help="For server: local port. For client with Serveo: local_port:external_port. For client direct: port")
    parser.add_argument('-u', '--username', required=True, help="Username")
    args = parser.parse_args()

# ............................. Server .............................
    if args.server:
        if args.domain:
            # Use Serveo
            port = int(args.port)
            run_server(args.domain, port, use_serveo=True)

        else:
            # Direct connection
            if not args.host:
                args.host = '0.0.0.0'
            port = int(args.port)
            run_server(args.host, port, use_serveo=False)

# ............................. Client .............................
    elif args.client:
        if args.domain:
            # Use Serveo
            try:
                local_port_str, external_port_str = args.port.split(":")
                local_port = int(local_port_str)
                external_port = int(external_port_str)
            except ValueError:
                print("Error: For client with Serveo, -p must be in format local_port:external_port (e.g., 8081:8080)")
                sys.exit(1)
            run_client(args.domain, local_port, external_port, use_serveo=True)
        else:
            # Direct connection
            if not args.host:
                print("Error: For client in direct mode, -H host is required")
                sys.exit(1)
            try:
                port = int(args.port)
            except ValueError:
                print("Error: For client in direct mode, -p must be an integer port")
                sys.exit(1)
            run_client(args.host, port, use_serveo=False)


# ##################################################################################################################################################################################################################################
# ##################################################################################################################################################################################################################################
# ##################################################################################################################################################################################################################################
