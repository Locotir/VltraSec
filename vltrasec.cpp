#include <iostream>      // Provides functionalities for input and output (cin, cout).
#include <string>        // Provides the string class for handling text data.
#include <vector>        // Implements the vector container for dynamic array handling.
#include <thread>        // Enables multi-threading support.
#include <mutex>         // Provides mutual exclusion primitives for thread synchronization.
#include <csignal>       // Provides functions to handle asynchronous events (signals).
#include <cstring>       // Provides functions for handling C-style strings (e.g., strcpy, strlen).
#include <sys/socket.h>  // Defines structures and functions for socket programming.
#include <sys/ioctl.h>   // Provides an interface for device-specific input/output operations.
#include <sys/types.h>   // Defines data types used in system calls.
#include <sys/wait.h>    // Provides macros and functions for process control (e.g., waitpid).
#include <arpa/inet.h>   // Contains functions for manipulating IP addresses.
#include <unistd.h>      // Provides access to the POSIX API, including system calls (e.g., fork, close).
#include <fcntl.h>       // Defines constants and functions for file control operations (e.g., O_RDONLY, open).
#include <gmp.h>         // Provides support for arbitrary-precision arithmetic (GNU Multiple Precision library).
#include <gmpxx.h>       // C++ wrapper for GMP, offering an object-oriented interface.
#include <openssl/evp.h> // Provides the EVP API for high-level cryptographic operations.
#include <openssl/sha.h> // Implements the Secure Hash Algorithm (SHA) family for hashing.
#include <openssl/bio.h> // Implements the BIO abstraction layer for handling I/O streams.
#include <openssl/rand.h>// Provides functions for generating cryptographically secure random numbers.
#include <chrono>        // Provides utilities for measuring time and duration.
#include <iomanip>       // Enables formatted I/O manipulation (e.g., setting precision for floating points).
#include <fstream>       // Allows file stream handling (reading from and writing to files).
#include <cstdint>       // Provides fixed-width integer types like int32_t, uint64_t, etc.



volatile sig_atomic_t stop_flag = 0;
std::mutex print_mutex;
int server_socket = -1, client_socket = -1;
pid_t ssh_pid = -1;
std::string PASSWORD;
std::string encryption_method = "aes"; // Default to AES-256
// ANSI color codes
const std::string PURPLE = "\033[95m";
const std::string BLUE = "\033[94m";
const std::string BLUEL = "\033[96m";
const std::string GREEN = "\033[92m";
const std::string YELLOW = "\033[93m";
const std::string RED = "\033[91m";
const std::string WHITE = "\033[37m";
const std::string ORANGE = "\33[33m";
const std::string VIOLET = "\33[35m";
const std::string GREY = "\033[90m";

// ========================================================= Key Exchange Conf =============================================================
// Diffie-Hellman parameters
// Initial configuration for 8192-bit MODP Group
const std::string P_hex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
                          "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
                          "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
                          "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
                          "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
                          "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
                          "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
                          "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
                          "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
                          "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
                          "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
                          "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
                          "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
                          "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
                          "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
                          "43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7"
                          "88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA"
                          "2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6"
                          "287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED"
                          "1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9"
                          "93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934028492"
                          "36C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BD"
                          "F8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831"
                          "179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1B"
                          "DB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF"
                          "5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6"
                          "D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F3"
                          "23A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AA"
                          "CC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE328"
                          "06A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55C"
                          "DA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE"
                          "12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E4"
                          "38777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300"
                          "741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F568"
                          "3423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD9"
                          "22222E04A4037C0713EB57A81A23F0C73473FC646CEA306B"
                          "4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A"
                          "062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A36"
                          "4597E899A0255DC164F31CC50846851DF9AB48195DED7EA1"
                          "B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F92"
                          "4009438B481C6CD7889A002ED5EE382BC9190DA6FC026E47"
                          "9558E4475677E9AA9E3050E2765694DFC81F56E880B96E71"
                          "60C980DD98EDD3DFFFFFFFFFFFFFFFFF";
mpz_class P(P_hex, 16);
mpz_class G = 2;
// =============================================================================================================================================

std::string client_username;  // Global variable to store the client username
std::string server_username;  // Global variable to store the server username

void safe_print(const std::string& msg) {
    std::lock_guard<std::mutex> lock(print_mutex);
    std::cout << msg << std::flush;  // Ensure immediate output
}

void remove_print_line() {
    std::cout << "\33[2K\r" << std::flush;
}

void print_lines(const std::string& ch) {
    struct winsize w;
    // Get the terminal size for stdout
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) == -1) {
        std::cerr << "Could not get terminal size." << std::endl;
        return;
    }
    int terminal_width = w.ws_col;
    for (int i = 0; i < terminal_width; ++i) {
        std::cout << ch;
    }
    std::cout << std::endl;
}

std::string get_timestamp() { // [hh:mm]
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << std::put_time(std::localtime(&time), "[%H:%M]");
    return oss.str();
}

uint64_t htonll(uint64_t hostlonglong) { 
    uint64_t netlonglong;
    char* ptr = reinterpret_cast<char*>(&netlonglong);
    ptr[0] = (hostlonglong >> 56) & 0xFF;
    ptr[1] = (hostlonglong >> 48) & 0xFF;
    ptr[2] = (hostlonglong >> 40) & 0xFF;
    ptr[3] = (hostlonglong >> 32) & 0xFF;
    ptr[4] = (hostlonglong >> 24) & 0xFF;
    ptr[5] = (hostlonglong >> 16) & 0xFF;
    ptr[6] = (hostlonglong >> 8) & 0xFF;
    ptr[7] = hostlonglong & 0xFF;
    return netlonglong;
}

uint64_t ntohll(uint64_t netlonglong) {
    return htonll(netlonglong);  // Symmetric operation
}


std::string encrypt_aes(const std::string& plaintext, const std::string& key_str) {
    // Create a 32-byte key (256 bits) and a 16-byte IV (Initialization Vector)
    unsigned char key[32], iv[16];
    
    // Generate a SHA-256 hash of the key_str and store it in the 'key' array
    // SHA-256 produces a 256-bit (32-byte) output.
    SHA256(reinterpret_cast<const unsigned char*>(key_str.c_str()), key_str.size(), key);
    
    // Generate a random 16-byte IV using OpenSSL's random number generator
    RAND_bytes(iv, 16);

    // Create a new cipher context for AES encryption
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    
    // Initialize the encryption operation with AES-256 in CBC mode
    // AES-256 uses a 256-bit key and CBC (Cipher Block Chaining) mode
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv);

    // Prepare a vector to store the ciphertext
    // The size of the ciphertext is at most the size of the plaintext plus the block size (16 bytes for AES)
    std::vector<unsigned char> ciphertext(plaintext.size() + 16);
    int len, ciphertext_len;

    // Encrypt the plaintext
    // 'plaintext.c_str()' is converted to a pointer to unsigned chars for encryption
    // The output ciphertext is stored in the 'ciphertext' vector
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.size());
    ciphertext_len = len;

    // Finalize the encryption, ensuring the remaining ciphertext is written
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;

    // Clean up and free the cipher context
    EVP_CIPHER_CTX_free(ctx);

    // Combine the IV (which is used for decryption) with the ciphertext
    // The IV is prepended to the ciphertext so it can be used during decryption
    std::string result(reinterpret_cast<char*>(iv), 16);
    result.append(reinterpret_cast<char*>(ciphertext.data()), ciphertext_len);
    
    // Return the encrypted data (IV + ciphertext) as a string
    return result;
}


std::string decrypt_aes(const std::string& ciphertext, const std::string& key_str) {
    // Create a 32-byte key (256 bits) for decryption
    unsigned char key[32];
    
    // Generate the SHA-256 hash of the key_str, same as during encryption
    SHA256(reinterpret_cast<const unsigned char*>(key_str.c_str()), key_str.size(), key);

    // The first 16 bytes of the ciphertext are the IV used during encryption
    const unsigned char* iv = reinterpret_cast<const unsigned char*>(ciphertext.data());
    
    // The rest of the ciphertext (after the first 16 bytes) is the encrypted data
    const unsigned char* data = iv + 16;
    
    // The length of the encrypted data is the total size of the ciphertext minus the IV size
    int data_len = ciphertext.size() - 16;

    // Create a new cipher context for AES decryption
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    
    // Initialize the decryption operation with AES-256 in CBC mode
    // The key and IV used during decryption must be the same as during encryption
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv);

    // Prepare a vector to store the decrypted plaintext
    std::vector<unsigned char> plaintext(data_len + 16);  // Adding some extra space for padding
    int len, plaintext_len;

    // Decrypt the data
    // 'data' is the encrypted data (without the IV)
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, data, data_len);
    plaintext_len = len;

    // Finalize the decryption, ensuring the remaining plaintext is written
    EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    plaintext_len += len;

    // Clean up and free the cipher context
    EVP_CIPHER_CTX_free(ctx);

    // Return the decrypted plaintext as a string
    return std::string(reinterpret_cast<char*>(plaintext.data()), plaintext_len);
}

std::string encrypt_clcrypt(const std::string& plaintext, const std::string& key_str) {
    char temp_template[] = "/tmp/vltrasec-enc-XXXXXX";
    int fd = mkstemp(temp_template);
    if (fd == -1) throw std::runtime_error("Failed to create temporary file");
    close(fd);
    std::string temp_path = temp_template;

    std::ofstream temp_file(temp_path, std::ios::binary);
    if (!temp_file) {
        std::remove(temp_path.c_str());
        throw std::runtime_error("Failed to write to temporary file");
    }
    temp_file << plaintext;
    temp_file.close();

    if (access(temp_path.c_str(), F_OK) != 0) {
        throw std::runtime_error("Temporary file does not exist: " + temp_path);
    }

    std::string command = "c-lcrypt -e " + temp_path + " -P " + key_str + " > /dev/null 2>&1";
    int status = std::system(command.c_str());
    if (status != 0) {
        std::remove(temp_path.c_str());
        throw std::runtime_error("Encryption failed with c-lcrypt");
    }

    std::ifstream encrypted_file(temp_path, std::ios::binary);
    std::string encrypted_data((std::istreambuf_iterator<char>(encrypted_file)),
                               std::istreambuf_iterator<char>());
    encrypted_file.close();
    std::remove(temp_path.c_str());
    return encrypted_data;
}

std::string decrypt_clcrypt(const std::string& ciphertext, const std::string& key_str) {
    char temp_template[] = "/tmp/vltrasec-dec-XXXXXX";
    int fd = mkstemp(temp_template);
    if (fd == -1) throw std::runtime_error("Failed to create temporary file");
    close(fd);
    std::string temp_path = temp_template;

    std::ofstream temp_file(temp_path, std::ios::binary);
    if (!temp_file) {
        std::remove(temp_path.c_str());
        throw std::runtime_error("Failed to write to temporary file");
    }
    temp_file << ciphertext;
    temp_file.close();

    if (access(temp_path.c_str(), F_OK) != 0) {
        throw std::runtime_error("Temporary file does not exist: " + temp_path);
    }

    std::string command = "c-lcrypt -d " + temp_path + " -P " + key_str + " > /dev/null 2>&1";
    int status = std::system(command.c_str());
    if (status != 0) {
        std::remove(temp_path.c_str());
        throw std::runtime_error("Decryption failed with c-lcrypt");
    }

    std::ifstream decrypted_file(temp_path, std::ios::binary);
    std::string decrypted_data((std::istreambuf_iterator<char>(decrypted_file)),
                               std::istreambuf_iterator<char>());
    decrypted_file.close();
    std::remove(temp_path.c_str());
    return decrypted_data;
}

std::string encrypt(const std::string& data, const std::string& key) {
    if (encryption_method == "aes") return encrypt_aes(data, key);
    else if (encryption_method == "clcrypt") return encrypt_clcrypt(data, key);
    throw std::runtime_error("Unknown encryption method");
}
std::string decrypt(const std::string& data, const std::string& key) {
    if (encryption_method == "aes") return decrypt_aes(data, key);
    else if (encryption_method == "clcrypt") return decrypt_clcrypt(data, key);
    throw std::runtime_error("Unknown encryption method");
}

void send_large_data(int sock, const std::string& data) { // Send large data (e.g., keys) with a length prefix
    uint32_t length = htonl(data.size());
    send(sock, &length, sizeof(length), 0);
    size_t sent = 0;
    while (sent < data.size()) {
        size_t n = send(sock, data.c_str() + sent, std::min<size_t>(16384, data.size() - sent), 0);
        if (n == -1) throw std::runtime_error("Send failed");
        sent += n;
    }
}

std::string recv_large_data(int sock) { 
    uint32_t length;
    if (recv(sock, &length, sizeof(length), 0) != sizeof(length)) throw std::runtime_error("Failed to receive length");
    length = ntohl(length);
    std::string data;
    data.reserve(length);
    while (data.size() < length) {
        char buf[16384];
        size_t n = recv(sock, buf, std::min<size_t>(sizeof(buf), length - data.size()), 0);
        if (n <= 0) throw std::runtime_error("Recv failed");
        data.append(buf, n);
    }
    return data;
}

std::pair<mpz_class, mpz_class> generate_dh_keys() { // Generate Public & Private Key
    gmp_randstate_t state;
    gmp_randinit_default(state);
    unsigned char seed[32];
    RAND_bytes(seed, sizeof(seed));
    mpz_class seed_mpz;
    mpz_import(seed_mpz.get_mpz_t(), sizeof(seed), 1, 1, 0, 0, seed);
    gmp_randseed(state, seed_mpz.get_mpz_t());
    mpz_class private_key;
    mpz_urandomm(private_key.get_mpz_t(), state, P.get_mpz_t());
    if (private_key < 2) private_key = 2;
    mpz_class public_key;
    mpz_powm(public_key.get_mpz_t(), G.get_mpz_t(), private_key.get_mpz_t(), P.get_mpz_t());
    gmp_randclear(state);
    return {private_key, public_key};
}

std::string exchange_username(int sock, const std::string& username, bool is_server) {
    std::string encoded_username = encrypt(username, PASSWORD);
    if (is_server) {
        send(sock, encoded_username.c_str(), encoded_username.size(), 0);
        char buf[1024];
        int n = recv(sock, buf, sizeof(buf), 0);
        return decrypt(std::string(buf, n), PASSWORD);
    } else {
        char buf[1024];
        int n = recv(sock, buf, sizeof(buf), 0);
        std::string other_username = decrypt(std::string(buf, n), PASSWORD);
        send(sock, encoded_username.c_str(), encoded_username.size(), 0);
        return other_username;
    }
}

void send_file(int sock, const std::string& file_path) {
    std::ifstream file(file_path, std::ios::binary);
    if (!file) {
        safe_print("Error: " + file_path + " is not a valid file.\n");
        return;
    }
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    safe_print(WHITE + "[" + RED + "🔥" + WHITE + "]" + WHITE + " Encrypting file...");
    std::string encrypted_content = encrypt(content, PASSWORD);
    std::string file_name = file_path.substr(file_path.find_last_of("/\\") + 1);
    std::string encrypted_name = encrypt(file_name, PASSWORD);
    remove_print_line();

    safe_print(WHITE + "[" + YELLOW + "✈" + WHITE + "]" + WHITE + " Sending file...");
    send(sock, "FILE", 4, 0);
    uint32_t name_len = htonl(encrypted_name.size());
    send(sock, &name_len, sizeof(name_len), 0);
    send(sock, encrypted_name.c_str(), encrypted_name.size(), 0);
    uint64_t content_len = htonll(encrypted_content.size());
    send(sock, &content_len, sizeof(content_len), 0);
    send(sock, encrypted_content.c_str(), encrypted_content.size(), 0);
    remove_print_line();
    remove_print_line();

    safe_print(WHITE + "[" + GREEN + "↑" + WHITE + "] File " + BLUEL + file_name + WHITE + " sent successfully.\n\n👤 > ");
}

std::string read_exactly(int sock, size_t n) {
    std::string data;
    data.reserve(n);
    while (data.size() < n) {
        char buf[1024];
        size_t to_recv = std::min<size_t>(sizeof(buf), n - data.size());
        ssize_t nread = recv(sock, buf, to_recv, 0);
        if (nread <= 0) throw std::runtime_error("Connection closed");
        data.append(buf, nread);
    }
    return data;
}


std::string get_username() {
    if (!client_username.empty()) return client_username;  // Client’s own username
    if (!server_username.empty()) return server_username;  // Server’s own username
    return "UnknownUser";
}

// =================================================================================== Manage Messages & Files ===================================================================================
void receive_data(int sock, const std::string& username) {
    while (!stop_flag) {
        try {
            std::string indicator = read_exactly(sock, 4);

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Manage File Sending ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
            if (indicator == "FILE") {
                uint32_t name_len;
                recv(sock, &name_len, sizeof(name_len), 0);
                name_len = ntohl(name_len);
                std::string encrypted_name = read_exactly(sock, name_len);
                std::string file_name = decrypt(encrypted_name, PASSWORD); // Read filename
                remove_print_line();
                safe_print(WHITE + "\n[" + BLUE + "?" + WHITE + "]" + YELLOW + " ✈ " + VIOLET + username + WHITE + " is sending file: " + BLUEL + file_name + WHITE);

                uint64_t content_len;
                recv(sock, &content_len, sizeof(content_len), 0);
                content_len = ntohll(content_len);
                std::string encrypted_content = read_exactly(sock, content_len);
                safe_print(WHITE + "\n[" + RED + "@" + WHITE + "]" + WHITE + " Decrypting file...");
                std::string content = decrypt(encrypted_content, PASSWORD);
                remove_print_line();
                remove_print_line();

                std::ofstream file(file_name, std::ios::binary);
                file.write(content.c_str(), content.size());
                file.close();
                remove_print_line();
                safe_print(WHITE + "\n[" + GREEN + "=" + WHITE + "] File saved: " + file_name + WHITE + "\n👤 > ");

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Manage Messages ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
            } else {
                uint32_t len = ntohl(*reinterpret_cast<const uint32_t*>(indicator.c_str()));
                std::string encrypted_message = read_exactly(sock, len);
                remove_print_line();
                std::string message = decrypt(encrypted_message, PASSWORD);
                remove_print_line();
                remove_print_line();
                safe_print(get_timestamp() + " " + YELLOW + " ✈ " + VIOLET + username + ": " +
                           GREEN + message + WHITE + "\n👤 > ");
            }
        } catch (const std::exception& e) {
            safe_print("\nError receiving data: " + std::string(e.what()) + "\n");
            stop_flag = 1;
            exit(1);
            break;
        }
    }
}
// -=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=-

// **New Function: Start gs-netcat for Server**
void start_gs_netcat_server(int port, const std::string& secret) {
    if (!secret.empty()) {
        std::string command = "gs-netcat -l -s " + secret + " -p " + std::to_string(port) + " &";
        system(command.c_str());
        sleep(1); // Wait for gs-netcat to start
    }
}

// **New Function: Start gs-netcat for Client**
void start_gs_netcat_client(int port, const std::string& secret) {
    if (!secret.empty()) {
        std::string command = "gs-netcat -s " + secret + " -p " + std::to_string(port) + " &";
        system(command.c_str());
        sleep(1); // Wait for gs-netcat to start
    }
}

// ______________________________________________________________________________________________________________________________________________________________________________________________
// ===================================================================================== SERVER SIDE MANAGE =====================================================================================
// ``````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````
void run_server(const std::string& host, int port, const std::string& gsocket_secret) {
	print_lines("=");
    // Local variable to determine the binding host
    std::string bind_host;

    // Decide the host to bind to based on gsocket_secret
    if (!gsocket_secret.empty()) {
        // Assuming you have a function to start the GSocket server
        start_gs_netcat_server(port, gsocket_secret);
        safe_print("🖧 GSocket tunnel running with secret: " + gsocket_secret + "\n");
        bind_host = "127.0.0.1"; // Bind to localhost when using GSocket
    } else {
        // Use provided host or default to "0.0.0.0" for direct connection
        bind_host = host.empty() ? "0.0.0.0" : host;
    }

    // Set up the server socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(bind_host.c_str()); // Use bind_host here

    bind(server_socket, (struct sockaddr*)&addr, sizeof(addr));
    listen(server_socket, 1);
    safe_print("📡 Listening on " + bind_host + ":" + std::to_string(port) + "\n");

    // Rest of your server code (accepting connections, key exchange, etc.)
    int conn = accept(server_socket, nullptr, nullptr);
    safe_print("🟢 Connected\n");

// @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ First Round Key Exchange @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    safe_print(WHITE + "[" + YELLOW + "%" + WHITE + "]" + WHITE + " Sarting Diffie-Hellman key exchange");
    auto [a_private, a_public] = generate_dh_keys();
    safe_print(WHITE + "\n         [" + GREEN + "=" + WHITE + "]" + WHITE + " Keys generated");
    send_large_data(conn, a_public.get_str());
    safe_print(WHITE + "\n         [" + YELLOW + "↑" + WHITE + "]" + WHITE + " Sent public key");
    mpz_class b_public(recv_large_data(conn));
    safe_print(WHITE + "\n         [" + YELLOW + "↓" + WHITE + "]" + WHITE + " Recived public key");
    mpz_class shared_secret;
    mpz_powm(shared_secret.get_mpz_t(), b_public.get_mpz_t(), a_private.get_mpz_t(), P.get_mpz_t());
    safe_print(WHITE + "\n         [" + RED + "🔒" + WHITE + "]" + WHITE + " First shared secret calculated\n");
    PASSWORD = shared_secret.get_str();

    print_lines("-");
// @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ Second Round Key Exchange @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    safe_print(WHITE + "[" + YELLOW + "%" + WHITE + "]" + WHITE + " Sarting second Diffie-Hellman key exchange");
    auto [a_private2, a_public2] = generate_dh_keys();
    safe_print(WHITE + "\n         [" + GREEN + "=" + WHITE + "]" + WHITE + " Keys generated");
    std::string encoded_a_public2 = encrypt(a_public2.get_str(), PASSWORD);
    safe_print(WHITE + "\n         [" + RED + "🔥" + WHITE + "]" + WHITE + " Encrypted public key");
    uint32_t len = htonl(encoded_a_public2.size());
    send(conn, &len, sizeof(len), 0);
    send(conn, encoded_a_public2.c_str(), encoded_a_public2.size(), 0);
    safe_print(WHITE + "\n         [" + YELLOW + "↑" + WHITE + "]" + WHITE + " Sent encrypted public key");
    std::string len_str = read_exactly(conn, 4);
    if (len_str.size() != 4) throw std::runtime_error("Failed to read length");
    memcpy(&len, len_str.data(), 4);
    len = ntohl(len);
    std::string encoded_b_public2 = read_exactly(conn, len);
    safe_print(WHITE + "\n         [" + YELLOW + "↓" + WHITE + "]" + WHITE + " Recived encrypted public key");
    mpz_class b_public2(decrypt(encoded_b_public2, PASSWORD));
    safe_print(WHITE + "\n         [" + RED + "@" + WHITE + "]" + WHITE + " Decrypted public key");
    mpz_class shared_secret2;
    mpz_powm(shared_secret2.get_mpz_t(), b_public2.get_mpz_t(), a_private2.get_mpz_t(), P.get_mpz_t());
    safe_print(WHITE + "\n         [" + RED + "🔒" + WHITE + "]" + WHITE + " Second shared secret calculated");
    PASSWORD = shared_secret2.get_str();
    safe_print(WHITE + "\n[" + GREEN + "+" + WHITE + "]" + WHITE + " Using second shared key as passwd");

    // ........................ Username Exchange ........................
    safe_print(GREY + "\nWaiting for client");
    std::string client_username = exchange_username(conn, server_username, true);
    remove_print_line();
    safe_print(WHITE + "🔗 Client: " + VIOLET + client_username + WHITE + "\n");
    print_lines("=");

// $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ Communication Manager $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
    std::thread receive_thread(receive_data, conn, client_username);
    receive_thread.detach();

    while (!stop_flag) {
        safe_print("\n👤 > ");
        std::string message;
        std::getline(std::cin, message);
        if (message.substr(0, 6) == "/send ") {
            std::thread(send_file, conn, message.substr(6)).detach();
        } else if (!message.empty()) {
            std::string encoded = encrypt(message, PASSWORD);
            uint32_t len = htonl(encoded.size());
            send(conn, &len, sizeof(len), 0);
            send(conn, encoded.c_str(), encoded.size(), 0);
            safe_print(GREY + "Message sent" + GREEN + " ✔" + WHITE);
        }
    }
    close(conn);
}
// -=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=-

// ______________________________________________________________________________________________________________________________________________________________________________________________
// ===================================================================================== CLIENT SIDE MANAGE =====================================================================================
// ``````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````
void run_client(const std::string& host, int port, const std::string& gsocket_secret) {
	print_lines("=");
    std::string connect_host;
    if (!gsocket_secret.empty()) {
        start_gs_netcat_client(port, gsocket_secret);
        safe_print("🖧 Connecting via GSocket with secret: " + gsocket_secret + "\n");
        connect_host = "127.0.0.1";
    } else {
        connect_host = host;
    }
    client_socket = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(connect_host.c_str());
    
    for (int attempt = 0; attempt < 10 && !stop_flag; ++attempt) {
        if (connect(client_socket, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            safe_print("🟢 Connected to " + host + ":" + std::to_string(port) + "\n");
            sleep(1);
            break;
        }
        safe_print("❌ Connection refused, waiting... (attempt " + std::to_string(attempt + 1) + "/10)\n");
        sleep(1);
    }

// @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ First Round Key Exchange @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    safe_print(WHITE + "[" + YELLOW + "%" + WHITE + "]" + WHITE + " Sarting Diffie-Hellman key exchange");
    mpz_class a_public(recv_large_data(client_socket));
    safe_print(WHITE + "\n         [" + YELLOW + "↓" + WHITE + "]" + WHITE + " Recived public key");
    auto [b_private, b_public] = generate_dh_keys();
    safe_print(WHITE + "\n         [" + GREEN + "=" + WHITE + "]" + WHITE + " Keys generated");
    send_large_data(client_socket, b_public.get_str());
    safe_print(WHITE + "\n         [" + YELLOW + "↑" + WHITE + "]" + WHITE + " Sent public key");
    mpz_class shared_secret;
    mpz_powm(shared_secret.get_mpz_t(), a_public.get_mpz_t(), b_private.get_mpz_t(), P.get_mpz_t());
    safe_print(WHITE + "\n         [" + RED + "🔒" + WHITE + "]" + WHITE + " First shared secret calculated\n");
    PASSWORD = shared_secret.get_str();

    print_lines("-");
// @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ Second Round Key Exchange @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    safe_print(WHITE + "[" + YELLOW + "%" + WHITE + "]" + WHITE + " Sarting second Diffie-Hellman key exchange");
    std::string len_str = read_exactly(client_socket, 4);
    if (len_str.size() != 4) throw std::runtime_error("Failed to read length");
    int32_t len;
    memcpy(&len, len_str.data(), 4);
    len = ntohl(len);
    std::string encoded_a_public2 = read_exactly(client_socket, len);
    safe_print(WHITE + "\n         [" + YELLOW + "↓" + WHITE + "]" + WHITE + " Recived encrypted public key");
    mpz_class a_public2(decrypt(encoded_a_public2, PASSWORD));
    safe_print(WHITE + "\n         [" + RED + "@" + WHITE + "]" + WHITE + " Decrypted public key");
    auto [b_private2, b_public2] = generate_dh_keys();
    safe_print(WHITE + "\n         [" + GREEN + "=" + WHITE + "]" + WHITE + " Keys generated");
    std::string encoded_b_public2 = encrypt(b_public2.get_str(), PASSWORD);
    safe_print(WHITE + "\n         [" + RED + "🔥" + WHITE + "]" + WHITE + " Encrypted public key");
    len = htonl(encoded_b_public2.size());
    send(client_socket, &len, sizeof(len), 0);
    send(client_socket, encoded_b_public2.c_str(), encoded_b_public2.size(), 0);
    safe_print(WHITE + "\n         [" + YELLOW + "↑" + WHITE + "]" + WHITE + " Sent encrypted public key");
    mpz_class shared_secret2;
    mpz_powm(shared_secret2.get_mpz_t(), a_public2.get_mpz_t(), b_private2.get_mpz_t(), P.get_mpz_t());
    safe_print(WHITE + "\n         [" + RED + "🔒" + WHITE + "]" + WHITE + " Second shared secret calculated");
    PASSWORD = shared_secret2.get_str();
    safe_print(WHITE + "\n[" + GREEN + "+" + WHITE + "]" + WHITE + " Using second shared key as passwd");


    // ........................ Username Exchange ........................
    safe_print(GREY + "\nWaiting for server");
    std::string server_username = exchange_username(client_socket, client_username, false);
    remove_print_line();
    safe_print(WHITE + "🛰 Server: " + VIOLET + server_username + WHITE + "\n");
    print_lines("=");

// $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ Communication Manager $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
    std::thread receive_thread(receive_data, client_socket, server_username);
    receive_thread.detach();

    while (!stop_flag) {
        safe_print("\n👤 > ");
        std::string message;
        std::getline(std::cin, message);
        if (message.substr(0, 6) == "/send ") {
            std::thread(send_file, client_socket, message.substr(6)).detach();
        } else if (!message.empty()) {
            std::string encoded = encrypt(message, PASSWORD);
            uint32_t len = htonl(encoded.size());
            send(client_socket, &len, sizeof(len), 0);
            send(client_socket, encoded.c_str(), encoded.size(), 0);
            safe_print(GREY + "\nMessage sent" + GREEN + " ✔" + WHITE);
        }
    }
    close(client_socket);
}
// -=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=--=-=-

void signal_handler(int sig) {
    stop_flag = 1;
    if (server_socket != -1) close(server_socket);
    if (client_socket != -1) close(client_socket);
    system("pkill gs-netcat"); // Clean up gs-netcat processes
    safe_print("\nInterrupt received. Closing...\n");
    exit(0);
}

int main(int argc, char* argv[]) {
    signal(SIGINT, signal_handler);

    // Define the help menu
    const std::string help_menu = R"(
vltrasec - Secure Communication Tool

**Usage:**

  To run as server:
    vltrasec -s [-H host] -p port -u username [-k key] -X encryption

  To run as client:
    vltrasec -c [-H host] -p port -u username [-k key] -X encryption

**Options:**

  - `-s, --server`        Run in server mode.
  - `-c, --client`        Run in client mode.
  - `-H, --host`          Specify the host address.
                          - For server: Address to bind to. With `-k`, binds to localhost; otherwise, to specified host or default "0.0.0.0".
                          - For client: Server's address. Required if `-k` is not provided; with `-k`, connects to localhost via gsocket.
  - `-p, --port`          Specify the port number (required).
  - `-u, --username`      Set the username (required).
  - `-k, --key`           Set the secret for gsocket tunneling (optional).
  - `-X`                  Specify the encryption method: `aes` or `clcrypt` (required).
  - `-h, --help`          Display this help menu.

**Description:**

  vltrasec is a secure communication tool that enables encrypted messaging and file transfer between a server and a client. It uses Diffie-Hellman key exchange for secure key agreement and supports two encryption methods: AES-256 (via `aes`) and c-lcrypt (via `clcrypt`).

  When using gsocket tunneling (with `-k`), the connection is established via gsocket, and the host address is automatically set to localhost. Without `-k`, the program uses a direct connection, requiring a host address for the client.

  To send a file, use the `/send /path/to/file` command in the chat interface after establishing a connection.

**Examples:**

  1. **Direct Connection:**
     - Server: `vltrasec -s -H 0.0.0.0 -p 8080 -u Alice -X aes`
     - Client: `vltrasec -c -H 192.168.1.100 -p 8080 -u Bob -X aes`

  2. **GSocket Tunneling:**
     - Server: `vltrasec -s -p 8080 -u Alice -k mysecret -X clcrypt`
     - Client: `vltrasec -c -p 8080 -u Bob -k mysecret -X clcrypt`

**Commands:**

  - `/send /path/to/file` : Send a file to the connected peer.
)";

    // Check for -h or --help
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "-h" || std::string(argv[i]) == "--help") {
            std::cout << help_menu << std::endl;
            return 0;
        }
    }
    
    bool is_server = false, is_client = false;
    std::string host, port_str, username, gsocket_secret;
    for (int i = 1; i < argc; i += 2) {
        std::string arg = argv[i];
        if (i + 1 >= argc) break;
        if (arg == "-s" || arg == "--server") { is_server = true; i--; }
        else if (arg == "-c" || arg == "--client") { is_client = true; i--; }
        else if (arg == "-H" || arg == "--host") host = argv[i + 1];
        else if (arg == "-p" || arg == "--port") port_str = argv[i + 1];
        else if (arg == "-u" || arg == "--username") username = argv[i + 1];
        else if (arg == "-k" || arg == "--key") gsocket_secret = argv[i + 1];
        else if (arg == "-X") encryption_method = argv[i + 1];
    }

    if (!is_server && !is_client) {
        std::cerr << "Must specify --server or --client\n";
        return 1;
    }
    if (port_str.empty() || username.empty()) {
        std::cerr << "Must specify --port and --username\n";
        return 1;
    }
    if (encryption_method != "aes" && encryption_method != "clcrypt") {
        std::cerr << "Invalid encryption method. Use 'aes' or 'clcrypt' with --encryption\n";
        return 1;
    }

    if (is_server) {
        server_username = username;
        int port = std::stoi(port_str);
        run_server(host, port, gsocket_secret);
    } else {
        client_username = username;
        if (host.empty() && gsocket_secret.empty()) {
            std::cerr << "For client, must specify either -H host (direct) or -k key (GSocket)\n";
            return 1;
        }
        int port = std::stoi(port_str);
        run_client(host, port, gsocket_secret);
    }

    return 0;
}
