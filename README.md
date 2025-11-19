# PGC - Pretty Good Chat

PGC is a personal project, implemented to showcase my understanding of basic cryptographic functions and types, such as AES and DHKE, these are used in the project to secure a communication channel between two users using a P2P architecture.

In order to implement this project we used popular and (so far) secure rust crates such as; `std::net` for tcp communication and sockets, `aes_gcm` for the aesgcm256 mode and `x25519_dalek` for the Diffie-Hellman Key Exchange.


## Cryptographic functions

AES-GCM is an authenticated encryption mode that provides both confidentiality and integrity. PGC uses a 256-bit key size for maximum security. Each message is encrypted with a unique 12-byte random nonce to ensure that identical messages produce different ciphertexts. The GCM mode automatically generates an authentication tag that allows the receiver to verify the message hasn't been tampered with.
The message format consists of the nonce (12 bytes), followed by the encrypted data, followed by the authentication tag embedded by GCM. The cipher is initialized with a shared secret derived from the Diffie-Hellman key exchange, ensuring both parties can encrypt and decrypt messages while keeping the encryption key secure and never transmitted over the network.

Diffie-Hellman Key Exchange allows two parties to establish a shared secret over an insecure channel without ever transmitting the secret itself. PGC uses the x25519 elliptic curve variant, which is widely regarded as secure and efficient.
The key exchange process works as follows. First, each peer generates an ephemeral private key and derives a corresponding public key. These public keys are then exchanged over the TCP connection. Note that public keys can be safely transmitted unencrypted, as the security of DHKE relies on the computational difficulty of deriving the private key from the public key. Once both parties have each other's public key, they independently compute the same shared secret by combining their own private key with the other party's public key. This shared secret becomes the AES-256 encryption key.
The use of ephemeral keys means each session generates a new key pair, providing forward secrecy. If a key is somehow compromised in the future, previous conversations remain secure because they used different keys.

## Limitations and future work

This implementation is only a foundational shell of a larger project, as this is vulnerable to man-in-the-middle attacks as there are no authentication of public keys, future implementations will provide the former.

Additional planned features include persistent chat history with encrypted storage, file transfer capabilities. The current command-line interface serves as a proof of concept for the underlying cryptographic protocols.

## Installation (dependencies) and usage

Prerequisites
-------------
Ensure you have Rust and Cargo installed on your system.
Install from: https://rustup.rs/

Building the Project
-------------------
git clone <repository-url>
cd pgc
cargo build --release

Running PGC
-----------
PGC operates in two modes: server (listener) and client (connector).

```
Server Mode (Listen for connections):
  cargo run --release -- listen <port>
  
  Example:
    cargo run --release -- listen 8080

Client Mode (Connect to server):
  cargo run --release -- connect <ip:port>
  
  Example:
    cargo run --release -- connect 127.0.0.1:8080
```

Testing Locally
---------------
Open two terminal windows:

```
Terminal 1 (Server):
  cargo run --release -- listen 8080
```
```
Terminal 2 (Client):
  cargo run --release -- connect 127.0.0.1:8080
```

Once connected, type messages in either terminal. Messages are automatically
encrypted with AES-256-GCM before transmission and decrypted on receipt.

Debug Mode
----------
Running without --release flag enables debug output showing:
  - Public keys exchanged during handshake
  - Computed shared secret (AES encryption key)

```  
Debug mode example:
  cargo run -- listen 8080
  cargo run -- connect 127.0.0.1:8080
```

WARNING: Debug output exposes cryptographic keys. Always use --release flag
for actual secure communications. Debug information is automatically disabled
in release builds.
