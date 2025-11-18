use std::io::{Read, Write, self, BufRead};
use std::net::{TcpListener, TcpStream};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce
};
use x25519_dalek::{EphemeralSecret, PublicKey};

// Shared secret key (32 bytes for AES-256)
/*const SHARED_KEY: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];*/

fn encrypt_message(cipher: &Aes256Gcm, plaintext: &str) -> Result<Vec<u8>, String> {
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    
    // Encrypt the message
    let ciphertext = cipher.encrypt(&nonce, plaintext.as_bytes())
        .map_err(|e| format!("Encryption failed: {:?}", e))?;
    
    let mut result = Vec::new();
    result.extend_from_slice(&nonce);       
    result.extend_from_slice(&ciphertext);
    
    Ok(result)
}

fn decrypt_message(cipher: &Aes256Gcm, data: &[u8]) -> Result<String, String> {
    if data.len() < 12 {
        return Err("Data too short".to_string());
    }
    
    let nonce = Nonce::from_slice(&data[0..12]);
    
    let ciphertext = &data[12..];
    
    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|e| format!("Decryption failed: {:?}", e))?;
    
    String::from_utf8(plaintext)
        .map_err(|e| format!("Invalid UTF-8: {}", e))
}

fn send_encrypted(stream: &mut TcpStream, cipher: &Aes256Gcm, message: &str) -> std::io::Result<()> {
    let encrypted = encrypt_message(cipher, message)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    
    let length = encrypted.len() as u32;
    stream.write_all(&length.to_be_bytes())?;
    
    stream.write_all(&encrypted)?;
    stream.flush()?;
    
    Ok(())
}

fn receive_encrypted(stream: &mut TcpStream, cipher: &Aes256Gcm) -> std::io::Result<String> {
    let mut length_bytes = [0u8; 4];
    stream.read_exact(&mut length_bytes)?;
    let length = u32::from_be_bytes(length_bytes) as usize;
    
    let mut encrypted = vec![0u8; length];
    stream.read_exact(&mut encrypted)?;
    
    decrypt_message(cipher, &encrypted)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
}

fn chat_set(stream: TcpStream, cipher: Aes256Gcm) {
    let read_stream = stream.try_clone().expect("Failed to clone");
    let mut write_stream = stream;

    let read_cipher = cipher.clone();
    std::thread::spawn(move || {
        let mut read_stream = read_stream;

        loop {
            match receive_encrypted(&mut read_stream, &read_cipher) {
                Ok(message) => {
                    println!("Them: {}", message.trim());
                }
                Err(e) => {
                    println!("Connection closed or error: {}", e);
                    break;
                }
            }
        }
    });

    let stdin = io::stdin();
    println!("Start chatting (Ctrl+C to exit):\n");

    for line in stdin.lock().lines() {
        match line {
            Ok(message) => {
                if let Err(e) = send_encrypted(&mut write_stream, &cipher, &message) {
                    println!("Failed to send message: {}", e);
                    break;
                }
            }
            Err(e) => {
                eprintln!("Error reading input: {}", e);
                break;
            }
        }
    }
}

fn server_function(port: &str) -> std::io::Result<()> {
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port))?;
    println!("Encrypted P2P Chat - Listening on port {}...", port);
    println!("Waiting for connection...\n");

    let (mut stream, addr) = listener.accept()?;
    println!("Connected to: {}\n", addr);

    let private_key = EphemeralSecret::random_from_rng(OsRng);
    let public_key = PublicKey::from(&private_key);
    
    #[cfg(debug_assertions)]
    {
        println!("Created public and private pair...");
        println!("Public Server Key: {:x?}", public_key.as_bytes());
    }

    stream.write_all(public_key.as_bytes())?;

    let mut bob_public = [0u8; 32];
    stream.read_exact(&mut bob_public)?;
    let public_pair = PublicKey::from(bob_public);

    #[cfg(debug_assertions)]
    {
        println!("Recieved Public key from host...");
        println!("Host Public Key: {:x?}\n", public_pair.as_bytes());
    }

    let shared_secret = private_key.diffie_hellman(&public_pair);

    let key = *shared_secret.as_bytes();

    let cipher = Aes256Gcm::new_from_slice(&key).expect("Failed to create cipher");

    chat_set(stream, cipher);
    Ok(())
}

fn client_function(address: &str) -> std::io::Result<()> {
    println!("Encrypted P2P Chat - Connecting to {}...", address);
    let mut stream = TcpStream::connect(address)?;
    println!("Connected!\n");
    
    let private_key = EphemeralSecret::random_from_rng(OsRng);
    let public_key = PublicKey::from(&private_key);

    let mut bob_public = [0u8; 32];
    stream.read_exact(&mut bob_public)?;

    let public_pair = PublicKey::from(bob_public);

    stream.write_all(public_key.as_bytes())?;

    let shared_secret = private_key.diffie_hellman(&public_pair);

    let key = *shared_secret.as_bytes();

    let cipher = Aes256Gcm::new_from_slice(&key).expect("Failed to create cipher");
    chat_set(stream, cipher);
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        println!("Encrypted P2P Chat Application");
        println!("\nUsage:");
        println!("  Server mode: {} listen <port>", args[0]);
        println!("  Client mode: {} connect <ip:port>", args[0]);
        println!("\nExamples:");
        println!("  {} listen 8080", args[0]);
        println!("  {} connect 127.0.0.1:8080", args[0]);
        return;
    }

    match args[1].as_str() {
        "listen" => {
            let port = args.get(2).unwrap_or(&"8080".to_string()).clone();
            if let Err(e) = server_function(&port) {
                eprintln!("Server error: {}", e);
            }
        }
        "connect" => {
            if args.len() < 3 {
                println!("Need address!");
                println!("Example: {} connect 127.0.0.1:8080", args[0]);
                return;
            }
            if let Err(e) = client_function(&args[2]) {
                eprintln!("Connection error: {}", e);
            }
        }
        _ => {
            println!("Unknown command: '{}'", args[1]);
            println!("Use 'listen' or 'connect'");
        }
    }
}
