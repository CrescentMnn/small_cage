use colored::*;
use std::io::{Read, Write, self, BufRead};
use std::net::{TcpListener, TcpStream};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce
};
use x25519_dalek::{EphemeralSecret, PublicKey};
use figlet_rs::FIGfont;

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

fn chat_set(stream: TcpStream, cipher: Aes256Gcm, address: &str) {
    let read_stream = stream.try_clone().expect("Failed to clone");
    let mut write_stream = stream;

    let my_addr = write_stream.local_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|_| "Unknown".to_string());

    let read_cipher = cipher.clone();

    let peer_addr_copy = address.to_string();
    std::thread::spawn(move || {
        let mut read_stream = read_stream;

        loop {
            match receive_encrypted(&mut read_stream, &read_cipher) {
                Ok(message) => {
                    // Their messages in red
                    println!("{}: {}", 
                        format!("[{}]", peer_addr_copy).red().bold(),
                        message.trim().red()
                    );
                }
                Err(e) => {
                    // Connection errors in yellow (warnings)
                    println!("{}", format!("Connection closed or error: {}", e).yellow());
                    break;
                }
            }
        }
    });

    let stdin = io::stdin();
    println!("{}", "Start chatting (Ctrl+C to exit):".yellow());
    println!(); 
    
    for line in stdin.lock().lines() {
        match line {
            Ok(message) => {
                println!("{}: {}", 
                    format!("[{}]", my_addr).green().bold(),
                    message.green()
                );
                if let Err(e) = send_encrypted(&mut write_stream, &cipher, &message) {
                    println!("{}", format!("Failed to send message: {}", e).yellow());
                    break;
                }
            }
            Err(e) => {
                // Input errors in yellow (warnings)
                eprintln!("{}", format!("Error reading input: {}", e).yellow());
                break;
            }
        }
    }
}

fn server_function(port: &str) -> std::io::Result<()> {
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port))?;
    println!("{}", format!("******************************Encrypted P2P Chat - Listening on port {}...*************************", port).green());
    println!("{}", "Waiting for connection...\n".green());
    println!("{}", format!("************************************************************\n\n").green());


    let (mut stream, addr) = listener.accept()?;
    println!("{}", format!("Connected to: {}\n", addr).green());

    let private_key = EphemeralSecret::random_from_rng(OsRng);
    let public_key = PublicKey::from(&private_key);

    #[cfg(debug_assertions)]
    {
        println!("{}", "Created public and private pair...".blue());
        println!("{}", format!("Public Server Key: {:x?}", public_key.as_bytes()).blue());
    }

    stream.write_all(public_key.as_bytes())?;

    let mut bob_public = [0u8; 32];
    stream.read_exact(&mut bob_public)?;
    let public_pair = PublicKey::from(bob_public);

    #[cfg(debug_assertions)]
    {
        println!("{}", "Received Public key from host...".blue());
        println!("{}", format!("Host Public Key: {:x?}\n", public_pair.as_bytes()).blue());
    }

    let shared_secret = private_key.diffie_hellman(&public_pair);

    let key = *shared_secret.as_bytes();

    #[cfg(debug_assertions)]
    {
        println!("{}", format!("AESGCM_256 KEY: [{:x?}]", key).blue());
    }

    let cipher = Aes256Gcm::new_from_slice(&key).expect("Failed to create cipher");

    chat_set(stream, cipher, &addr.to_string());
    Ok(())
}

fn client_function(address: &str) -> std::io::Result<()> {
    println!("{}", format!("*************************Encrypted P2P Chat - Connecting to {}...******************************", address).green());
    let mut stream = TcpStream::connect(address)?;
    println!("{}", "Connected!\n".green());
    println!("{}", format!("************************************************************\n\n").green());

    let peer_addr = stream.peer_addr()?;

    let private_key = EphemeralSecret::random_from_rng(OsRng);
    let public_key = PublicKey::from(&private_key);

    let mut bob_public = [0u8; 32];
    stream.read_exact(&mut bob_public)?;

    let public_pair = PublicKey::from(bob_public);

    stream.write_all(public_key.as_bytes())?;

    let shared_secret = private_key.diffie_hellman(&public_pair);

    let key = *shared_secret.as_bytes();

    let cipher = Aes256Gcm::new_from_slice(&key).expect("Failed to create cipher");
    chat_set(stream, cipher, &peer_addr.to_string());
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if let Ok(standard_font) = FIGfont::standard() {
        if let Some(logo) = standard_font.convert("PGC") {
            println!("{}", logo.to_string().green().bold());
        }
    }

    println!();

    if args.len() < 2 {
        println!("{}", "Encrypted P2P Chat Application".green().bold());
        println!("\n{}", "Usage:".green().bold());
        println!("{}", format!("Server mode: {} listen <port>", args[0]).green());
        println!("{}", format!("Client mode: {} connect <ip:port>", args[0]).green());
        println!("\n{}", "Examples:".green().bold());
        println!("{}", format!("{} listen 8080", args[0]).green());
        println!("{}", format!("{} connect 127.0.0.1:8080", args[0]).green());
        return;
    }

    match args[1].as_str() {
        "listen" => {
            let port = args.get(2).unwrap_or(&"8080".to_string()).clone();
            if let Err(e) = server_function(&port) {
                // Server errors in yellow
                eprintln!("{}", format!("Server error: {}", e).yellow());
            }
        }
        "connect" => {
            if args.len() < 3 {
                // Address requirement warning in yellow
                println!("{}", "Need address!".yellow());
                println!("{}", format!("Example: {} connect 127.0.0.1:8080", args[0]).green());
                return;
            }
            if let Err(e) = client_function(&args[2]) {
                // Connection errors in yellow
                eprintln!("{}", format!("Connection error: {}", e).yellow());
            }
        }
        _ => {
            // Unknown command in yellow (warning)
            println!("{}", format!("Unknown command: '{}'", args[1]).yellow());
            println!("{}", "Use 'listen' or 'connect'".green());
        }
    }
}
