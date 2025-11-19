
use colored::*;
use dialoguer::{theme::ColorfulTheme, Input, Select};
use figlet_rs::FIGfont;

use std::io::{self, BufRead, Read, Write};
use std::net::{TcpListener, TcpStream};

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use x25519_dalek::{EphemeralSecret, PublicKey};

// ---------------------------------------------------------
// ENCRYPTION HELPERS
// ---------------------------------------------------------
fn clear_screen() {
    // Works on Windows, macOS, Linux
    if cfg!(target_os = "windows") {
        std::process::Command::new("cmd")
            .args(&["/C", "cls"])
            .status()
            .unwrap();
    } else {
        std::process::Command::new("clear")
            .status()
            .unwrap();
    }
}

fn encrypt_message(cipher: &Aes256Gcm, plaintext: &str) -> Result<Vec<u8>, String> {
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_bytes())
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

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("Decryption failed: {:?}", e))?;

    String::from_utf8(plaintext).map_err(|e| format!("Invalid UTF-8: {}", e))
}

fn send_encrypted(
    stream: &mut TcpStream,
    cipher: &Aes256Gcm,
    message: &str,
) -> std::io::Result<()> {
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

// ---------------------------------------------------------
// CHAT LOOP
// ---------------------------------------------------------

fn chat_set(stream: TcpStream, cipher: Aes256Gcm, address: &str) {
    let read_stream = stream.try_clone().expect("Failed to clone");
    let mut write_stream = stream;

    let my_addr = write_stream
        .local_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|_| "Unknown".to_string());

    let read_cipher = cipher.clone();
    let peer_addr_copy = address.to_string();

    std::thread::spawn(move || {
        let mut read_stream = read_stream;

        loop {
            match receive_encrypted(&mut read_stream, &read_cipher) {
                Ok(message) => {
                    println!(
                        "{} {}",
                        format!("[{}]", peer_addr_copy).red().bold(),
                        message.trim().red()
                    );
                }
                Err(e) => {
                    println!("{}", format!("Connection closed: {}", e).yellow());
                    break;
                }
            }
        }
    });

    println!("{}", "\nStart chatting (Ctrl+C to exit):\n".bright_yellow());

    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        match line {
            Ok(message) => {
                println!(
                    "{} {}",
                    format!("[{}]", my_addr).green().bold(),
                    message.green()
                );
                if let Err(e) = send_encrypted(&mut write_stream, &cipher, &message) {
                    println!("{}", format!("Failed to send: {}", e).yellow());
                    break;
                }
            }
            Err(e) => {
                eprintln!("Input error: {}", e);
                break;
            }
        }
    }
}

// ---------------------------------------------------------
// SERVER
// ---------------------------------------------------------

fn server_function(port: &str) -> std::io::Result<()> {
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port))?;
    println!(
        "{}",
        format!("Listening on port {} …", port)
            .bright_green()
            .bold()
    );

    let (mut stream, addr) = listener.accept()?;
    println!("{}", format!("Connected to: {}", addr).green());

    let private_key = EphemeralSecret::random_from_rng(OsRng);
    let public_key = PublicKey::from(&private_key);

    stream.write_all(public_key.as_bytes())?;

    let mut bob_public = [0u8; 32];
    stream.read_exact(&mut bob_public)?;
    let public_pair = PublicKey::from(bob_public);

    let shared_secret = private_key.diffie_hellman(&public_pair);
    let key = *shared_secret.as_bytes();

    let cipher = Aes256Gcm::new_from_slice(&key).expect("cipher failure");

    chat_set(stream, cipher, &addr.to_string());
    Ok(())
}

// ---------------------------------------------------------
// CLIENT
// ---------------------------------------------------------

fn client_function(address: &str) -> std::io::Result<()> {
    println!("{}", format!("Connecting to {}…", address).green());
    let mut stream = TcpStream::connect(address)?;
    println!("{}", "Connected!\n".green());

    let peer_addr = stream.peer_addr()?;

    let private_key = EphemeralSecret::random_from_rng(OsRng);
    let public_key = PublicKey::from(&private_key);

    let mut bob_public = [0u8; 32];
    stream.read_exact(&mut bob_public)?;

    let public_pair = PublicKey::from(bob_public);
    stream.write_all(public_key.as_bytes())?;

    let shared_secret = private_key.diffie_hellman(&public_pair);
    let key = *shared_secret.as_bytes();
    let cipher = Aes256Gcm::new_from_slice(&key).expect("cipher failure");

    chat_set(stream, cipher, &peer_addr.to_string());
    Ok(())
}

// ---------------------------------------------------------
// MODERN CLI
// ---------------------------------------------------------

fn main() {
    clear_screen();
    // Banner
    if let Ok(font) = FIGfont::standard() {
        if let Some(fig) = font.convert("PGC CHAT") {
            println!("{}", fig.to_string().bright_green().bold());
        }
    }

    println!("{}", "Secure Peer-to-Peer Chat".bright_green().bold());
    println!("{}", "══════════════════════════════════════".green());

    // Menu
    let options = vec![
        "🌐  Start server (listen mode)",
        "🔗  Connect to peer (client mode)",
        "❌  Exit",
    ];

    let choice = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Choose an option")
        .items(&options)
        .default(0)
        .interact()
        .unwrap();

    match choice {
        0 => {

            let port: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Enter port to listen on")
                .default("8080".to_string())
                .interact_text()
                .unwrap();
            clear_screen();

            if let Err(e) = server_function(&port) {
                eprintln!("{}", format!("Server error: {}", e).red());
            }
        }

        1 => {
            let addr: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Enter peer address (ip:port)")
                .default("127.0.0.1:8080".to_string())
                .interact_text()
                .unwrap();

            if let Err(e) = client_function(&addr) {
                eprintln!("{}", format!("Connection error: {}", e).red());
            }
        }

        _ => {
            println!("{}", "\nGoodbye!\n".bright_green().bold());
        }
    }
}

