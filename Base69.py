import base64
import os
import tkinter as tk
from tkinter import filedialog, messagebox
from colorama import Fore, Style, init
import pyperclip
import glob
import time
from tqdm import tqdm
import hmac
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import secrets
import getpass
import json
import logging
import sys
from datetime import datetime

# Initialize logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f"base69_{datetime.now().strftime('%Y%m%d')}.log"),
        logging.StreamHandler()
    ]
)

# Initialize colorama
init(autoreset=True)
os.system("title Base69 v3.5 Pro - AES-256 + HMAC Enhanced")

BANNER = f"""{Fore.CYAN}
██████╗  █████╗ ███████╗███████╗     ██████╗ █████╗ 
██╔══██╗██╔══██╗██╔════╝██╔════╝    ██╔════╝██╔══██╗
██████╔╝███████║███████╗█████╗      ███████╗╚██████║
██╔══██╗██╔══██║╚════██║██╔══╝      ██╔═══██╗╚═══██║
██████╔╝██║  ██║███████║███████╗    ╚██████╔╝█████╔╝
╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝     ╚═════╝ ╚════╝ 
{Fore.LIGHTYELLOW_EX}►► Hybrid Encoding V3.5 (AES-256 + Vigenère + HMAC) ◄◄
{Fore.LIGHTBLACK_EX}Version 3.5 Pro | by: https://github.com/MrR0nak
{Style.RESET_ALL}"""

SEPARATOR = f"{Fore.LIGHTBLACK_EX}{'-' * 60}"


class EncodingError(Exception):
    """Custom exception for encoding errors"""
    pass


class DecodingError(Exception):
    """Custom exception for decoding errors"""
    pass


class AuthenticationError(Exception):
    """Custom exception for HMAC authentication errors"""
    pass


def apply_rot13(text: str) -> str:
    """Apply ROT13 substitution cipher to the text"""
    return text.translate(str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
    ))


def vigenere_cipher(text: str, key: str, mode: str) -> str:
    """
    Apply Vigenère cipher to text

    Args:
        text: The text to encrypt/decrypt
        key: The Vigenère key
        mode: 'encode' or 'decode'

    Returns:
        The processed text
    """
    if not key:
        raise ValueError("Vigenère key cannot be empty")

    result = []
    key = key.upper().replace(" ", "")
    if not key:
        raise ValueError("Vigenère key cannot consist of only spaces")

    extended_key = (key * (len(text) // len(key) + 1))[:len(text)]

    for i, char in enumerate(text):
        if char.isalpha():
            offset = ord('A') if char.isupper() else ord('a')
            shift = ord(extended_key[i]) - ord('A')
            if mode == 'decode':
                shift = -shift
            new_char = chr((ord(char) - offset + shift) % 26 + offset)
            result.append(new_char)
        else:
            result.append(char)
    return ''.join(result)


def advanced_encoding(text: str, xor_key: str) -> str:
    """
    Perform advanced encoding including Base64, ROT13, and XOR operations

    Args:
        text: Text to encode
        xor_key: Key for XOR operation

    Returns:
        Encoded text
    """
    try:
        if not xor_key:
            raise ValueError("XOR key cannot be empty")

        # Step 1: Base64 encoding
        step1 = base64.b64encode(text.encode()).decode()

        # Step 2: Apply ROT13
        step2 = apply_rot13(step1)

        # Step 3: Convert to binary
        step3 = ''.join(format(ord(c), '08b') for c in step2)

        # Step 4: XOR operation
        xor_bits = [str(int(bit) ^ (ord(xor_key[i % len(xor_key)]) % 2)) for i, bit in enumerate(step3)]

        # Step 5: Convert binary to bytes and then to Base64
        bytes_final = bytes(int(''.join(xor_bits[i:i + 8]), 2) for i in range(0, len(xor_bits), 8))
        return base64.b64encode(bytes_final).decode()
    except Exception as e:
        raise EncodingError(f"Advanced encoding failed: {str(e)}")


def advanced_decoding(encoded_text: str, xor_key: str) -> str:
    """
    Perform advanced decoding (reverse of advanced_encoding)

    Args:
        encoded_text: Text to decode
        xor_key: Key for XOR operation

    Returns:
        Decoded text
    """
    try:
        if not xor_key:
            raise ValueError("XOR key cannot be empty")

        # Step 1: Base64 decode
        initial_bytes = base64.b64decode(encoded_text)

        # Step 2: Convert to binary
        binary = ''.join(format(byte, '08b') for byte in initial_bytes)

        # Step 3: Reverse XOR
        xor_reversed = [str(int(bit) ^ (ord(xor_key[i % len(xor_key)]) % 2)) for i, bit in enumerate(binary)]
        binary_reversed = ''.join(xor_reversed)

        # Step 4: Convert binary to text
        rot13_text = ''.join(chr(int(binary_reversed[i:i + 8], 2)) for i in range(0, len(binary_reversed), 8))

        # Step 5: Reverse ROT13
        base64_text = apply_rot13(rot13_text)

        # Step 6: Base64 decode
        return base64.b64decode(base64_text).decode()
    except Exception as e:
        raise DecodingError(f"Advanced decoding failed: {str(e)}")


def generate_hmac(data: str, hmac_key: str) -> str:
    """
    Generate HMAC-SHA256 for data authentication

    Args:
        data: Data to authenticate
        hmac_key: HMAC key

    Returns:
        Base64-encoded HMAC
    """
    try:
        if not hmac_key:
            raise ValueError("HMAC key cannot be empty")

        hmac_obj = hmac.new(
            hmac_key.encode(),
            data.encode(),
            hashlib.sha256
        )
        return base64.b64encode(hmac_obj.digest()).decode()
    except Exception as e:
        raise ValueError(f"HMAC generation failed: {str(e)}")


def verify_hmac(data: str, hmac_key: str, received_hmac: str) -> bool:
    """
    Verify if received HMAC matches computed HMAC

    Args:
        data: Data to verify
        hmac_key: HMAC key
        received_hmac: HMAC to verify against

    Returns:
        True if HMAC is valid, False otherwise
    """
    try:
        computed_hmac = generate_hmac(data, hmac_key)
        return hmac.compare_digest(computed_hmac, received_hmac)
    except Exception as e:
        logging.error(f"HMAC verification failed: {str(e)}")
        return False


def derive_aes_key(password: str, salt: bytes = None) -> tuple:
    """
    Derive AES-256 key from password using PBKDF2

    Args:
        password: Master password
        salt: Salt for key derivation (generated if None)

    Returns:
        (key, salt) tuple
    """
    try:
        if not password:
            raise ValueError("Password cannot be empty")

        if salt is None:
            salt = get_random_bytes(16)  # 16-byte random salt

        # Derive key using PBKDF2 (100,000 iterations)
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=32)  # AES-256 (32 bytes)

        return key, salt
    except Exception as e:
        raise ValueError(f"Key derivation failed: {str(e)}")


def encrypt_aes(data: str, aes_key: bytes) -> tuple:
    """
    Encrypt data using AES-256 in GCM mode

    Args:
        data: Data to encrypt
        aes_key: AES key (32 bytes)

    Returns:
        (nonce, tag, ciphertext) tuple
    """
    try:
        nonce = get_random_bytes(12)  # 12-byte random nonce for GCM
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(data.encode())

        return nonce, tag, ciphertext
    except Exception as e:
        raise EncodingError(f"AES encryption failed: {str(e)}")


def decrypt_aes(nonce: bytes, tag: bytes, ciphertext: bytes, aes_key: bytes) -> str:
    """
    Decrypt data using AES-256 in GCM mode

    Args:
        nonce: Nonce used for encryption
        tag: Authentication tag
        ciphertext: Encrypted data
        aes_key: AES key (32 bytes)

    Returns:
        Decrypted data
    """
    try:
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        data = cipher.decrypt_and_verify(ciphertext, tag)

        return data.decode()
    except ValueError as e:
        raise DecodingError(f"AES authentication failed: {str(e)}")
    except Exception as e:
        raise DecodingError(f"AES decryption failed: {str(e)}")


def hybrid_encoding_v35(text: str, vigenere_key: str, xor_key: str, hmac_key: str, aes_key: str) -> str:
    """
    Version 3.5 hybrid encoding with AES-256 and HMAC

    Args:
        text: Text to encode
        vigenere_key: Key for Vigenère cipher
        xor_key: XOR key for advanced encoding
        hmac_key: Key for HMAC authentication
        aes_key: Master password for AES encryption

    Returns:
        Encoded text with HMAC
    """
    try:
        # Phase 1: Apply Vigenère cipher
        vigenere_text = vigenere_cipher(text, vigenere_key, 'encode')

        # Phase 2: Derive AES key from password
        aes_key_bytes, salt = derive_aes_key(aes_key)

        # Phase 3: Encrypt with AES-256 GCM
        nonce, tag, ciphertext = encrypt_aes(vigenere_text, aes_key_bytes)

        # Phase 4: Combine elements for transport
        elements = {
            "v": "3.5",  # Version identifier
            "s": base64.b64encode(salt).decode(),  # salt for key derivation
            "n": base64.b64encode(nonce).decode(),  # nonce for AES
            "t": base64.b64encode(tag).decode(),  # authentication tag
            "c": base64.b64encode(ciphertext).decode()  # encrypted content
        }

        # Encode elements to JSON string and apply advanced encoding
        elements_json = json.dumps(elements)
        advanced_text = advanced_encoding(elements_json, xor_key)

        # Generate HMAC for authentication and integrity verification
        hmac_value = generate_hmac(advanced_text, hmac_key)

        # Final format: encoded_text.hmac
        return f"{advanced_text}.{hmac_value}"
    except Exception as e:
        raise EncodingError(f"Hybrid encoding failed: {str(e)}")


def hybrid_decoding_v35(encoded_text: str, vigenere_key: str, xor_key: str, hmac_key: str, aes_key: str) -> str:
    """
    Version 3.5 hybrid decoding with AES-256 and HMAC verification

    Args:
        encoded_text: Text to decode
        vigenere_key: Key for Vigenère cipher
        xor_key: XOR key for advanced decoding
        hmac_key: Key for HMAC verification
        aes_key: Master password for AES decryption

    Returns:
        Decoded text
    """
    try:
        # Split encoded text from HMAC
        parts = encoded_text.split('.')
        if len(parts) != 2:
            raise ValueError("Invalid format: HMAC not found")

        advanced_text, received_hmac = parts

        # Verify HMAC for integrity
        if not verify_hmac(advanced_text, hmac_key, received_hmac):
            raise AuthenticationError("Invalid HMAC: content may have been tampered with")

        # Decode with advanced method to get JSON
        json_elements = advanced_decoding(advanced_text, xor_key)

        # Extract elements
        elements = json.loads(json_elements)

        # Version check
        version = elements.get("v", "3.2")
        if version not in ["3.2", "3.5"]:
            logging.warning(f"Unknown version {version}, attempting to decode anyway")

        # Decode from Base64
        salt = base64.b64decode(elements["s"])
        nonce = base64.b64decode(elements["n"])
        tag = base64.b64decode(elements["t"])
        ciphertext = base64.b64decode(elements["c"])

        # Derive AES key from password and salt
        aes_key_bytes, _ = derive_aes_key(aes_key, salt)

        # Decrypt with AES
        vigenere_text = decrypt_aes(nonce, tag, ciphertext, aes_key_bytes)

        # Decode Vigenère
        return vigenere_cipher(vigenere_text, vigenere_key, 'decode')

    except json.JSONDecodeError:
        raise DecodingError("Invalid JSON format in encoded data")
    except KeyError as e:
        raise DecodingError(f"Missing element in encoded data: {str(e)}")
    except AuthenticationError as e:
        raise AuthenticationError(str(e))
    except Exception as e:
        raise DecodingError(f"Hybrid decoding failed: {str(e)}")


def select_directory(title="Select Directory"):
    """Open directory selection dialog"""
    root = tk.Tk()
    root.withdraw()
    directory = filedialog.askdirectory(title=title)
    root.destroy()
    return directory


def select_files(title="Select Files", types=(("Text files", "*.txt"), ("All files", "*.*"))):
    """Open file selection dialog"""
    root = tk.Tk()
    root.withdraw()
    files = filedialog.askopenfilenames(title=title, filetypes=types)
    root.destroy()
    return list(files)


def select_save_directory(title="Save to"):
    """Open directory selection dialog for saving files"""
    root = tk.Tk()
    root.withdraw()
    directory = filedialog.askdirectory(title=title)
    root.destroy()
    return directory


def process_batch_file(file_path, vigenere_key, xor_key, hmac_key, aes_key, mode, output_dir):
    """
    Process a single file in batch mode

    Args:
        file_path: Path to input file
        vigenere_key: Key for Vigenère cipher
        xor_key: Key for XOR operation
        hmac_key: Key for HMAC
        aes_key: Key for AES
        mode: 'encode' or 'decode'
        output_dir: Directory to save output

    Returns:
        (success, result) tuple
    """
    try:
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        # Determine file encoding
        encodings = ['utf-8', 'latin-1', 'cp1252']
        file_content = None

        for encoding in encodings:
            try:
                with open(file_path, 'r', encoding=encoding) as f:
                    file_content = f.read()
                break
            except UnicodeDecodeError:
                continue

        if file_content is None:
            return False, "Could not decode file with any supported encoding"

        file_name = os.path.basename(file_path)
        extension = '.encoded' if mode == 'encode' else '.txt'
        output_file = os.path.join(output_dir, file_name + extension)

        if mode == 'encode':
            result = hybrid_encoding_v35(file_content, vigenere_key, xor_key, hmac_key, aes_key)
        else:
            result = hybrid_decoding_v35(file_content, vigenere_key, xor_key, hmac_key, aes_key)

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(result)

        return True, output_file
    except Exception as e:
        return False, str(e)


def get_secure_password(message):
    """
    Request a secure password and verify its strength

    Args:
        message: Prompt message

    Returns:
        Secure password
    """
    while True:
        # Use getpass for invisible password entry
        password = getpass.getpass(message)

        # Check password strength
        if len(password) < 12:
            print(f"{Fore.LIGHTRED_EX}Password too short. Use at least 12 characters.")
            continue

        has_uppercase = any(c.isupper() for c in password)
        has_lowercase = any(c.islower() for c in password)
        has_number = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)

        score = sum([has_uppercase, has_lowercase, has_number, has_special])

        if score < 3:
            print(f"{Fore.LIGHTRED_EX}Weak password. Use uppercase, lowercase, numbers, and special characters.")
            continue

        return password


def run_batch_mode(mode):
    """
    Run batch encoding/decoding

    Args:
        mode: 'encode' or 'decode'
    """
    os.system('cls' if os.name == 'nt' else 'clear')
    print(BANNER)
    print(SEPARATOR)

    title = "BATCH ENCODING" if mode == 'encode' else "BATCH DECODING"
    print(f"{Fore.LIGHTCYAN_EX}►► {title} (HYBRID MODE V3.5) ◄◄\n")

    print(f"{Fore.LIGHTWHITE_EX}Select files for processing...")
    files = select_files(
        title=f"Select files to {mode}",
        types=[
            ("Text files", "*.txt"),
            ("Encoded files", "*.encoded"),
            ("All files", "*.*")
        ]
    )

    if not files:
        print(f"{Fore.LIGHTRED_EX}No files selected.")
        input(f"{Fore.LIGHTBLACK_EX}\nPress Enter to continue...")
        return

    print(f"{Fore.LIGHTGREEN_EX}Found {len(files)} files to process.")

    print(f"{Fore.LIGHTWHITE_EX}Select directory to save results...")
    output_dir = select_save_directory(f"Select directory to save {mode}d files")

    if not output_dir:
        print(f"{Fore.LIGHTRED_EX}No destination directory selected.")
        input(f"{Fore.LIGHTBLACK_EX}\nPress Enter to continue...")
        return

    vigenere_key = input(f"{Fore.LIGHTWHITE_EX}►► Enter Vigenère key: ")
    xor_key = input(f"{Fore.LIGHTWHITE_EX}►► Enter XOR key: ")
    hmac_key = input(f"{Fore.LIGHTWHITE_EX}►► Enter HMAC key (authentication): ")
    aes_key = get_secure_password(f"{Fore.LIGHTWHITE_EX}►► Enter AES-256 key (master password): ")

    print(f"\n{Fore.LIGHTYELLOW_EX}Ready to process {len(files)} files. Confirm? (y/n): ", end="")
    if input().lower() != 'y':
        print(f"{Fore.LIGHTRED_EX}Operation canceled by user.")
        input(f"{Fore.LIGHTBLACK_EX}\nPress Enter to continue...")
        return

    print(f"\n{Fore.LIGHTWHITE_EX}Processing files:")

    successes = 0
    failures = 0
    failed_files = []
    start_time = time.time()

    for file_path in tqdm(files, bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]'):
        success, result = process_batch_file(
            file_path, vigenere_key, xor_key, hmac_key, aes_key, mode, output_dir
        )

        if success:
            successes += 1
            logging.info(f"Successfully processed: {os.path.basename(file_path)}")
        else:
            failures += 1
            failed_files.append((os.path.basename(file_path), result))
            logging.error(f"Failed to process {os.path.basename(file_path)}: {result}")

    total_time = time.time() - start_time

    print(f"\n{Fore.LIGHTGREEN_EX}Operation completed in {total_time:.2f} seconds!")
    print(f"{Fore.LIGHTGREEN_EX}Files processed successfully: {successes}")

    if failures > 0:
        print(f"{Fore.LIGHTRED_EX}Files with errors: {failures}")
        print(f"{Fore.LIGHTRED_EX}Error details:")
        for file_name, error in failed_files:
            print(f"{Fore.LIGHTRED_EX}- {file_name}: {error}")

    print(f"\n{Fore.LIGHTGREEN_EX}Results saved to: {output_dir}")
    input(f"{Fore.LIGHTBLACK_EX}\nPress Enter to continue...")


def show_about():
    """Display information about Base69"""
    os.system('cls' if os.name == 'nt' else 'clear')
    print(BANNER)
    print(SEPARATOR)
    print(f"{Fore.LIGHTCYAN_EX}About Base69 v3.5 Pro\n")
    print(f"{Fore.LIGHTWHITE_EX}Base69 is a hybrid encoding tool that combines multiple")
    print(f"{Fore.LIGHTWHITE_EX}cryptographic techniques to provide layered security.")
    print("")
    print(f"{Fore.LIGHTYELLOW_EX}Security layers in version 3.5:")
    print(f"{Fore.LIGHTWHITE_EX}1. Vigenère Cipher - classic cryptography")
    print(f"{Fore.LIGHTWHITE_EX}2. AES-256 in GCM mode - military-grade encryption")
    print(f"{Fore.LIGHTWHITE_EX}3. PBKDF2 key derivation - protection against brute force attacks")
    print(f"{Fore.LIGHTWHITE_EX}4. Advanced encoding - additional obfuscation")
    print(f"{Fore.LIGHTWHITE_EX}5. HMAC-SHA256 - integrity and authenticity verification")
    print("")
    print(f"{Fore.LIGHTCYAN_EX}Additional security features:")
    print(f"{Fore.LIGHTWHITE_EX}• Unique salt for each file")
    print(f"{Fore.LIGHTWHITE_EX}• Tamper protection via HMAC")
    print(f"{Fore.LIGHTWHITE_EX}• Password strength verification")
    print(f"{Fore.LIGHTWHITE_EX}• Batch mode for secure processing of multiple files")
    print(f"{Fore.LIGHTWHITE_EX}• Logging capabilities for auditing and troubleshooting")
    print(SEPARATOR)
    input(f"{Fore.LIGHTBLACK_EX}\nPress Enter to return to main menu...")


def show_menu():
    """Display main menu"""
    os.system("cls" if os.name == 'nt' else "clear")
    print(BANNER)
    print(SEPARATOR)
    print(f"{Fore.LIGHTWHITE_EX}1. Basic Encoding (Base64)")
    print(f"{Fore.LIGHTWHITE_EX}2. Basic Decoding (Base64)")
    print(f"{Fore.LIGHTWHITE_EX}3. Base64 Re-encoding")
    print(f"{Fore.LIGHTCYAN_EX}4. Hybrid Encoding V3.5 (AES-256 + Vigenère + HMAC)")
    print(f"{Fore.LIGHTCYAN_EX}5. Hybrid Decoding V3.5 (AES-256 + Vigenère + HMAC)")
    print(f"{Fore.LIGHTMAGENTA_EX}6. Batch Mode - Hybrid Encoding V3.5")
    print(f"{Fore.LIGHTMAGENTA_EX}7. Batch Mode - Hybrid Decoding V3.5")
    print(f"{Fore.LIGHTGREEN_EX}8. About Base69 v3.5")
    print(f"{Fore.LIGHTRED_EX}0. Exit")
    print(SEPARATOR)


def get_multiline_text(message: str) -> str:
    """
    Get multiline text input from user

    Args:
        message: Prompt message

    Returns:
        Input text
    """
    print(f"{Fore.LIGHTWHITE_EX}{message} (type a space and press Enter to finish):")
    lines = []
    while True:
        line = input()
        if line == ' ':
            break
        lines.append(line)
    return '\n'.join(lines)


def main():
    """Main program loop"""
    try:
        while True:
            show_menu()
            choice = input(f"\n{Fore.LIGHTWHITE_EX}►► Choose an option (0-8): ")

            if choice == '1':
                text = get_multiline_text("Enter text to encode")
                try:
                    encoded = base64.b64encode(text.encode()).decode()
                    print(f"{Fore.LIGHTGREEN_EX}\nEncoded text:\n{encoded}")
                    if input(f"{Fore.LIGHTWHITE_EX}►► Copy to clipboard? (y/n): ").lower() == 'y':
                        pyperclip.copy(encoded)
                        print(f"{Fore.LIGHTGREEN_EX}Copied to clipboard!")
                except Exception as e:
                    print(f"{Fore.LIGHTRED_EX}Error: {str(e)}")
                input(f"{Fore.LIGHTBLACK_EX}\nPress Enter to continue...")

            elif choice == '2':
                text = get_multiline_text("Enter Base64 text to decode")
                try:
                    decoded = base64.b64decode(text.encode()).decode()
                    print(f"{Fore.LIGHTGREEN_EX}\nDecoded text:\n{decoded}")
                    if input(f"{Fore.LIGHTWHITE_EX}►► Copy? (y/n): ").lower() == 'y':
                        pyperclip.copy(decoded)
                        print(f"{Fore.LIGHTGREEN_EX}Copied to clipboard!")
                except Exception as e:
                    print(f"{Fore.LIGHTRED_EX}Error: Invalid Base64 text!")
                input(f"{Fore.LIGHTBLACK_EX}\nPress Enter to continue...")

            elif choice == '3':
                text = get_multiline_text("Enter Base64 text to re-encode")
                try:
                    decoded = base64.b64decode(text.encode()).decode()
                    reencoded = base64.b64encode(decoded.encode()).decode()
                    print(f"{Fore.LIGHTGREEN_EX}\nRe-encoded text:\n{reencoded}")
                    if input(f"{Fore.LIGHTWHITE_EX}►► Copy? (y/n): ").lower() == 'y':
                        pyperclip.copy(reencoded)
                        print(f"{Fore.LIGHTGREEN_EX}Copied to clipboard!")
                except Exception as e:
                    print(f"{Fore.LIGHTRED_EX}Error: Invalid Base64 text!")
                input(f"{Fore.LIGHTBLACK_EX}\nPress Enter to continue...")

            elif choice == '4':
                text = get_multiline_text("Enter text for hybrid encoding V3.5")
                vigenere_key = input(f"{Fore.LIGHTWHITE_EX}►► Enter Vigenère key: ")
                xor_key = input(f"{Fore.LIGHTWHITE_EX}►► Enter XOR key: ")
                hmac_key = input(f"{Fore.LIGHTWHITE_EX}►► Enter HMAC key (authentication): ")
                aes_key = get_secure_password(f"{Fore.LIGHTWHITE_EX}►► Enter AES-256 key (master password): ")
                try:
                    encoded = hybrid_encoding_v35(text, vigenere_key, xor_key, hmac_key, aes_key)
                    print(f"{Fore.LIGHTGREEN_EX}\nEncoded text (Hybrid V3.5):\n{encoded}")
                    if input(f"{Fore.LIGHTWHITE_EX}►► Copy? (y/n): ").lower() == 'y':
                        pyperclip.copy(encoded)
                        print(f"{Fore.LIGHTGREEN_EX}Copied to clipboard!")
                except Exception as e:
                    print(f"{Fore.LIGHTRED_EX}Error: {str(e)}")
                input(f"{Fore.LIGHTBLACK_EX}\nPress Enter to continue...")

            elif choice == '5':
                text = get_multiline_text("Enter encoded text (Hybrid V3.5)")
                vigenere_key = input(f"{Fore.LIGHTWHITE_EX}►► Enter Vigenère key: ")
                xor_key = input(f"{Fore.LIGHTWHITE_EX}►► Enter XOR key: ")
                hmac_key = input(f"{Fore.LIGHTWHITE_EX}►► Enter HMAC key (authentication): ")
                aes_key = getpass.getpass(f"{Fore.LIGHTWHITE_EX}►► Enter AES-256 key (master password): ")
                try:
                    decoded = hybrid_decoding_v35(text, vigenere_key, xor_key, hmac_key, aes_key)
                    print(f"{Fore.LIGHTGREEN_EX}\nDecoded text:\n{decoded}")
                    if input(f"{Fore.LIGHTWHITE_EX}►► Copy? (y/n): ").lower() == 'y':
                        pyperclip.copy(decoded)
                        print(f"{Fore.LIGHTGREEN_EX}Copied to clipboard!")
                except AuthenticationError as e:
                    print(f"{Fore.LIGHTRED_EX}Authentication Error: {str(e)}")
                except DecodingError as e:
                    print(f"{Fore.LIGHTRED_EX}Decoding Error: {str(e)}")
                except Exception as e:
                    print(f"{Fore.LIGHTRED_EX}Error: {str(e)}")
                input(f"{Fore.LIGHTBLACK_EX}\nPress Enter to continue...")

            elif choice == '6':
                run_batch_mode('encode')

            elif choice == '7':
                run_batch_mode('decode')

            elif choice == '8':
                show_about()

            elif choice == '0':
                print(f"\n{Fore.LIGHTCYAN_EX}Goodbye!")
                break

            else:
                print(f"\n{Fore.LIGHTRED_EX}Invalid option! Use numbers 0 through 8.")
                input(f"{Fore.LIGHTBLACK_EX}\nPress Enter to continue...")
    except KeyboardInterrupt:
            print(f"\n\n{Fore.LIGHTRED_EX}Program terminated by user.")
    except Exception as e:
        logging.critical(f"Unhandled exception: {str(e)}")
        print(f"\n{Fore.LIGHTRED_EX}Critical error: {str(e)}")
        print(f"{Fore.LIGHTRED_EX}Check the log file for details.")
    finally:
        print(f"\n{Fore.LIGHTCYAN_EX}Exiting Base69...")
        sys.exit(0)
main()
