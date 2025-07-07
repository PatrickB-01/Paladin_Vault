from typing import Any
import os
import argon2
from Backend.CryptoUtils.CryptoPaladinExceptions import SaltLengthException
import logging
import base64
from Crypto.Cipher import AES
import time
import platform
import psutil
import secrets
import string


# Utility functions for encryption, decryption and key generation


def generate_key(input:str, salt:bytes = None) -> tuple[str,bytes]:
    '''
    Returns a (key,salt) based on input given
    '''
    
    # Generate a random salt
    #salt = os.urandom(16)
    if salt:
        if len(salt) != 16:
            raise SaltLengthException(size=len(salt), expected_size=16)
    else:
        salt = os.urandom(16)

    # Argon2id parameters: 
    # memory_cost unit is KB
    ph:argon2.PasswordHasher = argon2.PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32,type=argon2.low_level.Type.ID,salt_len=16) 
    # Derive key using Argon2id (salt is prepended internally)
    derived_key:str = ph.hash(input ,salt=salt)
    return (derived_key,salt)


def scan_usb_for_file(filename="keyfile.bin", interval=2):
    print("Scanning for USB containing:", filename)
    scanned = set()

    while True:
        time.sleep(interval)

        # Check all mounted/removable drives
        partitions = psutil.disk_partitions(all=False)
        for part in partitions:
            if platform.system() == "Windows":
                if 'removable' in part.opts.lower():
                    drive_path = part.mountpoint
                else:
                    continue
            else:  # Linux/macOS
                if part.mountpoint.startswith("/media") or part.mountpoint.startswith("/run/media"):
                    drive_path = part.mountpoint
                else:
                    continue

            file_path = os.path.join(drive_path, filename)
            if file_path in scanned:
                continue  # Skip if already checked

            scanned.add(file_path)

            if os.path.isfile(file_path):
                print(f"Found '{filename}' on {drive_path}")
                return file_path  # Or return drive_path if you prefer

        print("Waiting for USB with the target file...")


def save_key(key:str, salt:bytes, key_file:str) -> None:
    '''
    Saves the salt + derived key in the key file
    '''
    with open(key_file,"wb") as kf:
        kf.write(salt + key.encode())

def load_key(key_file:str) -> tuple[bytes,bytes]:
    with open(key_file,"rb") as kf:
        data = kf.read()
        salt = data[:16]
        key = data[16:]
    return (key,salt)

def verify_key(input:str, key:bytes, salt:bytes) -> bool:
    '''
    Verify if input matches key
    '''
    if salt:
        if len(salt) != 16:
            raise SaltLengthException(size=len(salt), expected_size=16)

    try:
        ph = argon2.PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32,type=argon2.low_level.Type.ID,salt_len=16)
        ph.verify(hash=key, password=input)
        logging.debug("Verified password successfully")
        return True
    except argon2.exceptions.VerifyMismatchError as ex:
        logging.error(str(ex))
        return False
    
def derive_key(input:str,salt:bytes) -> tuple[bytes,str]:
    ph = argon2.PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32,type=argon2.low_level.Type.ID,salt_len=16)
    hash_result:str = ph.hash(input ,salt=salt)
    argon2_values = hash_result.split("$")
    hash = argon2_values[-1]
    hash_bytes = base64.b64decode(hash+'==') # added padding because python is weird
    return (hash_bytes,hash_result)

# Encryption

def encrypt(plaintext:bytes, key:bytes) -> tuple[bytes,bytes,bytes]:
    '''
    Encrypts the plaintext using AES in GCM mode and a 256 bit key then returns  tuple[nonce , ciphertext , tag]
    '''
    # Generate a random 16-byte nonce
    nonce = os.urandom(16)
    # Create AES cipher in GCM mode
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce,mac_len=16)
    # Encrypt the plaintext
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return nonce, ciphertext, tag

def decrypt(key:bytes, ciphertext:bytes, nonce:bytes, tag:bytes) -> bytes:
    '''
    Decrypts the ciphertext using AES in GCM mode and a 256 bit key then verifies the MAC/TAG for integrity check
    '''
    # Create AES cipher in GCM mode with the same nonce
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce,mac_len=16)
    # Decrypt the ciphertext
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext


def generate_secure_password(length: int = 16) -> str:
    """
    Generates a cryptographically secure random password.

    Args:
        length: The desired length of the password. Must be between 8 and 128.

    Returns:
        A string containing the generated password.
        The password will contain at least one uppercase letter, one lowercase letter,
        one digit, and one special character.

    Raises:
        ValueError: If the length is outside the allowed range.
    """
    if not (8 <= length <= 128):
        raise ValueError("Password length must be between 8 and 128 characters.")

    # Define character sets
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    # Using a more common set of special characters for passwords
    special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"


    # Ensure the password contains at least one of each required character type
    password_chars = [
        secrets.choice(lowercase),
        secrets.choice(uppercase),
        secrets.choice(digits),
        secrets.choice(special_chars)
    ]

    # Fill the rest of the password length with a mix of all characters
    all_chars = lowercase + uppercase + digits + special_chars
    # Ensure we have enough characters to pick from for the remaining length
    if length < 4: # Should be caught by the initial length check, but as a safeguard
        password_chars = password_chars[:length] # Truncate if length is less than 4

    remaining_length = length - len(password_chars)
    if remaining_length > 0:
        for _ in range(remaining_length):
            password_chars.append(secrets.choice(all_chars))

    # Shuffle the characters to make the positions random
    secrets.SystemRandom().shuffle(password_chars)

    return "".join(password_chars)