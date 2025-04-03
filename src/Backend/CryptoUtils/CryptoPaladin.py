from typing import Any
import os
import argon2
from Backend.CryptoUtils.CryptoPaladinExceptions import SaltLengthException
import logging
import base64
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