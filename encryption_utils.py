"""
Encryption Utilities Module

This module provides utility functions for file encryption and decryption
using AES-256 encryption with secure key derivation.
"""

import os
import base64
from typing import Tuple, Optional, Union, BinaryIO
from pathlib import Path

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


# Constants
SALT_SIZE = 16  # 128 bits
IV_SIZE = 16    # 128 bits
KEY_SIZE = 32   # 256 bits
ITERATIONS = 100000  # Number of iterations for key derivation


def derive_key(password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """
    Derive an encryption key from a password using PBKDF2.
    
    Args:
        password: The password to derive the key from
        salt: Optional salt bytes. If None, a new random salt is generated
        
    Returns:
        Tuple of (derived_key, salt)
    """
    if salt is None:
        salt = os.urandom(SALT_SIZE)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    
    key = kdf.derive(password.encode('utf-8'))
    return key, salt


def encrypt_data(data: bytes, password: str) -> bytes:
    """
    Encrypt data using AES-256 with a password.
    
    Args:
        data: The data to encrypt
        password: The password to use for encryption
        
    Returns:
        Encrypted data with salt and IV prepended
    """
    # Generate a random IV
    iv = os.urandom(IV_SIZE)
    
    # Derive key from password
    key, salt = derive_key(password)
    
    # Pad the data
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    
    # Create cipher and encrypt
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    # Prepend salt and IV to the encrypted data
    return salt + iv + encrypted_data


def decrypt_data(encrypted_data: bytes, password: str) -> bytes:
    """
    Decrypt data that was encrypted with encrypt_data.
    
    Args:
        encrypted_data: The encrypted data (including salt and IV)
        password: The password used for encryption
        
    Returns:
        Decrypted data
    """
    # Extract salt and IV
    salt = encrypted_data[:SALT_SIZE]
    iv = encrypted_data[SALT_SIZE:SALT_SIZE + IV_SIZE]
    ciphertext = encrypted_data[SALT_SIZE + IV_SIZE:]
    
    # Derive key from password and salt
    key, _ = derive_key(password, salt)
    
    # Create cipher and decrypt
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Unpad the data
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    try:
        data = unpadder.update(padded_data) + unpadder.finalize()
        return data
    except ValueError:
        # This likely means the password was incorrect
        raise ValueError("Decryption failed. The password may be incorrect.")


def encrypt_file(input_path: Union[str, Path], output_path: Union[str, Path], password: str) -> None:
    """
    Encrypt a file using AES-256 with a password.
    
    Args:
        input_path: Path to the file to encrypt
        output_path: Path where the encrypted file will be saved
        password: The password to use for encryption
    """
    with open(input_path, 'rb') as f:
        data = f.read()
    
    encrypted_data = encrypt_data(data, password)
    
    with open(output_path, 'wb') as f:
        f.write(encrypted_data)


def decrypt_file(input_path: Union[str, Path], output_path: Union[str, Path], password: str) -> None:
    """
    Decrypt a file that was encrypted with encrypt_file.
    
    Args:
        input_path: Path to the encrypted file
        output_path: Path where the decrypted file will be saved
        password: The password used for encryption
    """
    with open(input_path, 'rb') as f:
        encrypted_data = f.read()
    
    try:
        decrypted_data = decrypt_data(encrypted_data, password)
        
        with open(output_path, 'wb') as f:
            f.write(decrypted_data)
    except ValueError as e:
        raise ValueError(f"Failed to decrypt file: {e}")


def read_file_content(file_path: Union[str, Path], max_size: int = 1024 * 1024) -> Tuple[bytes, str]:
    """
    Read file content and determine its type (text or binary).
    
    Args:
        file_path: Path to the file to read
        max_size: Maximum size to read (to prevent loading huge files into memory)
        
    Returns:
        Tuple of (file_content, content_type) where content_type is 'text' or 'binary'
    """
    with open(file_path, 'rb') as f:
        content = f.read(max_size)
    
    # Try to decode as text
    try:
        content.decode('utf-8')
        return content, 'text'
    except UnicodeDecodeError:
        return content, 'binary'


def get_file_preview(file_path: Union[str, Path], max_size: int = 100 * 1024) -> Tuple[str, bool]:
    """
    Get a preview of a file's content.
    
    Args:
        file_path: Path to the file
        max_size: Maximum size to read
        
    Returns:
        Tuple of (preview_text, is_truncated)
    """
    content, content_type = read_file_content(file_path, max_size)
    
    if content_type == 'text':
        try:
            text = content.decode('utf-8')
            truncated = len(content) >= max_size
            return text, truncated
        except UnicodeDecodeError:
            return "[Binary content - preview not available]", False
    else:
        return "[Binary content - preview not available]", False
