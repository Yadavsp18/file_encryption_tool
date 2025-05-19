"""
Test script for encryption utilities.
"""

import os
import encryption_utils

def test_encryption_decryption():
    """Test the encryption and decryption functions."""
    print("Testing encryption and decryption...")
    
    # Test data
    test_data = b"This is a test message for encryption and decryption."
    password = "test_password"
    
    # Encrypt the data
    print("Encrypting data...")
    encrypted_data = encryption_utils.encrypt_data(test_data, password)
    print(f"Encrypted data length: {len(encrypted_data)} bytes")
    
    # Decrypt the data
    print("Decrypting data...")
    decrypted_data = encryption_utils.decrypt_data(encrypted_data, password)
    print(f"Decrypted data length: {len(decrypted_data)} bytes")
    
    # Verify the decrypted data matches the original
    if decrypted_data == test_data:
        print("✅ Success! Decrypted data matches original data.")
    else:
        print("❌ Error: Decrypted data does not match original data.")
        print(f"Original: {test_data}")
        print(f"Decrypted: {decrypted_data}")

def test_file_encryption_decryption():
    """Test file encryption and decryption."""
    print("\nTesting file encryption and decryption...")
    
    # Test files
    input_file = "test_file.txt"
    encrypted_file = "test_file.txt.encrypted"
    decrypted_file = "test_file.txt.decrypted"
    password = "test_password"
    
    # Check if input file exists
    if not os.path.exists(input_file):
        print(f"❌ Error: Test file '{input_file}' not found.")
        return
    
    # Encrypt the file
    print(f"Encrypting file '{input_file}'...")
    encryption_utils.encrypt_file(input_file, encrypted_file, password)
    
    if os.path.exists(encrypted_file):
        print(f"✅ Encrypted file created: '{encrypted_file}'")
        print(f"   Size: {os.path.getsize(encrypted_file)} bytes")
    else:
        print(f"❌ Error: Failed to create encrypted file.")
        return
    
    # Decrypt the file
    print(f"Decrypting file '{encrypted_file}'...")
    encryption_utils.decrypt_file(encrypted_file, decrypted_file, password)
    
    if os.path.exists(decrypted_file):
        print(f"✅ Decrypted file created: '{decrypted_file}'")
        print(f"   Size: {os.path.getsize(decrypted_file)} bytes")
    else:
        print(f"❌ Error: Failed to create decrypted file.")
        return
    
    # Compare original and decrypted files
    with open(input_file, 'rb') as f1, open(decrypted_file, 'rb') as f2:
        original_data = f1.read()
        decrypted_data = f2.read()
        
        if original_data == decrypted_data:
            print("✅ Success! Decrypted file content matches original file.")
        else:
            print("❌ Error: Decrypted file content does not match original file.")
            print(f"Original file size: {len(original_data)} bytes")
            print(f"Decrypted file size: {len(decrypted_data)} bytes")

if __name__ == "__main__":
    test_encryption_decryption()
    test_file_encryption_decryption()
    print("\nAll tests completed.")
