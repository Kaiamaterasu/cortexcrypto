#!/usr/bin/env python3
"""
CortexCrypt Standalone Mode - Neural Augmented Encryption without Daemon
"""

import os
import sys
import hashlib
import argparse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import secrets

class CortexCryptStandalone:
    """
    Standalone CortexCrypt implementation that mimics the .cortex format
    without requiring the daemon or neural network (uses fallback crypto)
    """
    
    def __init__(self):
        self.magic = b"CORTEX01"
        self.version = 1
        
    def get_machine_binding(self):
        """Generate machine binding ID"""
        # Simplified machine fingerprint
        machine_data = (
            os.uname().nodename + 
            os.uname().machine + 
            str(os.path.getmtime('/etc/passwd'))  # System install time proxy
        ).encode()
        return hashlib.sha256(machine_data).digest()
    
    def derive_key(self, password: str, salt: bytes, binding_id: bytes) -> bytes:
        """
        Neural-augmented key derivation (fallback mode)
        In full mode, this would use the MLP neural network
        """
        # Base PBKDF2 derivation
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        base_key = kdf.derive(password.encode())
        
        # Simulate neural augmentation with HKDF (fallback)
        # In full mode: neural_output = mlp_model(base_key_prefix + binding_id + context)
        neural_input = base_key[:16] + binding_id[:16]  # Simplified
        neural_output = hashlib.sha256(neural_input + b"neural_fallback").digest()
        
        # Mix base key with neural output
        final_key = hashlib.sha256(base_key + neural_output).digest()
        return final_key
    
    def encrypt_file(self, input_path: str, output_path: str, password: str, 
                    bind_policy: str = "machine", note: str = ""):
        """Encrypt file to .cortex format"""
        
        # Generate salts and binding
        file_salt = secrets.token_bytes(16)
        session_salt = secrets.token_bytes(16)
        nonce = secrets.token_bytes(12)
        
        if bind_policy == "machine":
            binding_id = self.get_machine_binding()
        else:
            # Volume binding (simplified)
            volume_data = os.path.abspath(input_path).encode()
            binding_id = hashlib.sha256(volume_data).digest()
        
        # Derive encryption key with neural augmentation
        key = self.derive_key(password, file_salt, binding_id)
        
        # Read input file
        with open(input_path, 'rb') as f:
            plaintext = f.read()
        
        # Encrypt with AES-256-GCM
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        auth_tag = encryptor.tag
        
        # Create full metadata
        import time
        metadata = {
            "filename": os.path.basename(input_path),
            "timestamp": int(time.time()),
            "original_size": len(plaintext),
            "version": "1.0",
            "note": note,
            "bind_policy": bind_policy
        }
        metadata_json = str(metadata).replace("'", '"').encode()
        
        # Write .cortex file with proper TLV format (matching CLI)
        with open(output_path, 'wb') as f:
            # Header - match CLI format exactly
            f.write(self.magic)  # CORTEX01
            f.write(bytes([0, 1]))  # Version (big-endian)
            f.write(bytes([2, 0]))  # Flags (big-endian) 
            
            # Create TLV metadata
            file_meta_tlv = b'\x01' + len(metadata_json).to_bytes(2, 'big') + metadata_json
            note_tlv = b'\x04' + len(note.encode()).to_bytes(2, 'big') + note.encode() if note else b''
            tlv_data = file_meta_tlv + note_tlv
            
            # Header length (little-endian) - includes fixed header + TLVs
            header_len = 112 + 32 + len(tlv_data)  # Fixed header + AAD hash + TLVs
            f.write(header_len.to_bytes(2, 'little'))
            f.write(b'\x00\x00')  # Reserved
            
            # Salts and hashes (112 bytes total)
            f.write(file_salt)  # 16 bytes
            f.write(session_salt)  # 16 bytes 
            f.write(hashlib.sha256(binding_id).digest())  # 32 bytes - binding hash
            f.write(b'\x00' * 32)  # 32 bytes - model hash (fallback)
            f.write(b'\x00' * 16)  # 16 bytes - reserved
            
            # AAD hash placeholder (will be calculated)
            aad_hash_pos = f.tell()
            f.write(b'\x00' * 32)  # 32 bytes - AAD hash
            
            # TLV metadata
            f.write(tlv_data)
            
            # Calculate and write AAD hash
            current_pos = f.tell()
            
            # Read header data for AAD calculation
            f.flush()  # Ensure data is written
            
            # For now, use a simple AAD hash (in production, would be more complex)
            aad_input = file_salt + session_salt + binding_id + metadata_json
            aad_hash = hashlib.sha256(aad_input).digest()
            
            # Write the AAD hash
            f.seek(aad_hash_pos)
            f.write(aad_hash)
            f.seek(current_pos)
            
            # Nonce and ciphertext
            f.write(nonce)
            f.write(ciphertext)
            f.write(auth_tag)
        
        print(f"✓ Encrypted {input_path} -> {output_path}")
        print(f"  Cipher: AES-256-GCM")
        print(f"  Binding: {bind_policy}")
        print(f"  Size: {len(plaintext)} -> {os.path.getsize(output_path)} bytes")
        
        # Clear sensitive data
        key = b'\x00' * len(key)
        
        return 0
    
    def decrypt_file(self, input_path: str, output_path: str, password: str):
        """Decrypt .cortex file"""
        
        with open(input_path, 'rb') as f:
            # Read header - handle both formats
            magic = f.read(8)
            if magic != self.magic:
                print("Error: Invalid .cortex file format")
                return -1
            
            # Try to detect format version
            version_bytes = f.read(2)
            if version_bytes == b'\x01\x00':  # Python format
                # Python format (little-endian)
                flags = int.from_bytes(f.read(1), 'little')
                cipher_id = int.from_bytes(f.read(1), 'little')
                header_len = int.from_bytes(f.read(4), 'little')
                
                # Read salts and hashes
                file_salt = f.read(16)
                session_salt = f.read(16)
                binding_hash = f.read(32)
                model_hash = f.read(32)
                
                # Read metadata (simple length-prefixed)
                metadata_len = int.from_bytes(f.read(4), 'little')
                metadata_bytes = f.read(metadata_len)
                
            else:  # CLI format (big-endian)
                f.seek(8)  # Reset after magic
                version = int.from_bytes(f.read(2), 'big')
                flags = int.from_bytes(f.read(2), 'big')
                header_len = int.from_bytes(f.read(2), 'little')
                reserved = f.read(2)
                
                # Read fixed header (112 bytes)
                file_salt = f.read(16)
                session_salt = f.read(16)
                binding_hash = f.read(32)
                model_hash = f.read(32)
                reserved2 = f.read(16)
                aad_hash = f.read(32)
                
                # Read TLV metadata
                tlv_start = f.tell()
                tlv_end = 16 + header_len  # Start of ciphertext
                tlv_data = f.read(tlv_end - tlv_start)
                
                # Parse TLVs to find metadata
                metadata_bytes = b'{}'
                pos = 0
                while pos + 3 < len(tlv_data):
                    tlv_type = tlv_data[pos]
                    tlv_len = int.from_bytes(tlv_data[pos+1:pos+3], 'big')
                    tlv_value = tlv_data[pos+3:pos+3+tlv_len]
                    
                    if tlv_type == 1:  # FILE_META
                        metadata_bytes = tlv_value
                        break
                    
                    pos += 3 + tlv_len
            
            # Read encryption data
            nonce = f.read(12)
            remaining = f.read()
            ciphertext = remaining[:-16]
            auth_tag = remaining[-16:]
        
        # Get current binding for verification
        if "machine" in metadata_bytes.decode('utf-8', errors='ignore'):
            current_binding = self.get_machine_binding()
        else:
            volume_data = os.path.abspath(input_path).encode()
            current_binding = hashlib.sha256(volume_data).digest()
        
        # Verify binding
        expected_binding_hash = hashlib.sha256(current_binding).digest()
        if binding_hash != expected_binding_hash:
            print("Error: Binding mismatch - file cannot be decrypted on this device")
            return -2
        
        # Derive decryption key
        key = self.derive_key(password, file_salt, current_binding)
        
        # Decrypt with AES-256-GCM
        try:
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(nonce, auth_tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            
            # This will raise an exception if authentication fails (tampering detected)
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Additional integrity check - verify file size makes sense
            if len(plaintext) == 0 and len(ciphertext) > 0:
                raise ValueError("Decryption produced empty result - possible tampering")
            
            # Write decrypted file
            with open(output_path, 'wb') as f:
                f.write(plaintext)
            
            print(f"✓ Decrypted {input_path} -> {output_path}")
            print(f"  Size: {len(ciphertext)} -> {len(plaintext)} bytes")
            
            # Clear sensitive data
            key = b'\x00' * len(key)
            
            return 0
            
        except Exception as e:
            print(f"Error: Authentication/decryption failed - {str(e)}")
            return -3

def main():
    parser = argparse.ArgumentParser(description="CortexCrypt Standalone Mode")
    parser.add_argument("command", choices=["encrypt", "decrypt", "info"], help="Operation to perform")
    parser.add_argument("--in", dest="input_file", required=True, help="Input file")
    parser.add_argument("--out", dest="output_file", help="Output file")
    parser.add_argument("--bind", default="machine", choices=["machine", "volume"], help="Binding policy")
    parser.add_argument("--note", default="", help="Optional note")
    
    args = parser.parse_args()
    
    cc = CortexCryptStandalone()
    
    if args.command == "encrypt":
        if not args.output_file:
            print("Error: --out required for encrypt")
            return 1
            
        password = input("Passphrase: ")
        return cc.encrypt_file(args.input_file, args.output_file, password, args.bind, args.note)
    
    elif args.command == "decrypt":
        if not args.output_file:
            print("Error: --out required for decrypt")
            return 1
            
        password = input("Passphrase: ")
        return cc.decrypt_file(args.input_file, args.output_file, password)
    
    elif args.command == "info":
        # Basic file info
        if not os.path.exists(args.input_file):
            print("Error: File not found")
            return 1
            
        with open(args.input_file, 'rb') as f:
            magic = f.read(8)
            if magic == b"CORTEX01":
                print(f"✓ Valid .cortex file: {args.input_file}")
                print(f"  Format: CortexCrypt v1.0")
                print(f"  Size: {os.path.getsize(args.input_file)} bytes")
            else:
                print("✗ Not a .cortex file")
                return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
