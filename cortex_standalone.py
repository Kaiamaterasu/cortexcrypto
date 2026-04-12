#!/usr/bin/env python3
"""
CortexCrypt Standalone Mode - Neural Augmented Encryption without Daemon
"""

import os
import sys
import hashlib
import math
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
    
    # Rate limiting for failed decryption attempts
    _failed_attempts = {}  # {ip_or_host: [timestamp1, timestamp2, ...]}
    _lockout_duration = 300  # 5 minutes lockout after max attempts
    _max_attempts = 5  # Max failed attempts before lockout
    _time_window = 60  # Count attempts within 60 seconds
    
    def __init__(self):
        self.magic = b"CORTEX01"
        self.version = 1
        self.failed_attempts = {}  # Instance-level tracking
    
    def _check_rate_limit(self, identifier: str = "default") -> bool:
        """Check if requests should be rate limited"""
        import time
        current_time = time.time()
        
        # Initialize if not exists
        if identifier not in self.failed_attempts:
            self.failed_attempts[identifier] = []
        
        # Clean old attempts outside the time window
        self.failed_attempts[identifier] = [
            t for t in self.failed_attempts[identifier]
            if current_time - t < self._time_window
        ]
        
        # Check if locked out
        if len(self.failed_attempts[identifier]) >= self._max_attempts:
            # Check if lockout period has passed
            last_attempt = self.failed_attempts[identifier][-1]
            if current_time - last_attempt < self._lockout_duration:
                print(f"⚠️  Too many failed attempts. Please wait {int(self._lockout_duration - (current_time - last_attempt))} seconds")
                return False
            # Lockout expired, reset
            self.failed_attempts[identifier] = []
        
        return True
    
    def _record_failed_attempt(self, identifier: str = "default"):
        """Record a failed decryption attempt"""
        import time
        if identifier not in self.failed_attempts:
            self.failed_attempts[identifier] = []
        self.failed_attempts[identifier].append(time.time())
    
    def _record_success(self, identifier: str = "default"):
        """Clear failed attempts on successful decryption"""
        if identifier in self.failed_attempts:
            self.failed_attempts[identifier] = []
        
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
    
    def validate_password_strength(self, password: str) -> bool:
        """Validate password meets minimum strength requirements"""
        
        weak_passwords = [
            # Top 100 most common passwords
            '123456', 'password', '12345678', 'qwerty', '123456789',
            '12345', '1234', '111111', '1234567', 'dragon', 'letmein',
            'admin', 'welcome', 'monkey', 'master', 'abc123', '0000',
            'pass', 'test', 'guest', 'shadow', 'sunshine', 'princess',
            'football', 'baseball', 'soccer', 'killer', 'trustno1',
            'iloveyou', 'superman', 'batman', 'passw0rd', 'hello', 'rockyou',
            'cookie', 'cheese', 'poop', 'fuckoff', 'blahblah', 'solo',
            'mustang', 'pokemon', 'slayer', 'bubbles', 'bailey', 'buster',
            'summer', 'liverpool', 'arsenal', 'chelsea', 'manutd', 'rangers',
            # Repeating characters
            'aaaaaaaa', 'bbbbbbbb', 'cccccccc', 'dddddddd', 'eeeeeeee',
            'aaaaaaaaaaaa', '11111111', '22222222', 'password1', 'password12',
            # Keyboard patterns
            'qwertyuiop', 'asdfghjkl', 'zxcvbnm', 'qazwsxedc', 'zaq12wsx',
            'qweasdzxc', 'qweasd', 'qwe123', 'asd123', 'zxc123',
            # Common names
            'michael', 'jennifer', 'jordan', 'ashley', 'daniel', 'thomas',
            'natalie', 'brianna', 'joshua', 'andrea', 'jordan', 'matthew',
            # Year patterns
            'password2020', 'password2021', 'password2022', 'password2023', 'password2024',
            'admin2020', 'admin2021', 'admin2022', 'admin2023', 'admin2024',
            '1234567890', '0987654321', '19901991', '19911992', '19921993',
            # Leetspeak variants
            'p@ssw0rd', 'p@ssword', 'p@ssw0rd123', 'p@ssword123',
            's3cr3t', 's3cr3t123', 'S3cr3t', 'S3cr3t123',
            'l0g1n', 'l0g1n123', 'L0g1n', 'L0g1n123',
            '1qaz2wsx', '1qazwsx', 'qazwsxedc', 'qazwsx',
            # Word + number patterns
            'root1234', 'admin1234', 'user1234', 'test1234', 'guest1234',
            'shadow1', 'sunshine1', 'dragon1', 'princess1', 'butterfly1',
            'pizza123', 'coffee123', 'chocolate', 'chocolate1', 'purple1', 'tiger1',
            # OS and software
            'windows10', 'windows11', 'macos', 'ubuntu', 'linux', 'debian',
            'chrome', 'firefox', 'safari', 'edge', 'opera',
            'oracle', 'mysql', 'sqlserver', 'postgresql', 'mongodb',
            'google', 'facebook', 'twitter', 'instagram', 'youtube', 'netflix',
            # Dictionary words
            'apple', 'banana', 'orange', 'grape', 'lemon', 'lime', 'mango', 'peach',
            'coffee', 'milk', 'water', 'bread', 'cheese', 'pizza', 'burger', 'fries',
            'pasta', 'rice', 'soup', 'salad', 'chicken', 'beef', 'pork', 'fish', 'meat',
            # Animals
            'dog', 'cat', 'bird', 'fish', 'lion', 'tiger', 'bear', 'wolf', 'monkey', 'snake',
            'dogcat', 'catdog', 'wolfpack', 'corgi', 'husky', 'shepherd', 'bulldog',
            # Colors
            'red', 'blue', 'green', 'yellow', 'purple', 'orange', 'pink',
            'black', 'white', 'silver', 'golden', 'brown', 'navy', 'coral',
            # Days/Months
            'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday',
            'january', 'february', 'march', 'april', 'may', 'june', 'july', 'august',
            'september', 'october', 'november', 'december',
            # Brands
            'nike', 'adidas', 'puma', 'gucci', 'prada', 'chanel', 'dior',
            'cocacola', 'pepsi', 'starbucks', 'mcdonalds', 'kfc', 'burgerking',
            # Movies
            'starwars', 'harrypotter', 'gameofthrones', 'breakingbad', 'avengers', 'joker',
            # Sports
            'football', 'baseball', 'soccer', 'basketball', 'tennis', 'golf',
            'hockey', 'boxing', 'wrestling', 'cricket', 'rugby', 'volleyball',
            # Cars
            'toyota', 'honda', 'ford', 'bmw', 'benz', 'audi', 'ferrari',
            'lamborghini', 'porsche', 'mustang', 'camaro', 'charger', 'corvette',
            # Games
            'minecraft', 'fortnite', 'cod', 'csgo', 'dota', 'lol', 'ow', 'apex',
            'pubg', 'valorant', 'genshin', 'roblox', 'amongus', 'AmongUs',
            # Music
            'eminem', 'drake', 'beyonce', 'taylorswift', 'bieber', 'queen',
            'metallica', 'nirvana', 'acdc', 'u2', 'linkinpark', 'green_day',
            # Tech
            'microsoft', 'amazon', 'apple', 'intel', 'amd', 'nvidia', 'sony', 'samsung',
            # Programming
            'python', 'java', 'javascript', 'csharp', 'cpp', 'ruby', 'golang',
            'rust', 'swift', 'kotlin', 'php', 'perl', 'typescript',
            # More leetspeak
            'n00b', 'h4x0r', 'l33t', 'pr0', 'z3r0', 'h4ck3r',
            'xbl4d3', 'p4ssw0rd', 's3cur3', 'k3yb0ard', 'b4ckd00r',
            # Years
            '1990', '1991', '1992', '1993', '1994', '1995', '1996', '1997', '1998', '1999',
            '2000', '2001', '2002', '2003', '2004', '2005', '2006', '2007', '2008', '2009',
            '2010', '2011', '2012', '2013', '2014', '2015', '2016', '2017', '2018', '2019',
            '2020', '2021', '2022', '2023', '2024',
            # Family
            'mommy', 'daddy', 'mom', 'dad', 'sister', 'brother', 'family',
            'parents', 'grandma', 'grandpa', 'uncle', 'aunt', 'cousin', 'nephew', 'niece',
            # Simple patterns
            'loveyou', 'iloveyou', 'love123', 'iloveyou1', 'loveyou2',
            'hateyou', 'fuckyou', 'goodbye', 'hello', 'helloworld',
            # Shortcuts
            'root', 'toor', 'pass', 'test', 'temp', 'default', 'changeme',
            'keepout', 'masterkey', 'qwerty123', 'asdf1234', 'zxcv1234',
            '1qaz1234', '2wsx1234', 'passw0rd1', 'passw0rd12',
            # Special char + base
            'pass!', 'pass@', 'pass#', 'pass$', 'pass%', 'pass^', 'pass&', 'pass*',
            'test!', 'test@', 'test#', 'test$',
            'admin!', 'admin@', 'root!', 'root@', 'user!', 'user@',
            # Popular words
            'letmein', 'login', 'admin', 'root', 'user', 'guest', 'master',
            'secret', 'super', 'welcome', 'hello', 'world', 'blue', 'black',
            'white', 'green', 'red', 'yellow', 'pink', 'silver', 'golden',
        ]
        
        # Check minimum length
        if len(password) < 8:
            print("⚠️  Password too short (minimum 8 characters)")
            return False
        
        # Check against weak password blacklist
        if password.lower() in weak_passwords:
            print("⚠️  Password is too common (weak password detected)")
            return False
        
        # Check for repeating characters (e.g., 'aaaaaaaa')
        if len(set(password)) == 1:
            print("⚠️  Password has repeating characters")
            return False
        
        # Check for year patterns (e.g., 'password2024', 'Secure2023')
        import re
        year_pattern = re.search(r'(19|20)\d{2}$|(19|20)\d{2}', password)
        if year_pattern and len(password) < 14 and len(set(password)) < 8:
            # Only reject short passwords that are mostly simple with a year
            print("⚠️  Password contains common year pattern")
            return False
        
        # Check for common word + number patterns (e.g., 'hello123', 'user123')
        word_num_patterns = ['hello123', 'test123', 'user123', 'root123', 'admin123', 
                            'pass123', 'guest123', 'master123', 'love123', 'secret123',
                            'super123', 'welcome123', 'dragon123', 'shadow123', 'sunshine123',
                            # Common names + years
                            'john1980', 'john1990', 'john2000', 'john2020',
                            'mary1980', 'mary1990', 'mary2000', 'mary2020',
                            'james1980', 'james1990', 'robert1990', 'michael1990',
                            'daniel1980', 'david1990', 'william1990', 'richard1990',
                            'joseph1990', 'thomas1990', 'charles1990', 'christopher1990',
                            'mark1990', 'steven1990', 'paul1990', 'andrew1990',
                            'susan1990', 'jennifer1990', 'sarah1990', 'karen1990',
                            'lisa1990', 'nancy1990', 'betty1990', 'margaret1990',
                            'sandra1990', 'ashley1990', 'kimberly1990', 'emily1990',
                            'john123', 'mary123', 'james123', 'robert123', 'michael123',
                            'david123', 'william123', 'richard123', 'joseph123', 'thomas123',
                            # Word + 2-digit patterns (e.g., dragon01)
                            'dragon01', 'shadow01', 'sunshine01', 'princess01', 'butterfly01',
                            'minecraft1', 'fortnite1', 'starwars01',
                            # Word + number (generic)
                            'nike1234', 'eminem01', 'monday01', 'red12345', 'blue12345',
                            'green123', 'yellow123', 'pink123', 'black123', 'white123',
                            # Sports + number
                            'football1', 'baseball1', 'soccer1', 'basketball1',
                            # Food + number
                            'chicken1', 'pizza1', 'burger1', 'coffee1', 'pasta1',
                            # Car brands + number
                            'toyota1', 'honda1', 'ford1', 'bmw1', 'audi1',
                            # Music + number
                            'eminem1', 'drake1', 'beyonce1', 'queen1',
                            # Day + number
                            'monday1', 'tuesday1', 'wednesday1', 'thursday1', 'friday1',
                            'saturday1', 'sunday1',
                            # Month + number  
                            'january1', 'february1', 'march1', 'april1', 'may1', 'june1',
                            'july1', 'august1', 'september1', 'october1', 'november1', 'december1',
        ]
        if password.lower() in word_num_patterns:
            print("⚠️  Password is a common word with numbers")
            return False
        
        # Check if password looks like a file path
        if '/' in password or '\\' in password or password.startswith('.'):
            print("⚠️  Password cannot contain path separators")
            return False
        
        # Check for invalid characters in password
        if any(ord(c) < 32 for c in password):
            print("⚠️  Password contains invalid characters")
            return False
        
        # Check for control characters
        if any(ord(c) < 32 for c in password):
            print("⚠️  Password contains invalid characters")
            return False
        
        # Check for sequential characters (e.g., 'abcdefgh' or '12345678')
        # Only reject if password is mostly sequential (4+ chars in sequence)
        lower = password.lower()
        has_consecutive = False
        
        # Check for numeric sequences
        for i in range(len(lower) - 3):
            substr = lower[i:i+4]
            if substr.isdigit() or substr.isalpha():
                # Check if it's a sequence
                if substr in '0123456789' or substr in 'abcdefghijklmnopqrstuvwxyz':
                    has_consecutive = True
                    break
        
        # Only reject if all/nearly all characters are sequential
        if has_consecutive and len(set(lower)) < 6:
            print("⚠️  Password contains sequential characters")
            return False
        
        # Check for keyboard patterns (qwerty, asdf, zxcz, etc.)
        keyboard_patterns = ['qwerty', 'asdf', 'zxcv', 'qazwsx', 'wsxedc', 'edcrfv', 'rfvtgb', 'tgbyhn', 'yhnujm', 'ujmik', 'ikolp', 'pl;/[']
        kp_lower = lower
        for pattern in keyboard_patterns:
            if pattern in kp_lower or pattern[::-1] in kp_lower:
                print("⚠️  Password contains keyboard pattern")
                return False
        
        # Calculate entropy with PENALTY for character diversity
        charset_size = 0
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?/~`' for c in password)
        
        if has_lower: charset_size += 26
        if has_upper: charset_size += 26
        if has_digit: charset_size += 10
        if has_special: charset_size += 32
        
        # Require at least 2 character types
        char_types = sum([has_lower, has_upper, has_digit, has_special])
        if char_types < 2:
            print("⚠️  Password must contain at least 2 character types")
            return False
        
        # Require minimum unique characters (more unique = harder to guess)
        unique_chars = len(set(password))
        # For passwords < 12 chars, require more unique chars
        min_unique = 6 if len(password) < 12 else 4
        if unique_chars < min_unique:
            print(f"⚠️  Password must have at least {min_unique} unique characters")
            return False
        
        if charset_size > 0:
            entropy = len(password) * math.log2(charset_size)
            # Add bonus for unique characters
            entropy += unique_chars * 2
            
            if entropy < 40:  # Increased threshold
                print(f"⚠️  Password entropy too low ({entropy:.1f} bits, minimum 40)")
                return False
        
        return True
    
    def encrypt_file(self, input_path: str, output_path: str, password: str, 
                    bind_policy: str = "machine", note: str = ""):
        """Encrypt file to .cortex format"""
        
        # Validate password strength BEFORE encryption
        if not self.validate_password_strength(password):
            raise ValueError("Password does not meet minimum strength requirements")
        
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
        
        # Check rate limiting before proceeding
        if not self._check_rate_limit(input_path):
            return -3
        
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
            
            # Record successful decryption - clear rate limit
            self._record_success(input_path)
            
            # Clear sensitive data
            key = b'\x00' * len(key)
            
            return 0
            
        except Exception as e:
            print(f"Error: Authentication/decryption failed - {str(e)}")
            # Record failed attempt
            self._record_failed_attempt(input_path)
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
