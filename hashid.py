import re

def identify_hash(hash_string):
    hash_types = {
        'MD5': r'^[a-fA-F0-9]{32}$',
        'SHA-1': r'^[a-fA-F0-9]{40}$',
        'SHA-224': r'^[a-fA-F0-9]{56}$',
        'SHA-256': r'^[a-fA-F0-9]{64}$',
        'SHA-384': r'^[a-fA-F0-9]{96}$',
        'SHA-512': r'^[a-fA-F0-9]{128}$',
        'SHA3-224': r'^[a-fA-F0-9]{56}$',
        'SHA3-256': r'^[a-fA-F0-9]{64}$',
        'SHA3-384': r'^[a-fA-F0-9]{96}$',
        'SHA3-512': r'^[a-fA-F0-9]{128}$',
        'Blowfish': r'^\$2[ayb]\$.{56}$',
        'bcrypt': r'^\$2[ayb]\$.{56}$',
        'SHA-1 (Unix)': r'^\{SHA\}[a-zA-Z0-9+/]{27}=$',
        'NTLM': r'^[a-fA-F0-9]{32}$',
        'LM': r'^[a-fA-F0-9]{32}$',
        'MySQL': r'^[a-fA-F0-9]{16}$',
        'MySQL5': r'^\*[a-fA-F0-9]{40}$',
        'MySQL 160bit': r'^[a-fA-F0-9]{40}$',
        'Cisco-IOS(MD5)': r'^[a-fA-F0-9]{16}$',
        'Cisco-IOS(SHA-256)': r'^[a-fA-F0-9]{64}$',
        'Juniper': r'^[a-fA-F0-9]{32}$',
        'GOST R 34.11-94': r'^[a-fA-F0-9]{64}$',
        'RipeMD-160': r'^[a-fA-F0-9]{40}$',
        'Whirlpool': r'^[a-fA-F0-9]{128}$'
    }
    
    for hash_type, pattern in hash_types.items():
        if re.match(pattern, hash_string):
            return hash_type
    return 'Unknown hash type'

h = input("[#]Provide the hash to analyze: ")
hash_type = identify_hash(h)
print(f'[#]Hash: {h}\nType: {hash_type}\n')
