import re
import os
import sys

# Ensure the parent directory is in sys.path for direct script execution
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

# Import functions and DB_FILE from your database_connector (DB_FILE is needed for the print statement)
from src.discovery_agent.database_connector import save_crypto_asset, init_db, DB_FILE

def assess_risk(crypto_value_string):
    """
    This is where your AI agent begins its 'thinking'.
    Simple, rule-based logic for now, reflecting a nascent but powerful intelligence.
    """
    crypto_value_string_lower = crypto_value_string.lower()

    if "kyber" in crypto_value_string_lower or "dilithium" in crypto_value_string_lower:
        return "PQC Compliant", 20 # Low risk, current best practice
    elif "rsa-1024" in crypto_value_string_lower or "sha-1" in crypto_value_string_lower or "old_rsa_1024" in crypto_value_string_lower:
        return "Critically Vulnerable", 98 # Very high risk! Easily broken today.
    elif "rsa" in crypto_value_string_lower: # General RSA (e.g., 2048-bit)
        return "Quantum Vulnerable", 80 # Not broken today, but vulnerable to future quantum computers
    elif "aes" in crypto_value_string_lower and "gcm" in crypto_value_string_lower:
        return "Active & Strong (Classical)", 30 # Good classical symmetric encryption
    elif "sslproto" in crypto_value_string_lower and ("ssl" in crypto_value_string_lower or "tls" not in crypto_value_string_lower):
        return "Potentially Deprecated TLS Protocol", 70 # Could indicate old TLS versions like SSLv3/TLS1.0/1.1
    elif "ecdhe" in crypto_value_string_lower:
        return "Classical ECC (Good)", 40 # Good classical key exchange
    elif "openssl_0.9.8" in crypto_value_string_lower:
        return "Outdated Library Vulnerability", 90 # High risk due to known bugs

    return "Unknown/Standard", 50 # Default or less critical, requires further review

def scan_file_for_crypto_insights(filepath):
    """
    The AI agent's 'eyes' in action. It scans a file, extracts cryptographic patterns,
    assesses their risk, and records them in its memory (SQLite database).
    """
    print(f"🔍 AI agent scanning file: {filepath}")
    try:
        with open(filepath, 'r') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"❌ Error: File not found at {filepath}. AI skipping scan.")
        return []

    discovered_assets = []

    # Define the patterns for the AI's vision
    # Each tuple: (display_type_prefix, regex_pattern, category_for_db)
    patterns_to_scan = [
        # File Paths (often indicate key/cert locations)
        ("CertFile", r'(SSLCertificateFile|LEGACY_APP_CERT)\s*(.*)', "Certificate Path"),
        ("KeyFile", r'(SSLCertificateKeyFile|DB_ENCRYPTION_KEY_PATH|SSH_HOST_KEY)\s*(.*)', "Key Path"),

        # Algorithm Identifiers
        ("PQC_ENCRYPTION_ID", r'PQC_ENCRYPTION_KEY_ID=(.*)', "PQC Key ID"),
        ("PQC_SIGNING_ID", r'PQC_SIGNING_KEY_ID=(.*)', "PQC Signature ID"),
        ("DB_ENCRYPTION_ALGO", r'DB_ENCRYPTION_ALGORITHM=(.*)', "Database Encryption"),
        ("LegacyCryptoLib", r'LEGACY_APP_CRYPTO_LIB=(.*)', "Crypto Library"),

        # Protocols & Ciphers
        ("SSLProtocol_Config", r'SSLProtocol\s*(.*)', "TLS/SSL Protocol"),
        ("SSLCipherSuite_Config", r'SSLCipherSuite\s*(.*)', "Cipher Suite Configuration"),
    ]

    for display_type_prefix, pattern_str, category_for_db in patterns_to_scan:
        matches = re.findall(pattern_str, content, re.IGNORECASE)
        for match in matches:
            if isinstance(match, tuple):
                key_name = match[0].strip()
                value = match[1].strip()
            else:
                key_name = display_type_prefix
                value = match.strip()

            status, risk_score = assess_risk(value) # Your AI's initial insight!

            asset_data = {
                'type': key_name,
                'algorithm': value,
                'location': filepath,
                'status': status,
                'owner_team': 'Discovered by AI (Review Needed)',
                'expiration_date': None,
                'metadata': {
                    'category': category_for_db,
                    'risk_score': risk_score,
                    'source_scanner': 'Veritas Quantum AI File Scanner',
                    'raw_match': value
                }
            }
            discovered_assets.append(asset_data)
            save_crypto_asset(asset_data) # AI stores its findings

    return discovered_assets

if __name__ == "__main__":
    # --- Self-test for the file_scanner.py script ---
    print("\n--- Testing the AI Agent's Vision ---")
    init_db() # Ensure database is initialized before scanning and saving

    mock_file_path = os.path.join(os.path.dirname(__file__), 'enterprise_configs', 'mock_enterprise_config.txt')

    discovered_info = scan_file_for_crypto_insights(mock_file_path)

    if discovered_info:
        print(f"\n🎉 AI Agent successfully discovered {len(discovered_info)} crypto items.")
        print(f"Witness your AI's insights in '{DB_FILE}' SQLite database!")
    else:
        print("😔 AI Agent found no items or encountered an error during scan.")
