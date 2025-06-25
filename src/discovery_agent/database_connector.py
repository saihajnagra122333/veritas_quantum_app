import sqlite3
import uuid # To generate unique IDs for your crypto assets
import datetime # To record when assets were discovered
import json # To store flexible metadata as a JSON string

# Define the name of your SQLite database file
# This file will be created in your main 'veritas-quantum' directory
DB_FILE = 'veritas_quantum_db.db'

def connect_db():
    """
    Establishes a connection to the SQLite database.
    If the database file does not exist, it will be created.
    """
    conn = sqlite3.connect(DB_FILE)
    # This line allows you to access columns by their name (e.g., row['id'])
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """
    Initializes the database schema by creating the 'crypto_assets' table
    if it doesn't already exist.
    """
    conn = connect_db()
    cursor = conn.cursor()
    # SQL command to create the table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS crypto_assets (
            id TEXT PRIMARY KEY,           -- Unique identifier for the asset
            type TEXT NOT NULL,            -- e.g., "TLS Certificate", "Symmetric Key", "PQC Public Key"
            algorithm TEXT NOT NULL,       -- e.g., "RSA-2048", "AES-256", "Kyber768", "Dilithium3"
            location TEXT NOT NULL,        -- Where it was found (e.g., file path, cloud bucket)
            status TEXT NOT NULL,          -- AI agent's initial assessment (e.g., "Quantum Vulnerable", "PQC Compliant")
            owner_team TEXT,               -- Which team owns it (optional)
            expiration_date TEXT,          -- If applicable (e.g., "2025-12-31" for certificates)
            discovery_timestamp TEXT NOT NULL, -- When the AI agent discovered it
            metadata TEXT                  -- Flexible field for extra details (stored as JSON string)
        )
    ''')
    conn.commit() # Save changes to the database
    conn.close() # Close the connection
    print(f"✅ SQLite database '{DB_FILE}' initialized and 'crypto_assets' table ensured.")

def save_crypto_asset(asset_data):
    """
    Saves a discovered cryptographic asset to the SQLite 'crypto_assets' table.
    This is how your AI agent will store its findings.
    """
    conn = connect_db()
    cursor = conn.cursor()

    asset_id = str(uuid.uuid4()) # Generate a unique ID for this discovery
    # Record the current time in ISO format (standard for datetimes)
    discovery_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat() 

    # Prepare data for insertion into the SQL query
    data_to_insert = {
        'id': asset_id,
        'type': asset_data.get('type'),
        'algorithm': asset_data.get('algorithm'),
        'location': asset_data.get('location'),
        'status': asset_data.get('status'),
        'owner_team': asset_data.get('owner_team'),
        'expiration_date': asset_data.get('expiration_date'),
        'discovery_timestamp': discovery_timestamp,
        'metadata': json.dumps(asset_data.get('metadata', {})) # Convert metadata dictionary to JSON string
    }

    # SQL INSERT statement using named parameters (safer and cleaner)
    cursor.execute('''
        INSERT INTO crypto_assets (id, type, algorithm, location, status, owner_team, expiration_date, discovery_timestamp, metadata)
        VALUES (:id, :type, :algorithm, :location, :status, :owner_team, :expiration_date, :discovery_timestamp, :metadata)
    ''', data_to_insert)

    conn.commit() # Save changes
    conn.close() # Close connection
    print(f"✅ Saved crypto asset with ID: {asset_id} to SQLite.")
    return asset_id

def get_all_crypto_assets():
    """
    Retrieves all crypto assets from the database.
    Returns a list of dictionaries containing asset information.
    """
    conn = connect_db()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM crypto_assets ORDER BY discovery_timestamp DESC')
    rows = cursor.fetchall()
    
    assets = []
    for row in rows:
        asset = dict(row)
        # Parse metadata JSON back to dictionary
        if asset['metadata']:
            asset['metadata'] = json.loads(asset['metadata'])
        assets.append(asset)
    
    conn.close()
    return assets

def get_crypto_assets_by_status(status):
    """
    Retrieves crypto assets filtered by their quantum vulnerability status.
    """
    conn = connect_db()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM crypto_assets WHERE status = ? ORDER BY discovery_timestamp DESC', (status,))
    rows = cursor.fetchall()
    
    assets = []
    for row in rows:
        asset = dict(row)
        if asset['metadata']:
            asset['metadata'] = json.loads(asset['metadata'])
        assets.append(asset)
    
    conn.close()
    return assets

if __name__ == "__main__":
    # --- Self-test for the database_connector.py script ---
    print("--- Running database_connector.py self-test ---")
    init_db() # Ensure the table is created before trying to save data

    # Example 1: Simulate a discovered Quantum Vulnerable TLS Certificate
    # This is the kind of insight your AI agent will generate!
    dummy_data_1 = {
        'type': 'TLS Certificate',
        'algorithm': 'RSA-2048',
        'location': 'Local Path: /etc/ssl/legacy_web_cert.pem',
        'status': 'Quantum Vulnerable', # AI's initial assessment
        'owner_team': 'Marketing Website',
        'expiration_date': '2025-12-31',
        'metadata': {
            'issuer': 'Self-Signed Corp CA',
            'common_name': 'old.example.com',
            'compliance_risk': 'High (NIST PQC)',
            'source_scanner_test': 'Veritas Quantum SQLite Test'
        }
    }
    save_crypto_asset(dummy_data_1)

    # Example 2: Simulate a discovered PQC Compliant Key
    dummy_data_2 = {
        'type': 'PQC Public Key',
        'algorithm': 'Kyber768',
        'location': 'Local App: /app/config/pqc_api_key.json',
        'status': 'PQC Compliant', # AI's initial assessment
        'owner_team': 'API Gateway Team',
        'expiration_date': '2030-01-01',
        'metadata': {
            'purpose': 'API Key Exchange',
            'quantum_safe': True,
            'source_scanner_test': 'Veritas Quantum SQLite Test'
        }
    }
    save_crypto_asset(dummy_data_2)

    # Example 3: Simulate a discovered Symmetric Key
    dummy_data_3 = {
        'type': 'Symmetric Key',
        'algorithm': 'AES-256',
        'location': 'Cloud Storage: s3://secure-bucket/encryption_keys/',
        'status': 'Quantum Vulnerable',
        'owner_team': 'Data Encryption Team',
        'expiration_date': '2024-06-30',
        'metadata': {
            'key_rotation': 'Monthly',
            'encryption_mode': 'GCM',
            'compliance_risk': 'Medium (Grover\'s Algorithm)',
            'source_scanner_test': 'Veritas Quantum SQLite Test'
        }
    }
    save_crypto_asset(dummy_data_3)

    print(f"\n💡 SQLite database '{DB_FILE}' updated.")
    print("You can verify the data by opening the 'veritas_quantum_db.db' file")
    print("in your project folder using a free SQLite browser like 'DB Browser for SQLite'.")
    
    # Display all saved assets
    print("\n📊 Current crypto assets in database:")
    all_assets = get_all_crypto_assets()
    for asset in all_assets:
        print(f"  - {asset['type']} ({asset['algorithm']}) - {asset['status']}")
        print(f"    Location: {asset['location']}")
        print(f"    Team: {asset['owner_team']}")
        print()
