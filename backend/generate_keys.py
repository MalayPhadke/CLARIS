"""
Generate secure keys for Vigilink backend.
Run this script to create JWT and encryption keys for production use.
"""
import secrets
import base64

def generate_keys():
    """Generate secure random keys for JWT and encryption."""
    
    print("=" * 70)
    print("VIGILINK SECURITY KEY GENERATOR")
    print("=" * 70)
    print()
    
    # Generate JWT secret (32 bytes = 256 bits)
    jwt_secret = secrets.token_urlsafe(32)
    print("JWT_SECRET_KEY:")
    print(jwt_secret)
    print()
    
    # Generate encryption master key (32 bytes for AES-256)
    encryption_key = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
    print("ENCRYPTION_MASTER_KEY:")
    print(encryption_key)
    print()
    
    print("=" * 70)
    print("INSTRUCTIONS:")
    print("=" * 70)
    print()
    print("1. Copy these keys to your .env file:")
    print()
    print(f"   JWT_SECRET_KEY={jwt_secret}")
    print(f"   ENCRYPTION_MASTER_KEY={encryption_key}")
    print()
    print("2. NEVER commit .env file to version control")
    print("3. Store production keys in secure secret manager")
    print("4. Rotate keys every 90 days for security")
    print()
    print("⚠️  WARNING: Keep these keys secret! Anyone with these")
    print("   keys can decrypt stored passwords and forge JWT tokens.")
    print()

if __name__ == "__main__":
    generate_keys()
