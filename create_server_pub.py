from cryptography.hazmat.primitives import serialization
import sys, os

priv_path = "server_private_key.pem"
if not os.path.exists(priv_path):
    print("Private key not found:", priv_path)
    sys.exit(1)

with open(priv_path, "rb") as f:
    priv = serialization.load_pem_private_key(f.read(), password=None)
pub = priv.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
with open("server_public_key.pem", "wb") as f:
    f.write(pub)
print("Wrote server_public_key.pem")
