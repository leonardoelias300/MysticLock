This Python-based tool allows users to securely encrypt and decrypt .txt files and messages using a custom hybrid encryption mechanism. It leverages technologies such as SHA-256, Base64, and Fernet, while applying an obfuscation layer that hides the type of cryptography used — making it readable only by this software.

🔐 Features:

Encrypt and decrypt files or messages

Obfuscates the cryptographic method to avoid reverse engineering

User-defined seed/encryption key/passphrase

Minimal dependencies, easy to use, and secure by design

⚠️ Note: Only this software can decrypt the content, as the structure and method are uniquely implemented and obfuscated.

📦 Requirements

To run MysticLock, you'll need the following Python packages:

cryptography

reedsolo

Install them via pip:

pip install cryptography reedsolo
or
pip install -r requirements.txt
