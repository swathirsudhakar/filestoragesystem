from Crypto.PublicKey import RSA

# Generate RSA keys (2048 bits)
key = RSA.generate(2048)

# Export the private key to a file
private_key = key.export_key()
with open('private.pem', 'wb') as f:
    f.write(private_key)

# Export the public key to a file
public_key = key.publickey().export_key()
with open('public.pem', 'wb') as f:
    f.write(public_key)

print("RSA Keys generated and saved as 'private.pem' and 'public.pem'.")

