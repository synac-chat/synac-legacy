# unnamed security

List of security related things that are important to know.

  - Does not use SSL  
    Reason behind this is because we can't expect every
    server owner to own a domain and know how to
    sign a certificate. It defeats simplicity.
  - Details  
    AES 256-bit CBC encrypts the message with a random key and IV.
    RSA 3072-bit encrypts the AES key and IV.
  - Key exchange
    - The server owner gets a public and private key.
    - He/She shares this key with all users of the server securely.
    - The user also gets a public and private key (automatically).
    - He/She shares this key with the server encrypted (automatically).
    - All connections to the server are encrypted with the public key and decrypted with the server's private key.
    - All connections to the users are encrypted with the public key and decrypted with the user's private key.
