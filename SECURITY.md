# unnamed security

List of security related things that are important to know.

  - Does not use SSL
    Reason behind this is because we can't expect every
    server owner to own a domain and know how to
    sign a certificate. It defeats simplicity.
    Instead, we (will) do the following:
    - The server owner gets a public and private key.
    - He/She shares this key with all users of the server securely.
    - The user also gets a public and private key (automatically).
    - He/She shares this key with the server encrypted (automatically).
    - All connections to the server are encrypted with the public key and decrypted with the server's private key.
    - All connections to the users are encrypted with the public key and decrypted with the user's private key.
