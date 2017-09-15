# unnamed security

List of security related things that are important to know.

  - Custom certificate validation.
    Reason behind this is because we can't expect every
    server owner to own a domain and know how to get a CA
    to sign their certificate. It defeats simplicity.
    Instead, we validate a the certificate's public key using
    a hash the server owner is expected to securely share.

# E2E security

The protocol is designed to accept non-UTF bytes,
so it's possible for the client to E2E encrypt data.  
Here's how the official client (will) handle E2E encryption:

  - Details  
    AES 256-bit CBC encrypts the message with a random key and IV.
    RSA 3072-bit encrypts the AES key and IV.
  - Key exchange
    - User #1 generates a public and private key.
    - User #1 shares this key with User #2 *somehow* manually.
    - User #2 also generates a public and private key.
    - User #2 shares this key with User #1 encrypted with the public key.
    - Selected messages to User #2 are encrypted with User #2's public key.
    - Selected messages to User #1 are encrypted with User #1's public key.
