import argparse
from Crypto.Cipher import AES

if __name__ == '__main__':
  """ python3 sol_3.1.4.py 3.1.4_aes_weak_ciphertext.hex """

  parser = argparse.ArgumentParser(description="sol_3.1.4.py")
  parser.add_argument('cipher_text_file', type=str, help='The ciphertext file')
  args = parser.parse_args()

  with open(args.cipher_text_file, 'r') as cipher_text_file:
    known_cipher_text = bytes.fromhex(cipher_text_file.read().strip())
  
  known_iv = bytes.fromhex('0' * 32)

  for i in range(32):

    # The key is 32 bytes (256 bits) long, and its 251 most significant bits are all 0s
    test_key = (i).to_bytes(32, byteorder='big')

    # Create a new AES cipher object with the key and IV
    test_cipher = AES.new(test_key, AES.MODE_CBC, known_iv)

    # Decrypt the ciphertext
    decrypted = test_cipher.decrypt(known_cipher_text)
    plain_text = decrypted.rstrip(b' ')

    try:
      print(f"Key: {test_key.hex()}, Plaintext: {plain_text.decode()}")
    except:
      pass
