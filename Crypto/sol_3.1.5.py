import argparse
from Crypto.Util.number import long_to_bytes, bytes_to_long

if __name__ == '__main__':
  """ python3 sol_3.1.5.py 3.1.5_RSA_ciphertext.hex 3.1.5_RSA_private_key.hex 3.1.5_RSA_modulo.hex sol_3.1.5.hex """

  parser = argparse.ArgumentParser(description="sol_3.1.5.py")
  parser.add_argument('cipher_text_file', type=str, help='The ciphertext file')
  parser.add_argument('key_file', type=str, help='The private key file')
  parser.add_argument('modulo_file', type=str, help='The RSA modulo file')
  parser.add_argument('output_file', type=str, help='The output file')
  args = parser.parse_args()

  with open(args.cipher_text_file, 'r') as cipher_text_file:
    cipher_text = bytes_to_long(bytes.fromhex(cipher_text_file.read().strip()))

  with open(args.key_file, 'r') as key_file:
    private_key = bytes_to_long(bytes.fromhex(key_file.read().strip()))

  with open(args.modulo_file, 'r') as modulo_file:
    modulo = bytes_to_long(bytes.fromhex(modulo_file.read().strip()))
  
  plain_text = pow(cipher_text, private_key, modulo)

  with open(args.output_file, 'w') as f:
    f.write(long_to_bytes(plain_text).hex())
