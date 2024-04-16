import argparse
from Crypto.Cipher import AES

if __name__ == '__main__':
  """ python3 sol_3.1.3.py 3.1.3_aes_ciphertext.hex 3.1.3_aes_key.hex  3.1.3_aes_iv.hex sol_3.1.3.txt """

  parser = argparse.ArgumentParser(description="sol_3.1.3.py")
  parser.add_argument('ciphertext_file', type=str, help='The ciphertext file')
  parser.add_argument('key_file', type=str, help='The key file')
  parser.add_argument('iv_file', type=str, help='The initialization vector file')
  parser.add_argument('output_file', type=str, help='The output file')
  args = parser.parse_args()

  with open(args.ciphertext_file, 'r') as cipher_text_file:
    ciphertext = bytes.fromhex(cipher_text_file.read().strip())

  with open(args.key_file, 'r') as key_file:
    key = bytes.fromhex(key_file.read().strip())
  
  with open(args.iv_file, 'r') as iv_file:
    iv = bytes.fromhex(iv_file.read().strip())
  
  cipher = AES.new(key, AES.MODE_CBC, iv=iv)

  decrypted = cipher.decrypt(ciphertext)
  plain_text = decrypted.rstrip(b' ')

  with open(args.output_file, 'w') as output_file:
    output_file.write(plain_text.decode())
