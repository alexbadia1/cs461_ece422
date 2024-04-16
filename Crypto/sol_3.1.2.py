import argparse

if __name__ == '__main__':
  """ python3 sol_3.1.2.py 3.1.2_sub_ciphertext.txt 3.1.2_sub_key.txt sol_3.1.2.txt """

  parser = argparse.ArgumentParser(description="sol_3.1.2.py")
  parser.add_argument('ciphertext_file', type=str, help='The ciphertext file')
  parser.add_argument('key_file', type=str, help='The key file')
  parser.add_argument('output_file', type=str, help='The output file')
  args = parser.parse_args()

  alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

  with open(args.key_file, 'r') as key_file:
    cipher_key = [c for c in key_file.read()]
    
  cipher = {cipher_key[i]: alphabet[i] for i in range(len(alphabet))}

  print(cipher)

  with open(args.ciphertext_file, 'r') as cipher_text_file:
    cipher_text = [c for c in cipher_text_file.read()]
  
  plain_text = "".join(cipher.get(c, c) for c in cipher_text)

  with open(args.output_file, 'w') as output_file:
    output_file.write(plain_text)
