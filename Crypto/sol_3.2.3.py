import urllib.request, urllib.error


def get_status(blocks):
  ciphertext = ''.join(b.hex() for b in blocks)
  url = 'http://192.17.97.88:8080/mp3/abadia2/?' + ciphertext
  try:
    resp = urllib.request.urlopen(url)
    return True
  except urllib.error.HTTPError as e:
    if e.code == 404:
      print(url)
      print('code: ', e, 'read: ',  e.read().decode())
    return e.code == 404


def encode_c_prime_block_padding(c_prime_block, prev_block, plaintext_block, start):
  """
  Because the server expects the following padding schema {0x10, 0x0f, ..., 0x01}. 
  Can't continue to decrypt the 15th, 14th, ..., 1st bytes without encoding padding.

  Remember P2 = C1 XOR D2, where D2 is the decryption of C2. The goal is to get 
  P2 = padding_value, which can be achieved through XOR maniuplation:

    C1'' = C1 xor (C1 xor [C1' xor 0x10]) xor padding_value
         = [C1' xor 0x10] xor padding_value
         = C2 xor padding_value
    
    P2   = C1'' xor C2
         = (C2 xor padding_value) xor C2
         = padding_value
  
  Based padding schema, the padding variable is the inverse of the byte position. 
  """
  for byte_pos, padding_value in zip(reversed(range(start, 16)), range(start, 16)):
    c_prime_block[byte_pos] = prev_block[byte_pos] ^ plaintext_block[byte_pos] ^ padding_value


def decrypt(blocks, current_block_index):

  curr_block = blocks[current_block_index]
  prev_block = blocks[current_block_index - 1]

  block_size = len(curr_block)

  c_prime_block = bytearray(block_size)
  plaintext_block = bytearray(block_size)

  for byte_pos in reversed(range(block_size)):

    for j in range(256):
      
      c_prime_block[byte_pos] = j

      if get_status([c_prime_block, curr_block]):
        plaintext_block[byte_pos] = 0x10 ^ prev_block[byte_pos] ^ c_prime_block[byte_pos]

        if byte_pos > 0:
          encode_c_prime_block_padding(c_prime_block, prev_block, plaintext_block, byte_pos)
        
        break
  
  return plaintext_block
  

if __name__ == '__main__':
  """ python3 sol_3.2.3.py """

  with open('3.2.3_ciphertext.hex') as ciphertext_file:
    ciphertext = ciphertext_file.read().strip()

  ciphertext_blocks = [bytearray(bytes.fromhex(ciphertext[i:i + 32])) for i in range(0, len(ciphertext), 32)]

  decoded_blocks = []
  for i in reversed(range(len(ciphertext_blocks))):
    decoded_blocks.append(decrypt(ciphertext_blocks, i))
  
  plaintext = bytearray()
  for decoded_block in reversed(decoded_blocks[:-1]):
    plaintext += decoded_block
  
  print(plaintext)

  with open('sol_3.2.3.txt', 'wb') as output:
    output.write(plaintext)
