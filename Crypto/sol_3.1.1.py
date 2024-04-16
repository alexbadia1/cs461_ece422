with open("3.1.1_value.hex") as f:
  hex_string = f.read().strip()

  # Convert to decimal
  integer = int(hex_string, 16)

  # Convert to binary string
  binary = bin(integer)[2:]

  print(integer)
  print(binary)
