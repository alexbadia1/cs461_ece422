def WHA(in_str) -> str:
  mask: int = 0x3FFFFFFF
  out_hash: int = 0
  for _byte in in_str:
    intermediate_value = ((_byte ^ 0xCC) << 24) | \
      ((_byte ^ 0x33) << 16) | \
      ((_byte ^ 0xAA) << 8) | \
      (_byte ^ 0x55)
    out_hash = (out_hash & mask) + (intermediate_value & mask)
  return out_hash


if __name__ == '__main__':

  assert hex(WHA(b'Hello world!')) == hex(0x50b027cf)
  assert hex(WHA(b'I am Groot.')) == hex(0x57293cbb)

  # Order does not matter
  assert hex(WHA(b'PERIOD OF TIME NAMED FOR AN ALLOY OF COPPER  TIN  THE NEW WATERBEARING ZODIACAL EAR')) == hex(WHA(b'PERIOD OF TIME NAMED FOR AN ALLOY OF COPPER  TIN  THE NEW WATERBEARING ZODIACAL ERA'))
