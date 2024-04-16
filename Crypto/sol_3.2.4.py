import math
import hashlib
import os
import subprocess

from Crypto.Util import number
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding

import sympy
from sympy import symbols, Eq, solve
from sympy.ntheory.modular import solve_congruence

from mp3_certbuilder import make_cert, make_privkey

netid = 'abadia2'
E = 65537

class CertificateCollision:

  def __init__(self, load_root_cert: bool):
    self.load_root_cert = load_root_cert
    self.netid: str = 'abadia2'
    self.outfile: str = 'abadia2.cer'
    
    self.root_cert = None
    self.root_cert_tbs_bytes: bytes = None

    # TODO: Modulus byte start pos
    self.modulus_start_byte_position = 256

    self.blob_a: bytes = None
    self.blob_b: bytes = None

    self.prime_number_bit_size: int = 500
    self.n1: int = None
    self.n2: int = None
    self.p1: int = None
    self.p2: int = None
    self.q1: int = None
    self.q2: int = None

  def create_root_cert(self) -> None:
    """ 
    BEFORE RUNNING: Modify psuedonym field so the first byte of the Modulus 
                    value begins on a *multiple* of 64 (0-index) inside 
                    self.root_cert_tbs_bytes.
    """

    if self.load_root_cert:
      # DO NOT regenerate root cert
      return
    
    # Generate root cert
    p: int = number.getPrime(1024)
    q: int = number.getPrime(1024)
    privkey, pubkey = make_privkey(p, q)
    self.root_cert = make_cert(netid, pubkey)
    self.root_cert_tbs_bytes = self.root_cert.tbs_certificate_bytes
    print('[create_root_cert] md5 of cert.tbs_certificate_bytes:', hashlib.md5(self.root_cert.tbs_certificate_bytes).hexdigest())

    # Save to disk for fastcol
    with open(self.outfile, 'wb') as i, open('sol_3.2.4_prefix', 'wb') as o:
      o.write(self.root_cert_tbs_bytes[:self.modulus_start_byte_position])
    
    # Save to disk for analysis
    with open(self.outfile, 'wb') as f:
        f.write(self.root_cert.public_bytes(Encoding.DER))
    print('[create_root_cert] try the following command: openssl x509 -in %s -inform der -text -noout' % self.outfile)

    with open(f'{self.outfile}.tbs', 'wb') as f:
      f.write(self.root_cert_tbs_bytes)
    
    with open(f'{self.outfile}.serial', 'w') as f:
      # Ignored 0x prefix
      f.write(hex(self.root_cert.serial_number)[2:])
  
  def create_twin_certs(self) -> None:
    """ 
    Create two certificates with MD5 collisions. 
    
    Note: The fastcol collision blob, added to the prefix, is the start of the
          Modulus. Make sure the collision blob's leading bit is 0, so the
          Modulus will be 2047 bits after Lenstra's algorithm is used to fill
          in the remaining 1024 bits.
    """

    if self.load_root_cert:
      # DO NOT regenerate fastcol collisions
      return

    while True:

      a, b = False, False

      subprocess.run(['fastcoll', '-p', 'sol_3.2.4_prefix', '-o', 'sol_3.2.4_collisionA', 'sol_3.2.4_collisionB'])

      with open('sol_3.2.4_collisionA', 'rb') as collision_a, open('sol_3.2.4_collisionB', 'rb') as collision_b:
        collision_a.seek(self.modulus_start_byte_position)
        collision_b.seek(self.modulus_start_byte_position)

        if (ord(collision_a.read(1)) >> 6) & 3 == 1 and (ord(collision_b.read(1)) >> 6) & 3 == 1:
          collision_a.seek(self.modulus_start_byte_position)
          collision_b.seek(self.modulus_start_byte_position)
          self.blob_a = collision_a.read()
          self.blob_b = collision_b.read()

          assert int(self.blob_a.hex(), 16).bit_length() == 1023
          assert int(self.blob_b.hex(), 16).bit_length() == 1023

          with open('sol_3.2.4_b1', 'wb') as b1, open('sol_3.2.4_b2', 'wb') as b2:
            b1.write(self.blob_a)
            b2.write(self.blob_b)

          return
  
  def random_primes(self):
    p1 , p2 = -1, -1
    while p1 == p2:
      p1 = number.getPrime(self.prime_number_bit_size)
      p2 = number.getPrime(self.prime_number_bit_size)
    return p1, p2

  def generate_rsa_moduli(self):

    with open('sol_3.2.4_b1', 'rb') as b1, open('sol_3.2.4_b2', 'rb') as b2:
      self.blob_a = b1.read()
      self.blob_b = b2.read()

    b1 = int(self.blob_a.hex(), 16)
    b2 = int(self.blob_b.hex(), 16)

    ex = 2**1024
    b1_prime = b1 * ex
    b2_prime = b2 * ex

    assert b1_prime.bit_length() == 2047
    assert b2_prime.bit_length() == 2047
    assert(b1_prime % ex == 0)
    assert(b2_prime % ex == 0)

    while True:

      p1, p2 = self.random_primes()

      p_prime = p1 * p2

      print(f"\nModuli random primes:\n{p1}\n{p2}")

      if math.gcd(E, p1 - 1) != 1 or math.gcd(E, p2 - 1) != 1:
        continue
      
      # Compute b0 between 0 and p1 * p2 such that p1 | ((b1 * 2**1024) + b0) and p2 | ((b2 * (2**1024) + b0) (by the Chinese Remainder Theorem)
      congruence1 = -b1_prime % p1
      congruence2 = -b2_prime % p2
      
      b0 = solve_congruence((congruence1, p1), (congruence2, p2))[0]

      if b0 < 0 or b0 > p_prime or ((b1_prime + b0) % p1 != 0) or ((b2_prime + b0) % p2 != 0):
        print('INVALID B0 Found!')
        continue
      else:
        print('Valid B0:')
        print(b0)
      
      k = -1
      b = 0

      # When k has become so large that b ≥ 2**1024, restart with new random primes p1, p2
      while b.bit_length() < 1024:

        # Let k run through 0, 1, 2, . . ., and for each k compute b = b0 + kp1p2
        k += 1
        b = b0 + (k * p_prime)

        # check whether both q1 = (b1 * 2**1024 + b)/p1 and q2 = (b2 * 2**1024 + b)/p2 are primes, 
        # and whether e is coprime to both q1 − 1 and q2 − 1
        q1 = (b1_prime + b) // p1
        q2 = (b2_prime + b) // p2

        if math.gcd(E, q1 - 1) == 1 and math.gcd(E, q2 - 1) == 1 and number.isPrime(q1) and number.isPrime(q2):
          # when primes q1 and q2 have been found, stop, and output 
          #   n1 = b1 2**1024 + b and 
          #   n2 = b2 2**1024 + b 
          #   (as well as p1, p2, q1, q2).
          n1 = b1_prime + b
          n2 = b2_prime + b

          print('K:')
          print(k)
          print('\n\n\nModuli Done!\n\n\n')

          self.n1 = n1
          self.n2 = n2
          self.p1 = p1
          self.p2 = p2
          self.q1 = q1
          self.q2 = q2

          with open('sol_3.2.4_n1', 'w') as n1_file:
            n1_file.write(str(self.n1))
          with open('sol_3.2.4_n2', 'w') as n2_file:
            n2_file.write(str(self.n2))
          with open('sol_3.2.4_p1', 'w') as p1_file:
            p1_file.write(str(self.p1))
          with open('sol_3.2.4_p2', 'w') as p2_file:
            p2_file.write(str(self.p2))
          with open('sol_3.2.4_q1', 'w') as q1_file:
            q1_file.write(str(self.q1))
          with open('sol_3.2.4_q2', 'w') as q2_file:
            q2_file.write(str(self.q2))
          
          return

  def signed_twins(self):

    #
    # Load data from disk
    #

    with open('sol_3.2.4_b1', 'rb') as b1_file, open('sol_3.2.4_b2', 'rb') as b2_file:
      self.blob_a = b1_file.read()
      self.blob_b = b2_file.read()
    with open('sol_3.2.4_n1', 'r') as n1_file, open('sol_3.2.4_n2', 'r') as n2_file:
      self.n1 = int(n1_file.read())
      self.n2 = int(n2_file.read())
    
    #
    # Moduli
    #

    assert int(self.blob_a.hex(), 16).bit_length() == 1023
    assert int(self.blob_b.hex(), 16).bit_length() == 1023

    assert self.n1.bit_length() == 2047
    assert self.n2.bit_length() == 2047

    n1_hex: str = hex(self.n1)[2:]
    n2_hex: str = hex(self.n2)[2:]
    
    assert self.blob_a.hex() == n1_hex[:256]  # Remove 0x prefix
    assert self.blob_b.hex() == n2_hex[:256]  # Remove 0x prefix

    with open('sol_3.2.4_p1', 'r') as p1_file, open('sol_3.2.4_q1', 'r') as q1_file:
      self.p1 = int(p1_file.read())
      self.q1 = int(q1_file.read())
    
    with open('sol_3.2.4_p2', 'r') as p2_file, open('sol_3.2.4_q2', 'r') as q2_file:
      self.p2 = int(p2_file.read())
      self.q2 = int(q2_file.read())
    
    with open('sol_3.2.4_factorsA.hex', 'w') as factorsA:
      factorsA.write(hex(self.p1)[2:])
      factorsA.write('\n')
      factorsA.write(hex(self.q1)[2:])
    
    with open('sol_3.2.4_factorsB.hex', 'w') as factorsB:
      factorsB.write(hex(self.p2)[2:])
      factorsB.write('\n')
      factorsB.write(hex(self.q2)[2:])

    #
    # Signature
    #
    import hashlib
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend

    with open(f'{self.outfile}.serial', 'r') as f:
      serial_int = int(f.read(), 16)

    # pub_a = rsa.RSAPublicNumbers(E, self.n1)
    # pubkey_a = pub_a.public_key(default_backend())
    _, pubkey_a = make_privkey(self.p1, self.q1)
    cert_a = make_cert(netid, pubkey_a, serial=serial_int)
    print('[Cert A] md5 hash of cert_b.tbs_certificate_bytes: ', hashlib.md5(cert_a.tbs_certificate_bytes).hexdigest())

    with open('sol_3.2.4_certA.cer', 'wb') as f:
      f.write(cert_a.public_bytes(Encoding.DER))
    print('[Cert A] try the following command: openssl x509 -in sol_3.2.4_certA.cer -inform der -text -noout')
    
    # pub_b = rsa.RSAPublicNumbers(E, self.n2)
    # pubkey_b = pub_b.public_key(default_backend())
    _, pubkey_b = make_privkey(self.p2, self.q2)
    cert_b = make_cert(netid, pubkey_b, serial=serial_int)
    print('[Cert B] md5 hash of cert_b.tbs_certificate_bytes: ', hashlib.md5(cert_b.tbs_certificate_bytes).hexdigest())
    
    with open('sol_3.2.4_certB.cer', 'wb') as f:
      f.write(cert_b.public_bytes(Encoding.DER))
    print('[Cert B] try the following command: openssl x509 -in sol_3.2.4_certB.cer -inform der -text -noout')
  
if __name__ == '__main__':

  cc = CertificateCollision(load_root_cert=True)

  """
  Usage: Super hackish commenting and un-commenting code...

  1. Single Pass

    1. Set load_root_cert = False
    2. Run all sequentially:
      # 1. Root template
      cc.create_root_cert()
      # 2. Compare Hashes: openssl dgst -md5 sol_3.2.4_collisionA sol_3.2.4_collisionB
      cc.create_twin_certs()
      # 3. Moduli
      cc.generate_rsa_moduli()
      # 4. Generate collisioneed certs
      cc.signed_twins()

  2. Poor Man's Jupyter Notebook Style
    1. Set load_root_cert = False
    2. Run cc.create_root_cert()
    3. Run cc.create_twin_certs()
    4. Set load_root_cert = True
    5. Freely run and re-run 3 followed by 4 as many times as you want.
  """

  cc.signed_twins()
