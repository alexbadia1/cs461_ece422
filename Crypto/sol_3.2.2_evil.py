#!/usr/bin/env python3
# -*- coding: latin-1 -*-
blob = """     "��`j�gQ,�}yf�nG���K�{Y��<ܼ8���Dt��v)
�6ZL�%^ys���u�s��3��N�8tPt�{��<2UJN1�-��{r�Z���Iڟ�4��њx����a���y"""
from hashlib import sha256
print(sha256(blob.encode()).hexdigest())
if sha256(blob.encode()).hexdigest() == "9994092e4228e33b093006beeb258c6a7f01ddd281cb231d5b7bffb01bd6c5ec":
  print("I come in peace.")
else:
  print("Prepare to be destroyed!")
