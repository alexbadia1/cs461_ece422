import re

with open('1.2.8.txt', 'r') as i, open('ret.txt', 'w') as o:

  window = []

  for line in i:

    if len(window) > 7:
      window.pop(0)
    
    window.append(line)
    
    if re.search(r"c3\s+ret", line):
      o.write(''.join(window))
