import argparse
from urllib.parse import parse_qs, quote

from pymd5 import md5, padding


if __name__ == '__main__':
  """ python3 sol_3.2.1.py 3.2.1_query.txt 3.2.1_command3.txt sol_3.2.1.txt """

  parser = argparse.ArgumentParser(description="sol_3.2.1.py")
  parser.add_argument('query_file', type=str, help='The query file')
  parser.add_argument('command3_file', type=str, help='The command3 file')
  parser.add_argument('output_file', type=str, help='The output file')
  args = parser.parse_args()

  with open(args.query_file, 'r') as query_file:
    query = query_file.read().strip()

  with open(args.command3_file, 'r') as command3_file:
    command3 = command3_file.read().strip()
  
  pqs = parse_qs(query)
  token = pqs['token'][0]
  user = pqs['user'][0]
  command1 = pqs['command1'][0]
  command2 = pqs['command2'][0]
  message = f"user={user}&command1={command1}&command2={command2}"

  length_of_password = 8
  length_of_m = length_of_password + len(message)
  p = padding(length_of_m * 8)
  h = md5(state=token.encode(), count=(length_of_m + len(p)) * 8)
  h.update(command3)
  new_message = f"token={h.hexdigest()}&{message}{quote(p)}{command3}"

  with open(args.output_file, 'w') as output_file:
    output_file.write(new_message)
