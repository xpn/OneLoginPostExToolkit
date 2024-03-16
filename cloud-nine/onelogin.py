import asyncio
import sys
from lib import onelogin

async def main(key, hostname):
  ol = onelogin.OneLogin(key, hostname)
  print("[*] Sending Configuration")
  await ol.getConfiguration()
  print("[*] Sending Events")
  await ol.sendEvents()
  print("[*] Getting Users")
  await ol.getUsers()
  print("[*] Kicking off WebSocket...")
  await ol.startWebSocket()

if __name__ == "__main__":
  print("Cloud-Nine [OneLogin Edition]\n\tby: @_xpn_")

  if len(sys.argv) != 3:
    print("Usage: ./onelogin.py [API_KEY] [HOSTNAME]")
    sys.exit(1)

  key = sys.argv[1]
  hostname = sys.arg[2]

  asyncio.run(main(key, hostname))
