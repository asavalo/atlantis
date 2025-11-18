from pwn import *

PORT = 8080
HOST = "127.0.0.1"

# s = remote(HOST, PORT)

# execute_data = b"C" * 8

# data = p64(len(execute_data)) + execute_data

# s.send(data)

# s.recvuntil(b"SYMEXECUTEDONE")


while True:
    for i in range(5):
        s = remote(HOST, PORT)

        execute_data = chr(0x30 + i) * 8
        execute_data = execute_data.encode()

        data = p64(len(execute_data)) + execute_data

        s.send(data)
        s.recvuntil(b"SYMEXECUTEDONE")
        
        s.close()
