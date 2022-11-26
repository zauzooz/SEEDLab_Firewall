#
import socket
from time import sleep
udpSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

for i in range(0,3):
    str = f'hello{i}'

    udpSocket.sendto(bytes(str, 'utf-8'),("10.9.0.11",8080))
    sleep(1)