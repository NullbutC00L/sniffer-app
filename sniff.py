import socket, struct


HOST = socket.gethostbyname(socket.gethostname())

s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
print(HOST)
s.bind(('eth0',0))


# Include IP headers
#s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# receive all packages
#s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

# receive a package
n=1
f = open('workfile', 'w')
while(n<=400):
    print('Number ', n)
    data=s.recvfrom(65565)
    packet=data[0]
    address= data[1]
    header=struct.unpack('!BBHHHBBHBBBBBBBB', packet[:20])
    print(data)
    f.write(str(data))
    n=n+1