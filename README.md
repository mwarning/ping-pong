# Network Ping Pong

Send and receive network packets. Useful for testing. 

```
Usage: ./ping-pong <listen|send> <tcp|udp> <address> [<port>]
  Example:
    On device A (IP address 192.168.1.2):
      ./ping-pong listen udp 0.0.0.0
    On Device B:
      ./ping-pong send udp 192.168.1.2
```

Note: Only UDP is supported for now :-)

License: CC0-1.0
