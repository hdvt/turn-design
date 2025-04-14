## 1. Connection Establishment Data Sample

```plaintext
A. Client Socket Creation
------------------------
Socket Type: UDP
Local Address: 192.168.1.100:49152
Server Address: turn.example.com:3478
Socket Options:
  - SO_RCVBUF: 65536
  - SO_SNDBUF: 65536
  - SO_REUSEADDR: 1
  - SO_REUSEPORT: 1

B. Server Socket Creation
------------------------
Socket Type: UDP
Local Address: 192.168.1.200:3478
Client Address: 192.168.1.100:49152
Socket Options:
  - SO_RCVBUF: 65536
  - SO_SNDBUF: 65536
```

## 2. Authentication and Allocation Creation Data Sample

```plaintext
A. Initial Allocate Request
--------------------------
STUN Message:
  Message Type: Allocate (0x0003)
  Message Length: 20
  Transaction ID: 0x7f0000010000000000000000
  Attributes:
    - REQUESTED-TRANSPORT: UDP (0x11)
    - LIFETIME: 3600 seconds
    - DONT-FRAGMENT: 0x00

B. Server 401 Response
---------------------
STUN Message:
  Message Type: Allocate Error Response (0x0113)
  Message Length: 32
  Transaction ID: 0x7f0000010000000000000000
  Attributes:
    - ERROR-CODE: 401 (Unauthorized)
    - REALM: "example.com"
    - NONCE: "dcd98b7102dd2f0e8b11d0f600bfb0c093"

C. Authenticated Allocate Request
-------------------------------
STUN Message:
  Message Type: Allocate (0x0003)
  Message Length: 88
  Transaction ID: 0x7f0000010000000000000001
  Attributes:
    - REQUESTED-TRANSPORT: UDP (0x11)
    - LIFETIME: 3600 seconds
    - DONT-FRAGMENT: 0x00
    - USERNAME: "alice"
    - REALM: "example.com"
    - NONCE: "dcd98b7102dd2f0e8b11d0f600bfb0c093"
    - MESSAGE-INTEGRITY: [HMAC-SHA1 hash]

D. Server Success Response
------------------------
STUN Message:
  Message Type: Allocate Success Response (0x0103)
  Message Length: 48
  Transaction ID: 0x7f0000010000000000000001
  Attributes:
    - XOR-RELAYED-ADDRESS: 192.168.1.200:49152
    - XOR-MAPPED-ADDRESS: 192.168.1.100:49152
    - LIFETIME: 3600 seconds
    - MESSAGE-INTEGRITY: [HMAC-SHA1 hash]
```

## 3. Channel Binding Data Sample

```plaintext
A. ChannelBind Request
---------------------
STUN Message:
  Message Type: ChannelBind (0x0009)
  Message Length: 40
  Transaction ID: 0x7f0000010000000000000002
  Attributes:
    - CHANNEL-NUMBER: 0x4000
    - XOR-PEER-ADDRESS: 192.168.1.101:5000
    - USERNAME: "alice"
    - REALM: "example.com"
    - NONCE: "dcd98b7102dd2f0e8b11d0f600bfb0c093"
    - MESSAGE-INTEGRITY: [HMAC-SHA1 hash]

B. Server Success Response
------------------------
STUN Message:
  Message Type: ChannelBind Success Response (0x0109)
  Message Length: 20
  Transaction ID: 0x7f0000010000000000000002
  Attributes:
    - MESSAGE-INTEGRITY: [HMAC-SHA1 hash]
```

## 4. Data Exchange Using ChannelData Data Sample

```plaintext
A. Client-to-Peer ChannelData Message
-----------------------------------
ChannelData Message:
  Channel Number: 0x4000
  Data Length: 100
  Data: [Application data...]
  Padding: 0x0000

B. Server-to-Peer UDP Packet
---------------------------
UDP Packet:
  Source: 192.168.1.200:49152 (Relay Address)
  Destination: 192.168.1.101:5000 (Peer Address)
  Data: [Application data...]

C. Peer-to-Server UDP Packet
---------------------------
UDP Packet:
  Source: 192.168.1.101:5000 (Peer Address)
  Destination: 192.168.1.200:49152 (Relay Address)
  Data: [Application data...]

D. Server-to-Client ChannelData Message
-------------------------------------
ChannelData Message:
  Channel Number: 0x4000
  Data Length: 100
  Data: [Application data...]
  Padding: 0x0000
```

## 5. Refreshing and Terminating Allocations Data Sample

```plaintext
A. Refresh Request
-----------------
STUN Message:
  Message Type: Refresh (0x0004)
  Message Length: 40
  Transaction ID: 0x7f0000010000000000000003
  Attributes:
    - LIFETIME: 1800 seconds
    - USERNAME: "alice"
    - REALM: "example.com"
    - NONCE: "dcd98b7102dd2f0e8b11d0f600bfb0c093"
    - MESSAGE-INTEGRITY: [HMAC-SHA1 hash]

B. Server Success Response
------------------------
STUN Message:
  Message Type: Refresh Success Response (0x0104)
  Message Length: 20
  Transaction ID: 0x7f0000010000000000000003
  Attributes:
    - LIFETIME: 1800 seconds
    - MESSAGE-INTEGRITY: [HMAC-SHA1 hash]

C. Termination Request
--------------------
STUN Message:
  Message Type: Refresh (0x0004)
  Message Length: 40
  Transaction ID: 0x7f0000010000000000000004
  Attributes:
    - LIFETIME: 0 seconds
    - USERNAME: "alice"
    - REALM: "example.com"
    - NONCE: "dcd98b7102dd2f0e8b11d0f600bfb0c093"
    - MESSAGE-INTEGRITY: [HMAC-SHA1 hash]

D. Server Success Response
------------------------
STUN Message:
  Message Type: Refresh Success Response (0x0104)
  Message Length: 20
  Transaction ID: 0x7f0000010000000000000004
  Attributes:
    - LIFETIME: 0 seconds
    - MESSAGE-INTEGRITY: [HMAC-SHA1 hash]
```
