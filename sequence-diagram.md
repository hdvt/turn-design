## 1. Connection Establishment Sequence Diagram

```mermaid
sequenceDiagram
    participant Client
    participant Server
    
    Note over Client: Connection Establishment
    
    Client->>+Client: Create client session (app_ur_session)
    Client->>+Client: Create socket (UDP/TCP/TLS)
    Client->>+Client: Configure socket (buffers, binding)
    
    alt TCP or TLS connection
        Client->>+Server: Connect TCP socket to server
        Server->>+Server: Accept new connection
    else UDP connection
        Client->>+Client: Store server address for sendto()
    end
    
    alt TLS/DTLS used
        Client->>+Server: Initiate TLS handshake
        Server->>+Client: Complete TLS handshake
    end
    
    Client->>+Client: Set socket to non-blocking mode
    Client->>+Client: Create I/O event handler for socket
    Client->>+Client: Store socket info in session
    
    Server->>+Server: Create server-side session (ts_ur_super_session)
    Server->>+Server: Store client socket in session
    Server->>+Server: Register client_input_handler for socket
    Server->>+Server: Link socket to session object
    Server->>+Server: Start allocation timeout timer
    
    Client->>+Client: Mark client session as ready
    
    Note over Client: Connection established
```

## 2. Authentication and Allocation Creation Sequence Diagram

```mermaid
sequenceDiagram
    participant Client
    participant Server
    
    Note over Client: Authentication & Allocation Creation
    
    Client->>+Client: Create initial Allocate request
    Client->>+Client: Add REQUESTED-TRANSPORT (UDP/TCP)
    Client->>+Client: Add LIFETIME and other attributes
    Client->>+Server: Send Allocate request without auth
    
    Server->>+Server: Check authentication needed
    Server->>+Server: Generate new nonce
    Server->>+Client: Send 401 Unauthorized with REALM, NONCE
    
    Client->>+Client: Create new Allocate request
    Client->>+Client: Add all allocation parameters
    Client->>+Client: Add USERNAME, REALM, NONCE
    Client->>+Client: Calculate MESSAGE-INTEGRITY
    Client->>+Server: Send authenticated Allocate request
    
    Server->>+Server: Verify authentication credentials
    Server->>+Server: Validate MESSAGE-INTEGRITY
    
    alt Authentication Failure
        Server->>+Client: Send 401 error response
    else Authentication Success
        Server->>+Server: Check allocation parameters
        Server->>+Server: Verify user quota and bandwidth
        
        Server->>+Server: Create relay socket(s)
        Server->>+Server: Allocate relay port(s)
        Server->>+Server: Configure relay address
        Server->>+Server: Set up relay socket event handlers
        
        Server->>+Server: Set allocation lifetime timer
        Server->>+Server: Mark allocation as valid
        Server->>+Server: Log allocation creation
        
        Server->>+Client: Send Allocate success response
        Server->>+Client: Include XOR-RELAYED-ADDRESS
        Server->>+Client: Include XOR-MAPPED-ADDRESS
        Server->>+Client: Include LIFETIME, MESSAGE-INTEGRITY
        
        Client->>+Client: Store relay and mapped addresses
    end
    
    Note over Client: Client now has a relay allocation
```

## 3. Channel Binding Sequence Diagram

```mermaid
sequenceDiagram
    participant Client
    participant Server
    participant Peer
    
    Note over Client,Peer: Channel Binding
    
    Client->>+Client: Create ChannelBind request
    Client->>+Client: Generate channel number (0x4000-0x7FFE)
    Client->>+Client: Add CHANNEL-NUMBER attribute
    Client->>+Client: Add XOR-PEER-ADDRESS for Peer
    Client->>+Client: Add authentication attributes
    Client->>+Server: Send ChannelBind request
    
    Server->>+Server: Verify authentication
    Server->>+Server: Check allocation exists
    Server->>+Server: Extract channel number and peer address
    Server->>+Server: Check for conflicting bindings
    
    alt Invalid request or conflicts
        Server->>+Client: Send error response
    else Valid binding request
        Server->>+Server: Create/update permission for Peer (internal)
        Server->>+Server: Create/update channel binding
        Server->>+Server: Set channel expiration (10 minutes)
        
        Server->>+Client: Send ChannelBind success response
    end
    
    Client->>+Client: Store channel to peer mapping
    
    Note over Client,Peer: Channel binding established
```

## 4. Data Exchange Using ChannelData Sequence Diagram

```mermaid
sequenceDiagram
    participant Client
    participant Server
    participant Peer
    
    Note over Client,Peer: Data Exchange Using ChannelData
    
    Note over Client,Peer: A. Client-to-Peer Data Flow
    
    Client->>+Client: Create ChannelData message
    Client->>+Client: Add channel number (first 2 bytes)
    Client->>+Client: Add data length (next 2 bytes)
    Client->>+Client: Add application data
    Client->>+Client: Add padding to multiple of 4 bytes
    Client->>+Server: Send ChannelData message
    
    Server->>+Server: Identify message as ChannelData
    Server->>+Server: Extract channel number
    Server->>+Server: Look up peer address for channel
    Server->>+Server: Verify permission exists (automatic)
    
    alt No channel binding or permission
        Server->>+Server: Drop packet silently
    else Valid channel and permission
        Server->>+Peer: Forward data to Peer
    end
    
    Note over Client,Peer: B. Peer-to-Client Data Flow
    
    Peer->>+Server: Send data to relay address
    
    Server->>+Server: Receive data on relay socket
    Server->>+Server: Look up allocation
    Server->>+Server: Check permission exists for Peer (automatic)
    Server->>+Server: Look up channel for Peer
    
    alt No permission for Peer
        Server->>+Server: Drop packet silently
    else Permission exists and channel bound
        Server->>+Server: Format ChannelData message
        Server->>+Server: Add channel number (first 2 bytes)
        Server->>+Server: Add data length (next 2 bytes)
        Server->>+Server: Add Peer's data
        Server->>+Server: Add padding to multiple of 4 bytes
        Server->>+Client: Send ChannelData message
        
        Client->>+Client: Process ChannelData message
        Client->>+Client: Extract channel number
        Client->>+Client: Look up peer address for channel
        Client->>+Client: Extract application data
        Client->>+Client: Forward to application layer
    end
```

## 5. Refreshing and Terminating Allocations Sequence Diagram

```mermaid
sequenceDiagram
    participant Client
    participant Server
    
    Note over Client: Refreshing and Terminating Allocations
    
    Note over Client: A. Refreshing Allocation
    
    Client->>+Client: Create Refresh request
    Client->>+Client: Add LIFETIME attribute (>0)
    Client->>+Client: Add authentication attributes
    Client->>+Client: Calculate MESSAGE-INTEGRITY
    Client->>+Server: Send Refresh request
    
    Server->>+Server: Verify authentication
    Server->>+Server: Check allocation exists
    Server->>+Server: Extract requested lifetime
    
    alt Invalid allocation or auth
        Server->>+Client: Send error response
    else Valid refresh request
        Server->>+Server: Apply maximum lifetime limits
        Server->>+Server: Update allocation expiration time
        Server->>+Server: Reset allocation lifetime timer
        
        Server->>+Client: Send Refresh success response
        Server->>+Client: Include granted LIFETIME
    end
    
    Client->>+Client: Update local expiration time
    
    Note over Client: B. Terminating Allocation
    
    Client->>+Client: Create Refresh request
    Client->>+Client: Add LIFETIME=0 attribute
    Client->>+Client: Add authentication attributes
    Client->>+Server: Send Refresh request with lifetime=0
    
    Server->>+Server: Verify authentication
    Server->>+Server: Check allocation exists
    Server->>+Server: Detect termination request
    
    Server->>+Server: Mark allocation for deletion
    Server->>+Server: Log allocation deletion
    
    Server->>+Client: Send Refresh success response
    Server->>+Client: Include LIFETIME=0
    
    Server->>+Server: Release user quotas
    Server->>+Server: Clean up relay sockets
    Server->>+Server: Remove permissions and channels
    Server->>+Server: Delete session from tracking
    Server->>+Server: Free all resources
    
    Note over Client: C. Automatic Expiration
    
    Note right of Server: Allocation timer expires
    Server->>+Server: Detect expired allocation
    Server->>+Server: Mark allocation as invalid
    Server->>+Server: Perform termination cleanup
    Server->>+Server: Close client connection if needed
```
