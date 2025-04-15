# Comprehensive Code Flow: Authentication and Allocation Creation in TURN

I'll walk you through the complete step-by-step code flow for Authentication and Allocation Creation, showing how the client and server interact throughout the process:

## 1. Client Sends Initial Allocation Request

**Client-side (startuclient.c):**
```c
static int clnet_allocate(bool verbose, app_ur_conn_info *clnet_info, ioa_addr *relay_addr, int af, ...) {
    // Prepare allocation parameters
    int af4 = dual_allocation || (af == STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV4);
    int af6 = dual_allocation || (af == STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV6);
    
    // Create Allocate request
    stun_set_allocate_request(&request_message, UCLIENT_SESSION_LIFETIME, af4, af6, 
                            relay_transport, mobility, rt, ep);
    
    // Add optional attributes
    if (bps) {
        stun_attr_add_bandwidth_str(request_message.buf, &(request_message.len), bps);
    }
    if (dont_fragment) {
        stun_attr_add(&request_message, STUN_ATTRIBUTE_DONT_FRAGMENT, NULL, 0);
    }
    
    // Add origin and fingerprint (first request typically without integrity)
    add_origin(&request_message);
    stun_attr_add_fingerprint_str(request_message.buf, &(request_message.len));
    
    // Send request
    send_buffer(clnet_info, &request_message, 0, 0);
}
```

## 2. Server Receives Initial Request and Processes Command

**Server-side (ns_turn_server.c):**
```c
static void client_input_handler(ioa_socket_handle s, int event_type, 
                               ioa_net_data *data, void *arg, int can_resume) {
    // Process client data
    read_client_connection(server, ss, data, can_resume, 1);
}

static int read_client_connection(turn_turnserver *server, ts_ur_super_session *ss, 
                              ioa_net_data *in_buffer, int can_resume, int count_usage) {
    // Check if STUN message
    if (stun_is_command_message_full_check_str(...)) {
        // Process STUN command
        handle_turn_command(server, ss, in_buffer, nbh, &resp_constructed, can_resume);
    }
}
```

## 3. Server Checks Authentication and Sends Challenge

**Server-side (ns_turn_server.c):**
```c
static int handle_turn_command(turn_turnserver *server, ts_ur_super_session *ss, 
                            ioa_net_data *in_buffer, ioa_network_buffer_handle nbh, 
                            int *resp_constructed, int can_resume) {
    // Extract method and transaction ID
    uint16_t method = stun_get_method_str(ioa_network_buffer_data(in_buffer->nbh), 
                                       ioa_network_buffer_get_size(in_buffer->nbh));
    stun_tid tid;
    stun_tid_from_message_str(..., &tid);
    
    // Check authentication for the method
    if (method == STUN_METHOD_ALLOCATE) {
        check_stun_auth(server, ss, &tid, resp_constructed, &err_code, &reason, 
                      in_buffer, nbh, method, &message_integrity, &postpone_reply, can_resume);
        
        // If response constructed (401), return
        if (*resp_constructed) {
            return 0;
        }
    }
}

static int check_stun_auth(turn_turnserver *server, ts_ur_super_session *ss, ...) {
    // Check if auth required
    if (!need_stun_authentication(server, ss)) {
        return 0;
    }
    
    // Generate new nonce if needed
    if (ss->nonce[0] == 0 || turn_time_before(ss->nonce_expiration_time, server->ctime)) {
        // Generate random nonce
        for (i = 0; i < NONCE_LENGTH_32BITS; i++) {
            uint8_t *s = ss->nonce + 4 * i;
            uint32_t rand = (uint32_t)turn_random();
            snprintf((char *)s, NONCE_MAX_SIZE - 4 * i, "%04x", (unsigned int)rand);
        }
        ss->nonce_expiration_time = server->ctime + *(server->stale_nonce);
    }
    
    // Check for MESSAGE-INTEGRITY attribute
    stun_attr_ref sar = stun_attr_get_first_by_type_str(..., STUN_ATTRIBUTE_MESSAGE_INTEGRITY);
    if (!sar) {
        // No MESSAGE-INTEGRITY - send 401 challenge
        *err_code = 401;
        return create_challenge_response(ss, tid, resp_constructed, err_code, reason, nbh, method);
    }
}

static int create_challenge_response(ts_ur_super_session *ss, stun_tid *tid, ...) {
    // Build 401 Unauthorized response with challenge
    stun_init_error_response_str(method, ioa_network_buffer_data(nbh), &len, *err_code, *reason, tid);
    
    // Add REALM and NONCE attributes
    stun_attr_add_str(ioa_network_buffer_data(nbh), &len, STUN_ATTRIBUTE_NONCE, 
                    ss->nonce, (int)(NONCE_MAX_SIZE - 1));
    stun_attr_add_str(ioa_network_buffer_data(nbh), &len, STUN_ATTRIBUTE_REALM, 
                    (uint8_t *)realm, (int)(strlen((char *)(realm))));
    
    // Mark response as constructed
    ioa_network_buffer_set_size(nbh, len);
    *resp_constructed = 1;
    return 0;
}
```

## 4. Client Receives Challenge and Prepares Authenticated Request

**Client-side (startuclient.c):**
```c
static int clnet_allocate(bool verbose, app_ur_conn_info *clnet_info, ioa_addr *relay_addr, int af, ...) {
    // Wait for and process server response
    while (!allocate_received) {
        int len = recv_buffer(clnet_info, &response_message, 0, 0, NULL, &err_code, ...);
        
        if (stun_is_challenge_response_str(response_message.buf, len)) {
            // 401 Unauthorized - get REALM and NONCE
            allocate_received = true;
            
            // Extract REALM
            stun_attr_ref sar = stun_attr_get_first_by_type_str(response_message.buf, len, 
                                                             STUN_ATTRIBUTE_REALM);
            if (sar) {
                int slen = stun_attr_get_len(sar);
                char realm[STUN_MAX_REALM_SIZE + 1];
                ns_bcopy(stun_attr_get_value(sar), realm, slen);
                realm[slen] = 0;
                ns_bcopy(realm, clnet_info->realm, slen);
                clnet_info->realm[slen] = 0;
            }
            
            // Extract NONCE
            sar = stun_attr_get_first_by_type_str(response_message.buf, len, 
                                              STUN_ATTRIBUTE_NONCE);
            if (sar) {
                int slen = stun_attr_get_len(sar);
                char nonce[STUN_MAX_NONCE_SIZE + 1];
                ns_bcopy(stun_attr_get_value(sar), nonce, slen);
                nonce[slen] = 0;
                ns_bcopy(nonce, clnet_info->nonce, slen);
                clnet_info->nonce[slen] = 0;
            }
            
            // Generate HMAC key for authentication
            if (!clnet_info->key_set) {
                generate_auth_key(clnet_info->username, clnet_info->realm, 
                               clnet_info->password, clnet_info->key, &clnet_info->key_set);
            }
            
            // Create new authenticated request
            stun_set_allocate_request(&request_message, UCLIENT_SESSION_LIFETIME, af4, af6, 
                                    relay_transport, mobility, rt, ep);
            
            // Add optional attributes
            if (bps) {
                stun_attr_add_bandwidth_str(request_message.buf, &(request_message.len), bps);
            }
            if (dont_fragment) {
                stun_attr_add(&request_message, STUN_ATTRIBUTE_DONT_FRAGMENT, NULL, 0);
            }
            
            // Add authentication and integrity
            add_origin(&request_message);
            add_integrity(clnet_info, &request_message);
            stun_attr_add_fingerprint_str(request_message.buf, &(request_message.len));
            
            // Send authenticated request
            send_buffer(clnet_info, &request_message, 0, 0);
        }
    }
}

static int add_integrity(app_ur_conn_info *clnet_info, stun_buffer *message) {
    if (clnet_info->key_set) {
        // Add USERNAME
        stun_attr_add_str(message->buf, &(message->len), STUN_ATTRIBUTE_USERNAME, 
                        (uint8_t*)clnet_info->username, strlen((char*)clnet_info->username));
        
        // Add REALM
        stun_attr_add_str(message->buf, &(message->len), STUN_ATTRIBUTE_REALM, 
                        (uint8_t*)clnet_info->realm, strlen((char*)clnet_info->realm));
        
        // Add NONCE
        stun_attr_add_str(message->buf, &(message->len), STUN_ATTRIBUTE_NONCE, 
                        (uint8_t*)clnet_info->nonce, strlen((char*)clnet_info->nonce));
        
        // Calculate and add MESSAGE-INTEGRITY
        stun_attr_add_integrity_str(message->buf, &(message->len), 
                                  clnet_info->key, sizeof(clnet_info->key));
    }
    return 0;
}
```

## 5. Server Receives Authenticated Request and Validates Credentials

**Server-side (ns_turn_server.c):**
```c
static int check_stun_auth(turn_turnserver *server, ts_ur_super_session *ss, ...) {
    // Check for MESSAGE-INTEGRITY attribute
    stun_attr_ref sar = stun_attr_get_first_by_type_str(..., STUN_ATTRIBUTE_MESSAGE_INTEGRITY);
    if (!sar) {
        *err_code = 401;
        return create_challenge_response(...);
    }
    
    // Extract and validate REALM
    sar = stun_attr_get_first_by_type_str(..., STUN_ATTRIBUTE_REALM);
    if (!sar) {
        *err_code = 400;
        return -1;
    }
    uint8_t realm[STUN_MAX_REALM_SIZE+1];
    alen = min((size_t)stun_attr_get_len(sar), sizeof(realm)-1);
    memcpy(realm, stun_attr_get_value(sar), alen);
    realm[alen] = 0;
    
    // Extract and validate USERNAME
    sar = stun_attr_get_first_by_type_str(..., STUN_ATTRIBUTE_USERNAME);
    if (!sar) {
        *err_code = 400;
        return -1;
    }
    uint8_t usname[STUN_MAX_USERNAME_SIZE+1];
    alen = min((size_t)stun_attr_get_len(sar), sizeof(usname)-1);
    memcpy(usname, stun_attr_get_value(sar), alen);
    usname[alen] = 0;
    
    // Extract and validate NONCE
    sar = stun_attr_get_first_by_type_str(..., STUN_ATTRIBUTE_NONCE);
    if (!sar) {
        *err_code = 400;
        return -1;
    }
    uint8_t nonce[STUN_MAX_NONCE_SIZE+1];
    alen = min((size_t)stun_attr_get_len(sar), sizeof(nonce)-1);
    memcpy(nonce, stun_attr_get_value(sar), alen);
    nonce[alen] = 0;
    
    // Validate NONCE freshness
    if (strcmp((char *)ss->nonce, (char *)nonce)) {
        *err_code = 438;
        *reason = (const uint8_t *)"Wrong nonce";
        return create_challenge_response(...);
    }
    
    // Get user credentials via callback
    if (method == STUN_METHOD_ALLOCATE) {
        if (!ss->hmackey_set) {
            if (server->userkeycb) {
                hmackey_t hmackey;
                (server->userkeycb)(server->id, server->ct, server->oauth, &(ss->oauth), 
                                  usname, realm, &(ss->max_session_time_auth), &hmackey);
                
                if (hmackey[0] == 0) {
                    *err_code = 401;
                    *reason = (const uint8_t *)"Unauthorized";
                    return create_challenge_response(...);
                }
                
                memcpy(ss->hmackey, hmackey, sizeof(hmackey_t));
                ss->hmackey_set = 1;
            }
        }
    }
    
    // Verify MESSAGE-INTEGRITY
    if (ss->hmackey_set) {
        if (stun_check_message_integrity_by_key_str(ioa_network_buffer_data(in_buffer->nbh),
                                                  ioa_network_buffer_get_size(in_buffer->nbh),
                                                  ss->hmackey, sizeof(ss->hmackey)) < 0) {
            *err_code = 401;
            *reason = (const uint8_t *)"Unauthorized";
            return -1;
        }
    }
    
    // Authentication successful
    *message_integrity = 1;
    ss->nonce_expiration_time = server->ctime + *(server->stale_nonce);
    return 0;
}
```

## 6. Server Processes Allocation Request

**Server-side (ns_turn_server.c):**
```c
static int handle_turn_command(turn_turnserver *server, ts_ur_super_session *ss, ...) {
    switch (method) {
        case STUN_METHOD_ALLOCATE:
            handle_turn_allocate(server, ss, &tid, resp_constructed, &err_code, &reason,
                               unknown_attrs, &ua_num, in_buffer, nbh);
            log_method(ss, "ALLOCATE", err_code, reason);
            break;
    }
}

static int handle_turn_allocate(turn_turnserver *server, ts_ur_super_session *ss, ...) {
    // Check for existing allocation
    allocation* a = get_allocation_ss(ss);
    if (a && is_allocation_valid(a)) {
        *err_code = 437;
        *reason = (const uint8_t *)"Allocation Mismatch";
        return -1;
    }
    
    // Extract REQUESTED-TRANSPORT attribute
    uint8_t transport = 0;
    stun_attr_ref sar = stun_attr_get_first_by_type_str(..., STUN_ATTRIBUTE_REQUESTED_TRANSPORT);
    if (!sar) {
        *err_code = 400;
        *reason = (const uint8_t *)"Bad Request: No REQUESTED-TRANSPORT attribute";
        return -1;
    }
    transport = get_transport_value(stun_attr_get_value(sar));
    
    // Check if transport is supported
    if ((transport != STUN_ATTRIBUTE_TRANSPORT_UDP_VALUE) && 
        (transport != STUN_ATTRIBUTE_TRANSPORT_TCP_VALUE)) {
        *err_code = 442;
        *reason = (const uint8_t *)"Unsupported Transport Protocol";
        return -1;
    }
    
    // Extract LIFETIME attribute
    uint32_t lifetime = 0;
    sar = stun_attr_get_first_by_type_str(..., STUN_ATTRIBUTE_LIFETIME);
    if (sar) {
        lifetime = stun_attr_get_lifetime(sar);
    } else {
        lifetime = STUN_DEFAULT_ALLOCATE_LIFETIME;
    }
    
    // Adjust lifetime based on server limits
    lifetime = stun_adjust_allocate_lifetime(lifetime, *(server->max_allocate_lifetime), 
                                           ss->max_session_time_auth);
    
    // Check optional attributes (reservation token, even port, address family)
    uint64_t in_reservation_token = 0;
    sar = stun_attr_get_first_by_type_str(..., STUN_ATTRIBUTE_RESERVATION_TOKEN);
    if (sar) {
        in_reservation_token = stun_attr_get_reservation_token(sar);
    }
    
    int even_port = -1;
    sar = stun_attr_get_first_by_type_str(..., STUN_ATTRIBUTE_EVEN_PORT);
    if (sar) {
        even_port = stun_attr_get_even_port(sar);
    }
    
    // Check bandwidth requirements
    uint32_t bps = 0;
    sar = stun_attr_get_first_by_type_str(..., STUN_ATTRIBUTE_BANDWIDTH);
    if (sar) {
        bps = stun_attr_get_bandwidth(sar);
    }
    
    // Apply bandwidth quota
    if (server->allocate_bps_func) {
        if (bps > TURN_MAX_ALLOCATION_BPS) {
            bps = TURN_MAX_ALLOCATION_BPS;
        }
        ss->bps = server->allocate_bps_func(bps, 1);
        if (ss->bps < bps) {
            *err_code = 507;
            *reason = (const uint8_t *)"Insufficient Bandwidth Capacity";
            return -1;
        }
    }
    
    // Check user allocation quota
    if (((turn_turnserver *)ss->server)->chquotacb) {
        if ((((turn_turnserver *)ss->server)->chquotacb)(ss->username, ss->oauth, 
                                                       (uint8_t *)ss->realm) < 0) {
            *err_code = 486;
            *reason = (const uint8_t *)"Allocation Quota Reached";
            return -1;
        }
    }
    
    // Create relay connection
    uint64_t out_reservation_token = 0;
    int err = create_relay_connection(server, ss, lifetime, address_family, transport,
                                    even_port, in_reservation_token, &out_reservation_token,
                                    err_code, reason, NULL);
    if (err < 0) {
        return -1;
    }
    
    // Set allocation timer
    IOA_EVENT_DEL(ss->lifetime_ev);
    ss->lifetime_ev = set_ioa_timer(server->e, lifetime, 0, 
                                  client_ss_allocation_timeout_handler, ss, 0,
                                  "client_ss_allocation_timeout_handler");
    
    // Create success response
    pxor_relayed_addr1 = get_local_addr_from_ioa_socket(get_relay_socket_ss(ss, AF_INET));
    pxor_mapped_addr = get_local_addr_from_ioa_socket(ss->client_socket);
    
    stun_set_allocate_response_str(ioa_network_buffer_data(nbh), &len, tid,
                                 pxor_relayed_addr1, pxor_relayed_addr2, pxor_mapped_addr,
                                 lifetime, *(server->max_allocate_lifetime), 0, NULL,
                                 out_reservation_token, ss->s_mobile_id);
    
    // Add MESSAGE-INTEGRITY to response
    if (ss->hmackey_set) {
        stun_attr_add_integrity_str(ioa_network_buffer_data(nbh), &len, ss->hmackey, 
                                  ss->pwd, ss->realm);
    }
    
    ioa_network_buffer_set_size(nbh, len);
    *resp_constructed = 1;
    
    return 0;
}
```

## 7. Server Creates Relay Resources

**Server-side (ns_turn_server.c):**
```c
static int create_relay_connection(turn_turnserver *server, ts_ur_super_session *ss, 
                                 uint32_t lifetime, int address_family, uint8_t transport, 
                                 int even_port, uint64_t in_reservation_token, 
                                 uint64_t *out_reservation_token, int *err_code, 
                                 const uint8_t **reason, accept_cb acb) {
    // Create relay socket
    ioa_socket_handle s = create_ioa_socket(server->e, NULL, ss->client_socket->st, RELAY_SOCKET);
    
    // Configure relay address based on address family
    ioa_addr relay_addr;
    addr_set_any(&relay_addr);
    if (address_family == STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV4) {
        addr_set_any_ipv4(&relay_addr);
    } else if (address_family == STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV6) {
        addr_set_any_ipv6(&relay_addr);
    }
    
    // Bind socket to address with even port and reservation token
    int res = bind_ioa_socket(s, &relay_addr, even_port, in_reservation_token, 
                            out_reservation_token);
    
    if (res < 0) {
        *err_code = 508;
        *reason = (const uint8_t *)"Cannot allocate relay address";
        close_ioa_socket(s);
        return -1;
    }
    
    // Update socket information
    addr_get_from_sock(s, &relay_addr);
    set_ioa_socket_session(s, ss);
    
    // Store relay information in session
    ss->relay_socket = s;
    addr_cpy(&(ss->relay_addr), &relay_addr);
    ss->lifetime = lifetime;
    ss->alloc_is_valid = 1;
    
    // Setup callbacks on socket
    set_ioa_socket_sub_session(s, lifetime);
    
    // Enable events on socket
    if (transport == STUN_ATTRIBUTE_TRANSPORT_UDP_VALUE) {
        IOA_EVENT_DEL(s->read_event);
        s->read_event = set_ioa_socket_event(server->e, s, IOA_EV_READ, 
                                          peer_input_handler, ss);
    }
    
    // Log allocation
    char saddr[256];
    addr_to_string(&relay_addr, saddr);
    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, 
                "Allocation succeeded: %s, lifetime=%lu\n", 
                saddr, (unsigned long)lifetime);
    
    // Update quota
    inc_quota(ss, ss->username);
    
    return 0;
}
```

## 8. Client Receives Allocation Success

**Client-side (startuclient.c):**
```c
static int clnet_allocate(bool verbose, app_ur_conn_info *clnet_info, ioa_addr *relay_addr, int af, ...) {
    while (!allocate_received) {
        int len = recv_buffer(clnet_info, &response_message, 0, 0, NULL, &err_code, ...);
        
        if (stun_is_success_response(&response_message)) {
            // Process successful allocation response
            if (stun_is_response(&response_message)) {
                allocate_received = true;
                allocate_finished = true;
                
                // Extract relay address
                if (stun_attr_get_first_addr(&response_message, STUN_ATTRIBUTE_XOR_RELAYED_ADDRESS, 
                                          relay_addr, NULL) < 0) {
                    if (verbose) {
                        TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "No relay address in allocate response\n");
                    }
                    return -1;
                }
                
                // Extract mapped address
                ioa_addr mapped_addr;
                if (stun_attr_get_first_addr(&response_message, STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS, 
                                          &mapped_addr, NULL) >= 0) {
                    addr_cpy(&(clnet_info->mapped_addr), &mapped_addr);
                    addr_set_port(&(clnet_info->mapped_addr), addr_get_port(&mapped_addr));
                }
                
                // Extract lifetime
                stun_attr_ref sar = stun_attr_get_first_by_type(&response_message, STUN_ATTRIBUTE_LIFETIME);
                if (sar) {
                    uint32_t lifetime = stun_attr_get_lifetime(sar);
                    clnet_info->lifetime = lifetime;
                }
                
                // Extract reservation token if present
                sar = stun_attr_get_first_by_type(&response_message, STUN_ATTRIBUTE_RESERVATION_TOKEN);
                if (sar) {
                    uint64_t rt = stun_attr_get_reservation_token(sar);
                    current_reservation_token = rt;
                }
                
                // Read mobility ticket if mobility enabled
                if (mobility) {
                    read_mobility_ticket(clnet_info, &response_message);
                }
            }
        }
    }
    
    return 0;
}
```

## Complete End-to-End Code Flow Summary

1. **Initial Connection**
   - Client creates socket and connects to server
   - Server accepts connection and creates session

2. **First Allocation Request**
   - Client creates Allocate request without authentication
   - Client sets REQUESTED-TRANSPORT and other attributes
   - Client sends request to server

3. **Server Authentication Challenge**
   - Server receives request via `client_input_handler`
   - Server processes request via `read_client_connection` and `handle_turn_command`
   - Server checks for authentication via `check_stun_auth`
   - Server finds no MESSAGE-INTEGRITY, generates nonce
   - Server sends 401 Unauthorized with REALM and NONCE via `create_challenge_response`

4. **Client Credential Preparation**
   - Client receives 401 response
   - Client extracts REALM and NONCE attributes
   - Client calculates HMAC key using long-term credentials
   - Client prepares new request with USERNAME, REALM, NONCE
   - Client adds MESSAGE-INTEGRITY via `add_integrity`
   - Client sends authenticated request

5. **Server Authentication Verification**
   - Server receives authenticated request
   - Server validates MESSAGE-INTEGRITY, REALM, USERNAME, and NONCE
   - Server gets user credentials via `userkeycb` callback
   - Server verifies MESSAGE-INTEGRITY using HMAC

6. **Allocation Processing**
   - Server processes Allocate request via `handle_turn_allocate`
   - Server checks for existing allocation
   - Server extracts and validates REQUESTED-TRANSPORT
   - Server adjusts LIFETIME based on limits
   - Server checks bandwidth and user quota limits

7. **Relay Creation**
   - Server creates relay sockets via `create_relay_connection`
   - Server binds to relay address
   - Server sets up event handlers
   - Server updates quota
   - Server sets allocation timer

8. **Success Response**
   - Server builds success response with XOR-RELAYED-ADDRESS
   - Server adds XOR-MAPPED-ADDRESS
   - Server adds MESSAGE-INTEGRITY to response
   - Server sends response to client

9. **Client Completion**
   - Client receives success response
   - Client extracts relay address, mapped address, and lifetime
   - Client stores allocation information
   - Allocation process is complete
