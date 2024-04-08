Test-suite that checks the psk-based wolfssl engine

# Run teset
- Open the server_client_input.ini file and update the third parameter in each row to valid domain name.
- Run the python test_suite: ./run_test_suite.py <minutes> (default 30). The tests will run for the time you gave as a <minutes> argument.
- Run with -d option in order to see more details and test output files in case of failure.

### Results
At the end, you will receive a report in the log.txt file that will be an indication of which tests have passed and which failed.
The tests will check the following cases:

##### Server (Authentic & Confidential) | Client (Authentic)
This test simulates two Comm-Daemons.
1. comm-daemon 1: 1 server that supports SecurityLevel Authentic and 1 Confidential (2 services).
2. comm-daemon 2: client that supports only Authentic Confidential (same port as the server).
If the test fails: either the support for two server with different SecurityLevel (same library) is not possible or the Authentic SecurityLevel communication is not supported.

##### Server (Authentic) | Client (Authentic & Confidential)
This test simulates two Comm-Daemons.
1. comm-daemon 1: server that supports SecurityLevel Authentic (1 services).
2. comm-daemon 2: 1 client that supports SecurityLevel Authentic and 1 Confidential.
If the test fails: either the support for two client with different SecurityLevel (same library) is not possible or the Authentic SecurityLevel communication is not supported.

##### Server (Confidential) | Client (Authentic & Confidential)
This test simulates two Comm-Daemons.
1. comm-daemon 1: server that supports SecurityLevel Confidential (2 services).
2. comm-daemon 2: 1 client that supports SecurityLevel Authentic and 1 Confidential.
If the test fails: either the support for two client with different SecurityLevel (same library) is not possible or the Confidential SecurityLevel communication is not supported.

##### Server (Authentic & Confidential) | Client (Authentic & Confidential)
This test simulates two Comm-Daemons.
1. comm-daemon 1: 1 server that supports SecurityLevel Authentic and 1 Confidential (2 services).
2. comm-daemon 2: 1 client that supports SecurityLevel Authentic and 1 Confidential.
If the test fails: either the support for two client/server with different SecurityLevel (same library) is not possible or the simultaneous communication for Confidential SecurityLevel and Authentic SecurityLevel is not supported.

##### Server (Authentic & Confidential) | Client (Confidential)
This test simulates two Comm-Daemons.
1. comm-daemon 1: 1 server that supports SecurityLevel Authentic and 1 Confidential (2 services).
2. comm-daemon 2: client that supports SecurityLevel Confidential (same port as the server).
If the test fails: either the support for two server with different SecurityLevel (same library) is not possible or the Confidential SecurityLevel communication is not supported.

##### Multiple Clients
This test simulates four Comm-Daemons.
1. comm-daemon 1: 2 servers that supports Authentic SecurityLevel with different ports, and 2 servers that supports Confidential SecurityLevel with different ports.
2. comm-daemon 2: 1 client for each server (2 Authentic with different ports, and 2 Confidential with different ports).
3. comm-daemon 3: 1 client for each server (2 Authentic with different ports, and 2 Confidential with different ports).
4. comm-daemon 4: 1 client for each server (2 Authentic with different ports, and 2 Confidential with different ports).
If the test fails: either the support for four client/server with different SecurityLevel and different ports (same library) is not possible or the simultaneous communication for Confidential SecurityLevel and Authentic SecurityLevel / different ports is not supported.
