# Component "sSOA TLS Library"

## General Description

The sSOA TLS library is a common library to unify secure connections. It abstracts complex cryptographic procedures and allow the user an easy and straight forward way to achieve a secure connection with as little actions as possible. The library supports 2 types of secure connections. These secure connections will be achieved by an abstract easy to use factories. See further explanation below.

#### 1. PSK
The library supports a creation of both client and server secure connection. Using a pre-shared key matrix, and user defined "hints"(std::string) the library can automatically establish a connection between server and client and allow the user to be responsible only for the data sent, and not the infrastructure.

#### 2. Certificate based
The library supports the creation of TLS client using certified(mutual and one-sided) secure connection. Using the common TLS protocol the client can connect to every modern commonly known web service (or predefined one).
The library supports OCSP & OCSP stapling (OCSP Fallback Mechanism for Revocation Checks).

***(For more details- look for the relevant API or at the components below)***

## Overview of the library

### Components:
The TLS library contains several key elements:
1. TLSResult - this class is a template to allow checks on returning values, pending errors and getPayload for the encapsulted class.
2. TLSSocketFactory - responsible for creation of TLSSocket, with different protocols.
3. TLSSocket - is an initialized TLSSocket without connection.
4. TLSSessionEndpoint - return from TLSSocket that created a connection. this is the secure working socket for the entire system run-time.

### Required Classes

5. InetAddress (InetAddressFactory) - the class represent IP address in the TLS library. each address must constructed with the InetAddressFactory to keep this format.
6. IOStream - the underlying connection infrastructure, it can be user defined or use the default that comes with the library. it must follow the IOStream Interface.

##### 1. TLSResult
This is a wrapper for the result of all the factories in the library. it allows the user to use the following functionallity:
```C++
bool succeeded();//if the operation succeeded
T getPayload();//get the object created by the relevant factory
TLSReturnCodes getErrorCode();//get errors that were thrown by the factory
```

##### 2. TLSSocketFactory:
This factory supports the creation of the following sockets

#### Create PSK Client
######to create a client with the connection parameters:
```C++
TLSClientSocketResult createClientSocket(SPIInetAddress inet,  const UInt16 port,  const std::string &localDomainName, const SecurityLevel confidentiality, const SocketType socketType = SOCKETTYPE_STREAM );
```

######to create a client with a given socket file descriptor:
```C++
TLSClientSocketResult createClientSocket(int fd,  const std::string &localDomainName, const SecurityLevel confidentiality);
```

#### Create PSK Server
######to create a server with the connection parameters, use the following:
```C++
TLSServerSocketResult createServerSocket(SPIInetAddress inet,  const UInt16 port ,  const std::string &localDomainName, const SecurityLevel securityLevel, const SocketType socketType = SOCKETTYPE_STREAM );
```

######to create a server based on a given socket, use the following:
```C++
TLSServerSocketResult createServerSocket(int fd,  const std::string &localDomainName, const SecurityLevel confidentiality);
```

######to create a server based on an already connected socket, use the following:
```C++
TLSSessionEndpointResult createPskServerSession(int connectionFd, const std::string &localDomainName, const SecurityLevel confidentiality);
```


#### Create Certificate Client

######to create a client socket to a certificate-based connection, use the following:
```C++
TLSClientSocketResult createTlsClient(const std::shared_ptr<IOStream> &stream, const std::string& hostName, const CertStoreID& certStoreId, const  ClientCertificateSetID &clientCertificateSetID,  const CipherSuiteIds& cipherSuiteIds, const TimeCheckTime& checkTime,  const std::vector<HashSha256>& httpPublicKeyPinningHashs, const bool revocationCheckEnabled = false);
```


##### 3. TLSSocket
After using the TLSSocketFactory successfully, a TLSSocket will be created.
Depending on the type, the next actions will return an active socket instead.
```C++
TLSResult<std::shared_ptr<ITLSSessionEndpoint>> accept();//for server socket

TLSResult<std::shared_ptr<ITLSSessionEndpoint>> connect();//for client socket
```

##### 4. TLSSessionEndpoint
The TLSSessionEndpoint acts like a socket(sys/socket.h) and provides the following functionalities:
```C++
Int32 send(const Byte b[], const Int32 len);
Int32 send(const Byte b[], const UInt32 offset, const Int32 len);
Int32 receive(Byte b[], const Int32 len);
int getSocketFD();
TLSReturnCodes shutdown();
std::string getLocalDomainName();
std::string getRemoteDomainName();
UInt16 	getRemotePort();
SPIInetAddress getRemoteInetAddress();
```

##### 5. InetAddressFactory

###### Make IP Address:
```C++
static IInetAddressResult makeIPAddress(const std::string &inetAddr);
static IInetAddressResult makeIPAddress(const char* inetAdd);
```

##### 6.The IOStream Class
```C++
int32_t Receive(void *buf, uint32_t len);
int32_t Send(const void *buf, uint32_t len);
void Close();
bool IsOpen();
bool isClosed()
```


## How to build it
    mkdir build
    cd ./build
    
    # use cmake for all the makefiles:
    cmake ..

    # Then make everything:
    make -j
    
## FAQ

#### General
    
    Q: 
    A:

    Q:
    A:
    
#### OCSP

    Q: How do I disable OCSP requests in case of Hard-Fail fallback mechanism? 
    A: Build the library according to "How to build it" section but instead of "cmake .." use "cmake -DICAS3_NO_OCSP_HARD_FAIL=ON .."
