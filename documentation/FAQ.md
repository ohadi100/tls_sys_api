# FAQ

## Q1. How is the library expected to handle TLS certificate-based client TLS handshake with non-blocking IOStream?

A1. Non blocking is not entirely supported in the Accept-Connect / handshake phase of the connection at this moment, so after calling "connect" on the received "ITLSClientSocket" the handshake might fail due to missing data on the socket with "RC_TLS_WOULD_BLOCK_READ".

## Q2. Is it expected for TLS certificate-based client to NOT call close member function of the provided stream in any use case within the tlsapi library (including ITLSClientSocket::close member function of the appropriate derived object and others)?

A2. If the FD is not created internaly by the library it’s the user responsibility to manage the provided stream FD. According to current implementation the user needs to close() its fd by it self.

## Q3. vwg::tls:: ITLSSessionEndpoint::available member function header comment states: “The method blocks until data are available”. The sample implementation returns a 0 for all use cases (TLSSessionEndpointImpl). Is the member function ITLSSessionEndpoint::available expected to block until data is available?

A3. Indeed the TLSSessionEndpointImpl::available have empty implementation at this moment.

