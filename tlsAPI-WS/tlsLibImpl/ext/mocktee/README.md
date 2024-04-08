Reference implementation for access to mocked platform TEE.

| **version** |   **date**   | **branch** | **tag** | **notes** |
|:--------:|:--------:|--------|-----|-------------------------------------------------|
| 0.4.0    | 29.09.19 | master |     |<ul><li>include updated version of VKMSOnlineUpdateAPI</li><li>change to vwg::tee namespace</li><li>update to aligned key and certificate IDs</li><li>remove PSK and domain mapping files from repository</li><li>add certificate deletion functionality to ClientCertInitializerAPI</li><li>fix of "no PSK" bug</li></ul>                |
| 0.3.1    | 19.08.19 | master |     | <ul><li>remove botan dependencies from public APIs</li></ul>                |
| 0.3.0    | 08.07.19 | master |     | <ul><li>update VKMS_ECU_BASE certificate and key</li><li>remove usage of C++17/experimental features</li><li>add first draft version of VKMSOnlineUpdateAPI</li><li>minor changes to MockTEE APIs</li><li>minor changes to project structure</li></ul> |
| 0.2.1    | 24.05.19 | master |     | <ul><li>remove Botan usage from TLSTEEAPI calls and updates TLSTEEAPI patch</li></ul> |
| 0.2.0    | 20.05.19 | master |     | <ul><li>add patch for integration into TLSLib reference implementation</li></ul> |
| 0.1.1    | 30.04.19 | master |     | <ul><li>address IMAN-8779 & IMAN-8743</li></ul> |
| 0.1.0    | 15.04.19 | master |     | <ul><li>initial version</li></ul>                |


## Dependencies

LibMockTEE has a compile time dependency to the Botan Library (2.4/2.7). The library is not included in this package.


## Key and Certificate Storage

The following certificates and keys (private keys and PSKs) as well as the subfolders are expected to be available under /tmp/MockTeeStorage.

<pre>
/tmp/  
  MockTeeStorage/  
    ClientCertStore/   
    TrustStore/  
    VKMS/  
      keys.tsv  (not included)  
      domains.tsv  (not included)  
      VIN.txt  (bundled with repository)
      VKMS_ECU_BASE_CERT.pem  (bundled with repository)
      VKMS_ECU_BASE_KEY.pem  (bundled with repository)
      VKMS_ROOT_CERT.pem  (bundled with repository)
</pre>

The MockTeeStorage folder can be initialized with the bundled bash script (Scripts/init_tmp_storage.sh).
The PSKs and domain mappings (keys.tsv, domains.tsv) have to be requested separately.


## Build Instructions - Ubuntu

System prerequisites
- install Ubuntu version 18.04
- install Botan library
   >apt install libbotan-2-4 libbotan-2-dev

1. Clone dep-mocktee repo
   >git clone https://devstack.vwgroup.com/bitbucket/scm/iman/dep-mocktee.git

2. Move to repo folder, create and enter build directory  
   >cd dep-mocktee  
   >mkdir build  
   >cd build  

3. Create the MAKEFILE and build library and examples  
   >cmake ..  
   >make  

4. Run example
   >make runexample

5. Run tests
   >make check

## Documentation

The Doxygen documentation is built with the default target and placed in the /doc/html subdirectory.
If Doxygen or dot is not available, no documentation is built.  
