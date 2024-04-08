include(ExternalProject)

if(NOT EXISTS "${THIRD_PARTY_SRC}/install/lib/libbotan-2.so")
    message("-- Build Botan")
    if(CMAKE_CXX_PLATFORM_ID MATCHES "^(qnx|QNX)$" )
        set(CC_ABI_FLAGS -V${CMAKE_CXX_COMPILER_TARGET})
        set(LDFLAGS "${LDFLAGS} -lsocket")
    # elseif(CMAKE_CXX_PLATFORM_ID MATCHES "Linux")
    # # According to req-crypto-libe3botan-rng-configuration libe3botan shall use system call getrandom()
    # set(ENABLE_GETRANDOM --without-os-features=dev_random,arc4random --with-os-features=getrandom)
    endif()
    set(COMPILER "--cc=gcc")

    if(CMAKE_CXX_PLATFORM_ID MATCHES "^(qnx|QNX)$" )
        set(OS "--os=qnx")
        set (CPU "--cpu=arm64")
        set(IMPLICIT_LINK_LIBRARIES ${CMAKE_CXX_IMPLICIT_LINK_LIBRARIES})
        list(TRANSFORM IMPLICIT_LINK_LIBRARIES PREPEND "-l")
        string(REPLACE ";" " " IMPLICIT_LINK_LIBRARIES "${IMPLICIT_LINK_LIBRARIES}")
        set(IMPLICIT_LINK_DIRECTORIES ${CMAKE_CXX_IMPLICIT_LINK_DIRECTORIES})
        list(TRANSFORM IMPLICIT_LINK_DIRECTORIES PREPEND "-L")
        string(REPLACE ";" " " IMPLICIT_LINK_DIRECTORIES "${IMPLICIT_LINK_DIRECTORIES}")
        set(LDFLAGS "${IMPLICIT_LINK_LIBRARIES} ${IMPLICIT_LINK_DIRECTORIES} -lsocket")
        set(BOTAN_BUILD_TARGET --cc-bin=${CMAKE_C_COMPILER} --cc-abi-flags=-V${CMAKE_CXX_COMPILER_TARGET} --ldflags=${LDFLAGS})
    else()
        set(OS "--os=linux")  
        set (CPU "--cpu=x86_64")
    endif()

    # compile external project botan
    ExternalProject_Add(botan
            PREFIX ${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/external
            URL ${THIRD_PARTY_SRC}/archives/botan-2.8.0.tar.gz
            PATCH_COMMAND patch -p1 < ${THIRD_PARTY_SRC}/archives/botan-closeNoReset.patch
            INSTALL_DIR ${THIRD_PARTY_SRC}/install

            CONFIGURE_COMMAND
            ${CMAKE_COMMAND} -E env
            ${EXTERNAL_PROJECT_TOOLS}
            <SOURCE_DIR>/configure.py
            ${OS}
            ${COMPILER}
            ${CPU}
            --disable-neon
            --link-method=hardlink
            --no-autoload
            --amalgamation
            --enable-modules=tls,xts,rsa,eme_oaep,emsa_pssr,sha2_32,rdseed,adler32,aead,aes,aes_ni,aont,asn1,auto_rng,base,base64,bcrypt,bigint,blake2,block,blowfish,camellia,cascade,cast128,cast256,cbc,cbc_mac,ccm,cecpq1,certstor_sql,cfb,chacha,chacha20poly1305,cmac,comb4p,crc24,crc32,cryptobox,ctr,curve25519,des,dh,dl_algo,dl_group,dlies,dsa,eax,ec_group,ecc_key,ecdh,ecdsa,ecgdsa,ecies,eckcdsa,elgamal,eme_oaep,eme_pkcs1,eme_raw,emsa1,emsa_pkcs1,emsa_pssr,emsa_raw,emsa_x931,entropy,fd_unix,filters,fpe_fe1,gcm,gmac,gost_28147,gost_3410,gost_3411,hash,hash_id,hex,hkdf,hmac,hmac_drbg,http_util,idea,idea_sse2,iso9796,kasumi,kdf,kdf1,kdf1_iso18033,kdf2,keccak,keypair,lion,mac,mce,mceies,md4,md5,mdx_hash,mgf1,misty1,mode_pad,modes,mp,newhope,noekeon,noekeon_simd,numbertheory,ocb,ofb,par_hash,passhash9,pbkdf,pbkdf1,pbkdf2,pem,pkcs11,pk_pad,poly1305,prf_tls,prf_x942,pubkey,rc4,rdrand_rng,rdseed,rfc3394,rfc6979,rmd160,rng,rsa,salsa20,seed,serpent,serpent_simd,sessions_sql,sha1,sha1_sse2,sha2_32,sha2_64,sha3,shake,shake_cipher,simd,siphash,siv,skein,sp800_108,sp800_56c,srp6,stateful_rng,stream,system_rng,tiger,tls,tls_cbc,tss,twofish,utils,whirlpool,x509,x919_mac,xmss,xtea,xts,simd,noekeon_simd,serpent_simd,shacal2_simd
            ${BOTAN_BUILD_TARGET}
            --prefix=<INSTALL_DIR>
            ${EXTERNAL_PROJECT_CPU}
            BUILD_COMMAND ${MAKE}

            BUILD_BYPRODUCTS <INSTALL_DIR>/lib/libbotan-2.a
            )
endif()

add_library(botan_project SHARED IMPORTED GLOBAL)
set_property(TARGET botan_project PROPERTY 
    IMPORTED_LOCATION ${THIRD_PARTY_SRC}/install/lib/libbotan-2.a
)
add_dependencies(botan_project botan)
