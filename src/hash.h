// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_HASH_H
#define BITCOIN_HASH_H

#include "serialize.h"
#include "uint256.h"
#include "version.h"
#include "sph_sha2.h"
#include "sph_radiogatun.h"
#include "sph_panama.h"


#include <vector>

#include <openssl/ripemd.h>
#include <openssl/sha.h>


#ifndef QT_NO_DEBUG
#include <string>
#endif

#ifdef GLOBALDEFINED
#define GLOBAL
#else
#define GLOBAL extern
#endif

GLOBAL sph_sha256_context     z_sha256;
GLOBAL sph_radiogatun64_context       z_radiogatun64;
GLOBAL sph_panama_context   z_panama;


#define fillz() do { \
    sph_sha256_init(&z_sha256); \
    sph_radiogatun64_init(&z_radiogatun64); \
    sph_panama_init(&z_panama); \
} while (0) 


#define ZSHA256 (memcpy(&ctx_sha256, &z_sha256, sizeof(z_sha256)))
#define ZRADIOGATUN64 (memcpy(&ctx_radiogatun64, &z_radiogatun64, sizeof(z_radiogatun64)))
#define ZPANAMA (memcpy(&ctx_panama, &z_panama, sizeof(z_panama)))




template<typename T1>
inline uint256 Hash(const T1 pbegin, const T1 pend)
{
     sph_sha256_context	 ctx_sha256;
	sph_radiogatun64_context  ctx_radiogatun64;
	sph_panama_context	 ctx_panama;
	
	static unsigned char pblank[3];

	#ifndef QT_NO_DEBUG
	//std::string strhash;
	//strhash = "";
	#endif

	
	
	uint512 hash[7];

    sph_radiogatun64_init(&ctx_radiogatun64);
    sph_radiogatun64(&ctx_radiogatun64, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
    sph_radiogatun64_close(&ctx_radiogatun64, static_cast<void*>(&hash[0]));
    
    sph_panama_init(&ctx_panama);
    sph_panama(&ctx_panama, static_cast<const void*>(&hash[0]), 64);
    sph_panama_close(&ctx_panama, static_cast<void*>(&hash[1]));
    
    sph_sha256_init(&ctx_sha256);
    sph_sha256(&ctx_sha256, static_cast<const void*>(&hash[1]), 64);
    sph_sha256_close(&ctx_sha256, static_cast<void*>(&hash[2]));
        
     /*-------------------------------MIRROR---------------------------*/
        
    sph_sha256_init(&ctx_sha256);
    sph_sha256(&ctx_sha256, static_cast<const void*>(&hash[2]), 64);
    sph_sha256_close(&ctx_sha256, static_cast<void*>(&hash[3]));    
    
    sph_panama_init(&ctx_panama);
    sph_panama(&ctx_panama, static_cast<const void*>(&hash[3]), 64);
    sph_panama_close(&ctx_panama, static_cast<void*>(&hash[4]));
    
    sph_radiogatun64_init(&ctx_radiogatun64);
    sph_radiogatun64(&ctx_radiogatun64, static_cast<const void*>(&hash[4]), 64);
    sph_radiogatun64_close(&ctx_radiogatun64, static_cast<void*>(&hash[5]));
    

    return hash[5].trim256();
}

class CHashWriter
{
private:
    SHA256_CTX ctx;

public:
    int nType;
    int nVersion;

    void Init() {
        SHA256_Init(&ctx);
    }

    CHashWriter(int nTypeIn, int nVersionIn) : nType(nTypeIn), nVersion(nVersionIn) {
        Init();
    }

    CHashWriter& write(const char *pch, size_t size) {
        SHA256_Update(&ctx, pch, size);
        return (*this);
    }

    // invalidates the object
    uint256 GetHash() {
        uint256 hash1;
        SHA256_Final((unsigned char*)&hash1, &ctx);
        uint256 hash2;
        SHA256((unsigned char*)&hash1, sizeof(hash1), (unsigned char*)&hash2);
        return hash2;
    }

    template<typename T>
    CHashWriter& operator<<(const T& obj) {
        // Serialize to this stream
        ::Serialize(*this, obj, nType, nVersion);
        return (*this);
    }
};


template<typename T1, typename T2>
inline uint256 Hash(const T1 p1begin, const T1 p1end,
                    const T2 p2begin, const T2 p2end)
{
    static unsigned char pblank[1];
    uint256 hash1;
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, (p1begin == p1end ? pblank : (unsigned char*)&p1begin[0]), (p1end - p1begin) * sizeof(p1begin[0]));
    SHA256_Update(&ctx, (p2begin == p2end ? pblank : (unsigned char*)&p2begin[0]), (p2end - p2begin) * sizeof(p2begin[0]));
    SHA256_Final((unsigned char*)&hash1, &ctx);
    uint256 hash2;
    SHA256((unsigned char*)&hash1, sizeof(hash1), (unsigned char*)&hash2);
    return hash2;
}

template<typename T1, typename T2, typename T3>
inline uint256 Hash(const T1 p1begin, const T1 p1end,
                    const T2 p2begin, const T2 p2end,
                    const T3 p3begin, const T3 p3end)
{
    static unsigned char pblank[1];
    uint256 hash1;
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, (p1begin == p1end ? pblank : (unsigned char*)&p1begin[0]), (p1end - p1begin) * sizeof(p1begin[0]));
    SHA256_Update(&ctx, (p2begin == p2end ? pblank : (unsigned char*)&p2begin[0]), (p2end - p2begin) * sizeof(p2begin[0]));
    SHA256_Update(&ctx, (p3begin == p3end ? pblank : (unsigned char*)&p3begin[0]), (p3end - p3begin) * sizeof(p3begin[0]));
    SHA256_Final((unsigned char*)&hash1, &ctx);
    uint256 hash2;
    SHA256((unsigned char*)&hash1, sizeof(hash1), (unsigned char*)&hash2);
    return hash2;
}

template<typename T>
uint256 SerializeHash(const T& obj, int nType=SER_GETHASH, int nVersion=PROTOCOL_VERSION)
{
    CHashWriter ss(nType, nVersion);
    ss << obj;
    return ss.GetHash();
}

template<typename T1>
inline uint160 Hash160(const T1 pbegin, const T1 pend)
{
    static unsigned char pblank[1];
    uint256 hash1;
    SHA256((pbegin == pend ? pblank : (unsigned char*)&pbegin[0]), (pend - pbegin) * sizeof(pbegin[0]), (unsigned char*)&hash1);
    uint160 hash2;
    RIPEMD160((unsigned char*)&hash1, sizeof(hash1), (unsigned char*)&hash2);
    return hash2;
}

inline uint160 Hash160(const std::vector<unsigned char>& vch)
{
    return Hash160(vch.begin(), vch.end());
}

unsigned int MurmurHash3(unsigned int nHashSeed, const std::vector<unsigned char>& vDataToHash);

typedef struct
{
    SHA512_CTX ctxInner;
    SHA512_CTX ctxOuter;
} HMAC_SHA512_CTX;

int HMAC_SHA512_Init(HMAC_SHA512_CTX *pctx, const void *pkey, size_t len);
int HMAC_SHA512_Update(HMAC_SHA512_CTX *pctx, const void *pdata, size_t len);
int HMAC_SHA512_Final(unsigned char *pmd, HMAC_SHA512_CTX *pctx);

#endif
