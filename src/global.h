#include <algorithm>

#ifdef _WIN32
#define NOMINMAX
#pragma comment(lib,"Ws2_32.lib")
#include<Winsock2.h>
#include<ws2tcpip.h>
typedef __int64           sint64;
typedef unsigned __int64  uint64;
typedef __int32           sint32;
typedef unsigned __int32  uint32;
typedef __int16           sint16;
typedef unsigned __int16  uint16;
//typedef __int8            sint8;
//typedef unsigned __int8   uint8;

//typedef __int8 int8_t;
typedef unsigned __int8 uint8_t;
typedef __int16 int16_t;
typedef unsigned __int16 uint16_t;
typedef __int32 int32_t;
typedef unsigned __int32 uint32_t;
typedef __int64 int64_t;
typedef unsigned __int64 uint64_t;
#include "mpirxx.h"
#include "mpir.h"
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/fcntl.h>
#include <unistd.h>
#include <signal.h>
#define Sleep(ms) usleep(1000*ms)
#include <pthread.h>

typedef uint8_t BYTE;
typedef uint32_t DWORD;
#include <cstdlib>
#include <cstdio>
#include <gmpxx.h>
#include <gmp.h>
#endif
#include <iostream>


#include"jhlib/JHLib.h"

#include<stdio.h>
#include<time.h>
#include<set>

#include <iomanip>
#include"sha256.h"
#include"ripemd160.h"
static const int PROTOCOL_VERSION = 70001;

#include<openssl/bn.h>

// our own improved versions of BN functions
BIGNUM *BN2_mod_inverse(BIGNUM *in,	const BIGNUM *a, const BIGNUM *n, BN_CTX *ctx);
int BN2_div(BIGNUM *dv, BIGNUM *rm, const BIGNUM *num, const BIGNUM *divisor);
int BN2_num_bits(const BIGNUM *a);
int BN2_rshift(BIGNUM *r, const BIGNUM *a, int n);
int BN2_lshift(BIGNUM *r, const BIGNUM *a, int n);
int BN2_uadd(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);

#define fastInitBignum(bignumVar, bignumData) \
	bignumVar.d = (BN_ULONG*)bignumData; \
	bignumVar.dmax = 0x200/4; \
	bignumVar.flags = BN_FLG_STATIC_DATA; \
	bignumVar.neg = 0; \
	bignumVar.top = 1; 

// original primecoin BN stuff
#include"uint256.h"
#include"bignum2.h"

#include"prime.h"
#include"jsonrpc.h"

#include<stdint.h>
#include"xptServer.h"
#include"xptClient.h"

#define BEGIN(a)            ((char*)&(a))
#define END(a)              ((char*)&((&(a))[1]))

static inline double GetChainDifficulty(unsigned int nChainLength) { return (double)nChainLength / 16777216.0; }

template<typename T>
std::string HexStr(const T itbegin, const T itend, bool fSpaces=false)
{
    std::string rv;
    static const char hexmap[16] = { '0', '1', '2', '3', '4', '5', '6', '7',
                                     '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
    rv.reserve((itend-itbegin)*3);
    for(T it = itbegin; it < itend; ++it)
    {
        unsigned char val = (unsigned char)(*it);
        if(fSpaces && it != itbegin)
            rv.push_back(' ');
        rv.push_back(hexmap[val>>4]);
        rv.push_back(hexmap[val&15]);
    }

    return rv;
}

typedef struct  
{
	/* +0x00 */ uint32 seed;
	/* +0x04 */ uint32 nBitsForShare;
	/* +0x08 */ uint32 blockHeight;
	/* +0x0C */ uint32 padding1;
	/* +0x10 */ uint32 padding2;
	/* +0x14 */ uint32 client_shareBits;
	/* +0x18 */ uint32 serverStuff1;
	/* +0x1C */ uint32 serverStuff2;
}serverData_t;

typedef struct  
{
	volatile uint32_t primeChainsFound;
	volatile uint32_t foundShareCount;
	volatile float fShareValue;
	volatile float fBlockShareValue;
	volatile float fTotalSubmittedShareValue;
	volatile uint32_t chainCounter[4][13];
	volatile uint32_t chainCounter2[112][13];
	volatile uint32_t chainTotals[4];
	volatile uint32_t nWaveTime;
	volatile unsigned int nWaveRound;
	volatile uint32_t nTestTime;
	volatile unsigned int nTestRound;

	volatile float nChainHit;
	volatile float nPrevChainHit;
	volatile unsigned int nPrimorialMultiplier;
	
	std::vector<unsigned int> nPrimorials;
	volatile unsigned int nPrimorialsSize;

   volatile float nSieveRounds;
	volatile float nSPS;
	volatile int pMult;
   volatile float nCandidateCount;

#ifdef _WIN32
   CRITICAL_SECTION cs;
#else
  pthread_mutex_t cs;
#endif

	// since we can generate many (useless) primes ultra fast if we simply set sieve size low, 
	// its better if we only count primes with at least a given difficulty
	//volatile uint32 qualityPrimesFound;
	volatile uint32 bestPrimeChainDifficulty;
	volatile double bestPrimeChainDifficultySinceLaunch;
  uint64 primeLastUpdate;
  uint64 blockStartTime;
  uint64 startTime;
  
	bool shareFound;
	bool shareRejected;
	volatile unsigned int nL1CacheElements;
	volatile bool tSplit;
	volatile bool adminFunc;

}primeStats_t;

extern primeStats_t primeStats;

typedef struct  
{
	uint32	version;
	uint8	prevBlockHash[32];
	uint8	merkleRoot[32];
	uint32	timestamp;
	uint32	nBits;
	uint32	nonce;
	// GetHeaderHash() goes up to this offset (4+32+32+4+4+4=80 bytes)
	uint256 blockHeaderHash;
	//CBigNum bnPrimeChainMultiplierBN; unused
	mpz_class mpzPrimeChainMultiplier;
	// other
	serverData_t serverData;
	uint32 threadIndex; // the index of the miner thread
	bool xptMode;
}primecoinBlock_t;

typedef struct {
   bool dataIsValid;
   uint8 data[128];
   uint32 dataHash; // used to detect work data changes
   uint8 serverData[32]; // contains data from the server 
} workDataEntry_t;

typedef struct {
#ifdef _WIN32
	CRITICAL_SECTION cs;
#else
  pthread_mutex_t cs;
#endif
  uint8 protocolMode;
   workDataEntry_t workEntry[128]; // work data for each thread (up to 128)
   xptClient_t* xptClient;
} workData_t;

extern jsonRequestTarget_t jsonRequestTarget; // rpc login data

// prototypes from main.cpp
bool error(const char *format, ...);
bool jhMiner_pushShare_primecoin(uint8 data[256], primecoinBlock_t* primecoinBlock);
void primecoinBlock_generateHeaderHash(primecoinBlock_t* primecoinBlock, uint8 hashOutput[32]);
uint32 _swapEndianessU32(uint32 v);
uint32 jhMiner_getCurrentWorkBlockHeight(unsigned int threadIndex);

bool BitcoinMiner(primecoinBlock_t* primecoinBlock, CSieveOfEratosthenes*& psieve, unsigned int threadIndex, unsigned int nonceStep);

// direct access to share counters
extern volatile unsigned int total_shares;
extern volatile unsigned int valid_shares;
extern bool appQuitSignal;

#ifdef _WIN32
extern __declspec( thread ) BN_CTX* pctx;
#else
extern BN_CTX* pctx;
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

#if !HAVE_DECL_LE32DEC
static inline uint32_t le32dec(const void *pp)
{
	const uint8_t *p = (uint8_t const *)pp;
	return ((uint32_t)(p[0]) + ((uint32_t)(p[1]) << 8) +
	    ((uint32_t)(p[2]) << 16) + ((uint32_t)(p[3]) << 24));
}
#endif