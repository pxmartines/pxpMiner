#include"global.h"
#include "ticker.h"
//#include<intrin.h>
#include<ctime>
#include<map>

#ifdef _WIN32
#include<conio.h>
#else

#include <termios.h>            //termios, TCSANOW, ECHO, ICANON
#include <unistd.h>     //STDIN_FILENO
#endif

//used for get_num_cpu
#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#include <sys/types.h>
#include <sys/sysctl.h>
#endif

primeStats_t primeStats = {0};
volatile unsigned int total_shares = 0;
volatile unsigned int valid_shares = 0;
unsigned int nMaxSieveSize;
unsigned int vPrimesSize;
unsigned int nonceStep;
bool nPrintDebugMessages;
bool nPrintSPSMessages;
unsigned int nOverrideTargetValue;
unsigned int nOverrideBTTargetValue;
unsigned int nSieveExtensions;
volatile unsigned int threadSNum = 0;
char* dt;

char* minerVersionString = "T16 v5 (AeroCloud) linux";

bool error(const char *format, ...)
{
	puts(format);
	return false;
}


bool hex2bin(unsigned char *p, const char *hexstr, size_t len)
{
	bool ret = false;

	while (*hexstr && len) {
		char hex_byte[4];
		unsigned int v;

		if (!hexstr[1]) {
			std::cout << "hex2bin str truncated" << std::endl;
			return ret;
		}

		memset(hex_byte, 0, 4);
		hex_byte[0] = hexstr[0];
		hex_byte[1] = hexstr[1];

		if (sscanf(hex_byte, "%x", &v) != 1) {
			std::cout << "hex2bin sscanf '" << hex_byte << "' failed" << std::endl;
			return ret;
		}

		*p = (unsigned char) v;

		p++;
		hexstr += 2;
		len--;
	}

	if (len == 0 && *hexstr == 0)
		ret = true;
	return ret;
}



uint32 _swapEndianessU32(uint32 v)
{
	return ((v>>24)&0xFF)|((v>>8)&0xFF00)|((v<<8)&0xFF0000)|((v<<24)&0xFF000000);
}

uint32 _getHexDigitValue(uint8 c)
{
	if( c >= '0' && c <= '9' )
		return c-'0';
	else if( c >= 'a' && c <= 'f' )
		return c-'a'+10;
	else if( c >= 'A' && c <= 'F' )
		return c-'A'+10;
	return 0;
}

/*
 * Parses a hex string
 * Length should be a multiple of 2
 */
void yPoolWorkMgr_parseHexString(char* hexString, uint32 length, uint8* output)
{
	uint32 lengthBytes = length / 2;
	for(uint32 i=0; i<lengthBytes; i++)
	{
		// high digit
		uint32 d1 = _getHexDigitValue(hexString[i*2+0]);
		// low digit
		uint32 d2 = _getHexDigitValue(hexString[i*2+1]);
		// build byte
		output[i] = (uint8)((d1<<4)|(d2));	
	}
}

/*
 * Parses a hex string and converts it to LittleEndian (or just opposite endianness)
 * Length should be a multiple of 2
 */
void yPoolWorkMgr_parseHexStringLE(char* hexString, uint32 length, uint8* output)
{
	uint32 lengthBytes = length / 2;
	for(uint32 i=0; i<lengthBytes; i++)
	{
		// high digit
		uint32 d1 = _getHexDigitValue(hexString[i*2+0]);
		// low digit
		uint32 d2 = _getHexDigitValue(hexString[i*2+1]);
		// build byte
		output[lengthBytes-i-1] = (uint8)((d1<<4)|(d2));	
	}
}


void primecoinBlock_generateHeaderHash(primecoinBlock_t* primecoinBlock, uint8 hashOutput[32])
{
	uint8 blockHashDataInput[512];
	memcpy(blockHashDataInput, primecoinBlock, 80);
	sha256_context ctx;
	sha256_starts(&ctx);
	sha256_update(&ctx, (uint8*)blockHashDataInput, 80);
	sha256_finish(&ctx, hashOutput);
	sha256_starts(&ctx); // is this line needed?
	sha256_update(&ctx, hashOutput, 32);
	sha256_finish(&ctx, hashOutput);
}

void primecoinBlock_generateBlockHash(primecoinBlock_t* primecoinBlock, uint8 hashOutput[32])
{
	uint8 blockHashDataInput[512];
	memcpy(blockHashDataInput, primecoinBlock, 80);
	uint32 writeIndex = 80;
	sint32 lengthBN = 0;
	CBigNum bnPrimeChainMultiplier;
	bnPrimeChainMultiplier.SetHex(primecoinBlock->mpzPrimeChainMultiplier.get_str(16));
	std::vector<unsigned char> bnSerializeData = bnPrimeChainMultiplier.getvch();
	lengthBN = bnSerializeData.size();
	*(uint8*)(blockHashDataInput+writeIndex) = (uint8)lengthBN;
	writeIndex += 1;
	memcpy(blockHashDataInput+writeIndex, &bnSerializeData[0], lengthBN);
	writeIndex += lengthBN;
	sha256_context ctx;
	sha256_starts(&ctx);
	sha256_update(&ctx, (uint8*)blockHashDataInput, writeIndex);
	sha256_finish(&ctx, hashOutput);
	sha256_starts(&ctx); // is this line needed?
	sha256_update(&ctx, hashOutput, 32);
	sha256_finish(&ctx, hashOutput);
}





#define MINER_PROTOCOL_GETWORK		(1)
#define MINER_PROTOCOL_STRATUM		(2)
#define MINER_PROTOCOL_XPUSHTHROUGH	(3)

workData_t workData;

jsonRequestTarget_t jsonRequestTarget = {0}; // rpc login data
jsonRequestTarget_t jsonLocalPrimeCoin; // rpc login data


/*
 * Pushes the found block data to the server for giving us the $$$
 * Uses getwork to push the block
 * Returns true on success
 * Note that the primecoin data can be larger due to the multiplier at the end, so we use 256 bytes per default
 */
bool jhMiner_pushShare_primecoin(uint8 data[256], primecoinBlock_t* primecoinBlock)
{
   if( workData.protocolMode == MINER_PROTOCOL_GETWORK )
   {
      // prepare buffer to send
      fStr_buffer4kb_t fStrBuffer_parameter;
      fStr_t* fStr_parameter = fStr_alloc(&fStrBuffer_parameter, FSTR_FORMAT_UTF8);
      fStr_append(fStr_parameter, "[\""); // \"]
      fStr_addHexString(fStr_parameter, data, 256);
      fStr_appendFormatted(fStr_parameter, "\",\"");
      fStr_addHexString(fStr_parameter, (uint8*)&primecoinBlock->serverData, 32);
      fStr_append(fStr_parameter, "\"]");
      // send request
      sint32 rpcErrorCode = 0;
      jsonObject_t* jsonReturnValue = jsonClient_request(&jsonRequestTarget, "getwork", fStr_parameter, &rpcErrorCode);
      if( jsonReturnValue == NULL )
      {
         printf("PushWorkResult failed :(\n");
         return false;
      }
      else
      {
         // rpc call worked, sooooo.. is the server happy with the result?
         jsonObject_t* jsonReturnValueBool = jsonObject_getParameter(jsonReturnValue, "result");
         if( jsonObject_isTrue(jsonReturnValueBool) )
         {
            total_shares++;
            valid_shares++;
            time_t now = time(0);
            dt = ctime(&now);
            //printf("Valid share found!");
            //printf("[ %d / %d ] %s",valid_shares, total_shares,dt);
            jsonObject_freeObject(jsonReturnValue);
            return true;
         }
         else
         {
            total_shares++;
            // the server says no to this share :(
            printf("Server rejected share (BlockHeight: %d/%d nBits: 0x%08X)\n", primecoinBlock->serverData.blockHeight, jhMiner_getCurrentWorkBlockHeight(primecoinBlock->threadIndex), primecoinBlock->serverData.client_shareBits);
            jsonObject_freeObject(jsonReturnValue);
            return false;
         }
      }
      jsonObject_freeObject(jsonReturnValue);
      return false;
   }
   else if( workData.protocolMode == MINER_PROTOCOL_XPUSHTHROUGH )
{
	// printf("Queue share\n");
		xptShareToSubmit_t* xptShareToSubmit = (xptShareToSubmit_t*)malloc(sizeof(xptShareToSubmit_t));
		memset(xptShareToSubmit, 0x00, sizeof(xptShareToSubmit_t));
		memcpy(xptShareToSubmit->merkleRoot, primecoinBlock->merkleRoot, 32);
		memcpy(xptShareToSubmit->prevBlockHash, primecoinBlock->prevBlockHash, 32);
		xptShareToSubmit->version = primecoinBlock->version;
		xptShareToSubmit->nBits = primecoinBlock->nBits;
		xptShareToSubmit->nonce = primecoinBlock->nonce;
		xptShareToSubmit->nTime = primecoinBlock->timestamp;
		CBigNum bnPrimeChainMultiplier;
		bnPrimeChainMultiplier.SetHex(primecoinBlock->mpzPrimeChainMultiplier.get_str(16));
		std::vector<unsigned char> bnSerializeData = bnPrimeChainMultiplier.getvch();
		sint32 lengthBN = bnSerializeData.size();
		memcpy(xptShareToSubmit->chainMultiplier, &bnSerializeData[0], lengthBN);
		xptShareToSubmit->chainMultiplierSize = lengthBN;
		// todo: Set stuff like sieve size
		if( workData.xptClient && !workData.xptClient->disconnected)
		{
			xptClient_foundShare(workData.xptClient, xptShareToSubmit);
		        return true;
		}
		else
		{
			std::cout << "Share submission failed. The client is not connected to the pool." << std::endl;
		        return false;
		}
}
}

static double DIFFEXACTONE = 26959946667150639794667015087019630673637144422540572481103610249215.0;
static const uint64_t diffone = 0xFFFF000000000000ull;

static double target_diff(const unsigned char *target)
{
	double targ = 0;
	signed int i;

	for (i = 31; i >= 0; --i)
		targ = (targ * 0x100) + target[i];

	return DIFFEXACTONE / (targ ? targ: 1);
}

double target_diff(const uint32_t  *target)
{
	double targ = 0;
	signed int i;

	for (i = 0; i < 8; i++)
		targ = (targ * 0x100) + target[7 - i];

	return DIFFEXACTONE / ((double)targ ?  targ : 1);
   }


std::string HexBits(unsigned int nBits)
{
    union {
        int32_t nBits;
        char cBits[4];
    } uBits;
    uBits.nBits = htonl((int32_t)nBits);
    return HexStr(BEGIN(uBits.cBits), END(uBits.cBits));
}

bool IsXptClientConnected()
{
#ifdef _WIN32
	__try
	{
#endif
		if (workData.xptClient == NULL || workData.xptClient->disconnected)
			return false;
#ifdef _WIN32
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		return false;
	}
#endif

	return true;
}

int getNumThreads(void) {
  // based on code from ceretullis on SO
  uint32_t numcpu = 1; // in case we fall through;
#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
  int mib[4];
  size_t len = sizeof(numcpu); 

  /* set the mib for hw.ncpu */
  mib[0] = CTL_HW;
#ifdef HW_AVAILCPU
  mib[1] = HW_AVAILCPU;  // alternatively, try HW_NCPU;
#else
  mib[1] = HW_NCPU;
#endif
  /* get the number of CPUs from the system */
sysctl(mib, 2, &numcpu, &len, NULL, 0);

    if( numcpu < 1 )
    {
      numcpu = 1;
    }

#elif defined(__linux__) || defined(sun) || defined(__APPLE__)
  numcpu = static_cast<uint32_t>(sysconf(_SC_NPROCESSORS_ONLN));
#elif defined(_SYSTYPE_SVR4)
  numcpu = sysconf( _SC_NPROC_ONLN );
#elif defined(hpux)
  numcpu = mpctl(MPC_GETNUMSPUS, NULL, NULL);
#elif defined(_WIN32)
  SYSTEM_INFO sysinfo;
  GetSystemInfo( &sysinfo );
  numcpu = sysinfo.dwNumberOfProcessors;
#endif
  
  return numcpu;
}


void jhMiner_queryWork_primecoin()
{
   sint32 rpcErrorCode = 0;
   uint32 time1 = getTimeMilliseconds();
   jsonObject_t* jsonReturnValue = jsonClient_request(&jsonRequestTarget, "getwork", NULL, &rpcErrorCode);
   uint32 time2 = getTimeMilliseconds() - time1;
   // printf("request time: %dms\n", time2);
   if( jsonReturnValue == NULL )
   {
      printf("Getwork() failed with %serror code %d\n", (rpcErrorCode>1000)?"http ":"", rpcErrorCode>1000?rpcErrorCode-1000:rpcErrorCode);
      workData.workEntry[0].dataIsValid = false;
      return;
   }
   else
   {
      jsonObject_t* jsonResult = jsonObject_getParameter(jsonReturnValue, "result");
      jsonObject_t* jsonResult_data = jsonObject_getParameter(jsonResult, "data");
      //jsonObject_t* jsonResult_hash1 = jsonObject_getParameter(jsonResult, "hash1");
      jsonObject_t* jsonResult_target = jsonObject_getParameter(jsonResult, "target");
      jsonObject_t* jsonResult_serverData = jsonObject_getParameter(jsonResult, "serverData");
      //jsonObject_t* jsonResult_algorithm = jsonObject_getParameter(jsonResult, "algorithm");
      if( jsonResult_data == NULL )
      {
         printf("Error :(\n");
         workData.workEntry[0].dataIsValid = false;
         jsonObject_freeObject(jsonReturnValue);
         return;
      }
      // data
      uint32 stringData_length = 0;
      uint8* stringData_data = jsonObject_getStringData(jsonResult_data, &stringData_length);
      //printf("data: %.*s...\n", (sint32)min(48, stringData_length), stringData_data);

#ifdef _WIN32
      EnterCriticalSection(&workData.cs);
#else
    pthread_mutex_lock(&workData.cs);
#endif
      yPoolWorkMgr_parseHexString((char*)stringData_data, std::min<unsigned long>(128*2, stringData_length), workData.workEntry[0].data);
      workData.workEntry[0].dataIsValid = true;
      // get server data
      uint32 stringServerData_length = 0;
      uint8* stringServerData_data = jsonObject_getStringData(jsonResult_serverData, &stringServerData_length);
      memset(workData.workEntry[0].serverData, 0, 32);
      if( jsonResult_serverData )
         yPoolWorkMgr_parseHexString((char*)stringServerData_data, std::min(128*2, 32*2), workData.workEntry[0].serverData);
      // generate work hash
      uint32 workDataHash = 0x5B7C8AF4;
      for(uint32 i=0; i<stringData_length/2; i++)
      {
         workDataHash = (workDataHash>>29)|(workDataHash<<3);
         workDataHash += (uint32)workData.workEntry[0].data[i];
      }
      workData.workEntry[0].dataHash = workDataHash;
#ifdef _WIN32
      LeaveCriticalSection(&workData.cs);
#else
    pthread_mutex_unlock(&workData.cs);
#endif

      jsonObject_freeObject(jsonReturnValue);
   }
}

/*
* Returns the block height of the most recently received workload
*/
uint32 jhMiner_getCurrentWorkBlockHeight(unsigned int threadIndex)
{
   if( workData.protocolMode == MINER_PROTOCOL_GETWORK )
      return ((serverData_t*)workData.workEntry[0].serverData)->blockHeight;	
   else
      return ((serverData_t*)workData.workEntry[threadIndex].serverData)->blockHeight;
}

/*
* Worker thread mainloop for getwork() mode
*/
#ifdef _WIN32
int jhMiner_workerThread_getwork(int threadIndex){
#else
void *jhMiner_workerThread_getwork(void *arg){
uint32_t threadIndex = static_cast<uint32_t>((uintptr_t)arg);
#endif


	CSieveOfEratosthenes* psieve = NULL;
   while( true )
   {
      uint8 localBlockData[128];
      // copy block data from global workData
      uint32 workDataHash = 0;
      uint8 serverData[32];
      while( workData.workEntry[0].dataIsValid == false ) Sleep(200);
#ifdef _WIN32
      EnterCriticalSection(&workData.cs);
#else
    pthread_mutex_lock(&workData.cs);
#endif
      memcpy(localBlockData, workData.workEntry[0].data, 128);
      //seed = workData.seed;
      memcpy(serverData, workData.workEntry[0].serverData, 32);
#ifdef _WIN32
      LeaveCriticalSection(&workData.cs);
#else
    pthread_mutex_unlock(&workData.cs);
#endif
      // swap endianess
      for(uint32 i=0; i<128/4; i++)
      {
         *(uint32*)(localBlockData+i*4) = _swapEndianessU32(*(uint32*)(localBlockData+i*4));
      }
      // convert raw data into primecoin block
      primecoinBlock_t primecoinBlock = {0};
      memcpy(&primecoinBlock, localBlockData, 80);
      // we abuse the timestamp field to generate an unique hash for each worker thread...
      primecoinBlock.timestamp += threadIndex;
      primecoinBlock.threadIndex = threadIndex;
      primecoinBlock.xptMode = (workData.protocolMode == MINER_PROTOCOL_XPUSHTHROUGH);
      // ypool uses a special encrypted serverData value to speedup identification of merkleroot and share data
      memcpy(&primecoinBlock.serverData, serverData, 32);
      // start mining
      if (!BitcoinMiner(&primecoinBlock, psieve, threadIndex, nonceStep))
         break;
      primecoinBlock.mpzPrimeChainMultiplier = 0;
   }
	if( psieve )
	{
		delete psieve;
		psieve = NULL;
	}
   return 0;
}

/*
 * Worker thread mainloop for xpt() mode
 */
#ifdef _WIN32
int jhMiner_workerThread_xpt(int threadIndex)
{
#else
void *jhMiner_workerThread_xpt(void *arg){
uint32_t threadIndex = static_cast<uint32_t>((uintptr_t)arg);
#endif
	CSieveOfEratosthenes* psieve = NULL;
	while( true )
	{
      uint8 localBlockData[128];
		uint32 workDataHash = 0;
		uint8 serverData[32];
		while( workData.workEntry[threadIndex].dataIsValid == false ) Sleep(50);
#ifdef _WIN32
		EnterCriticalSection(&workData.cs);
#else
    pthread_mutex_lock(&workData.cs);
#endif
		memcpy(localBlockData, workData.workEntry[threadIndex].data, 128);
		memcpy(serverData, workData.workEntry[threadIndex].serverData, 32);
		workDataHash = workData.workEntry[threadIndex].dataHash;
#ifdef _WIN32
		LeaveCriticalSection(&workData.cs);
#else
    pthread_mutex_unlock(&workData.cs);
#endif
		primecoinBlock_t primecoinBlock = {0};
		memcpy(&primecoinBlock, localBlockData, 80);
		primecoinBlock.timestamp += threadIndex;
		primecoinBlock.threadIndex = threadIndex;
		primecoinBlock.xptMode = (workData.protocolMode == MINER_PROTOCOL_XPUSHTHROUGH);
		// ypool uses a special encrypted serverData value to speedup identification of merkleroot and share data
		memcpy(&primecoinBlock.serverData, serverData, 32);
		// start mining
		//uint32 time1 = getTimeMilliseconds();
      if (!BitcoinMiner(&primecoinBlock, psieve, threadIndex, nonceStep))
         break;
		//printf("Mining stopped after %dms\n", getTimeMilliseconds()-time1);
		primecoinBlock.mpzPrimeChainMultiplier = 0;
	}
	if( psieve )
	{
		delete psieve;
		psieve = NULL;
	}
	return 0;
}

typedef struct
{
	char* workername;
	char* workerpass;
	char* host;
   unsigned int port;
   unsigned int numThreads;
   unsigned int sieveSize;
	unsigned int L1CacheElements;
   unsigned int targetOverride;
   unsigned int initialPrimorial;
   unsigned int sieveExtensions;
}commandlineInput_t;

commandlineInput_t commandlineInput = {0};

void jhMiner_printHelp() {
   puts("Usage: pxpminer [options]");
   puts("Options:");
   puts("   -o, -O                        The miner will connect to this url");
   puts("                                 You can specifiy an port after the url using -o url:port");
   puts("   -u                            The username (workername) used for login");
   puts("   -p                            The password used for login");
   puts("   -t <num>                      The number of threads for mining (default ALL Threads)");
   puts("                                     For most efficient mining, set to number of CPU cores");
   puts("   -layers <num>                 Set Sieve Layers: Allowed: 9 to 12");
   puts("   -split <num>                  Split Primorials by Thread (default 0)");
   puts("   -m <num>                      Primorial #1: Allowed: 31 to 107");
   puts("   -m2 <num>                     Primorial #2: Allowed: 31 to 107 | 0 to Disable");
   puts("   -m3 <num>                     Primorial #3: Allowed: 31 to 107 | 0 to Disable");
   puts("   -m4 <num>                     Primorial #4: Allowed: 31 to 107 | 0 to Disable");
   puts("   -m5 <num>                     Primorial #5: Allowed: 31 to 107 | 0 to Disable");
   puts("   -m6 <num>                     Primorial #6: Allowed: 31 to 107 | 0 to Disable");
   puts("   -m7 to -m16 <num>               Additional Primorials");
   puts("                                   Recommended Primorials are: 31, 37, 41, 43, 47, 53");
   puts("   -s <num>                      Set MaxSieveSize: Minimum 512000, 64000 Increments");
   puts("   -c <num>                      Set Chunk Size: Minimum 64000, 64000 Increments");
   puts("Example usage:");
   puts("   pxpminer -o http://ypool.net:10034 -u workername.1 -p workerpass -t 4");
   puts("Press any key to continue...");
   getchar();
}

void jhMiner_printHelp2() {
   puts("Usage: pxpminer [options]");
   puts("Options:");
   puts("   -o, -O            The miner will connect to this url");
   puts("                       You can specifiy an port after the url using -o url:port");
   puts("   -u                The username (workername) used for login");
   puts("   -p                The password used for login");
   puts("   -t <num>          The number of threads for mining (default ALL Threads)");
   puts("                       For most efficient mining, set to number of CPU cores");
   puts("   -layers <num>     Set Sieve Layers: Allowed: 9 to 12");
   puts("   -split <num>      Split Primorials by Thread (default 0)");
   puts("   -m <num>          Primorial #1: Allowed: 31 to 107");
   puts("   -m2 <num>         Primorial #2: Allowed: 31 to 107 | 0 to Disable");
   puts("   -m3 <num>         Primorial #3: Allowed: 31 to 107 | 0 to Disable");
   puts("   -m4 <num>         Primorial #4: Allowed: 31 to 107 | 0 to Disable");
   puts("   -m5 <num>         Primorial #5: Allowed: 31 to 107 | 0 to Disable");
   puts("   -m6 <num>         Primorial #6: Allowed: 31 to 107 | 0 to Disable");
   puts("   -m7 to -m16 <num>   Additional Primorials");
   puts("                       Recommended Primorials are: 31, 37, 41, 43, 47, 53");
   puts("   -s <num>          Set MaxSieveSize: Minimum 512000, 64000 Increments");
   puts("   -c <num>          Set Chunk Size: Minimum 64000, 64000 Increments");
   puts("Additional In-Miner Commands:");
   puts("   <Ctrl-C>, <Q> - Quit");
   puts("   <s> - Print current settings");
   puts("   <h> - Print Help (This screen)");
   puts("   <m> - Toggle SPS Messages");
   puts("   <p> - Print Primorial Stats");
}

void PrintPrimorialStats() {
	double statsPassedTime = (double)(getTimeMilliseconds() - primeStats.primeLastUpdate);
	printf("══════════════════════════════════════════════════════════════════════════════\n");
	printf("        [    7ch] [    8ch] [    9ch] [   10ch] [   11ch] [  12ch+]\n");
	for (int i=0;i<112;i++) {
		if (primeStats.chainCounter2[i][0]>0) {
			printf("%6d: [%7d] [%7d] [%7d] [%7d] [%7d] [%7d]\n",
				i,
				primeStats.chainCounter2[i][7],
				primeStats.chainCounter2[i][8],
				primeStats.chainCounter2[i][9],
				primeStats.chainCounter2[i][10],
				primeStats.chainCounter2[i][11],
				primeStats.chainCounter2[i][12]
			);
		}
	}
	printf("══════════════════════════════════════════════════════════════════════════════\n");
}

void jhMiner_parseCommandline(int argc, char **argv)
{
	using namespace std;
	sint32 cIdx = 1;
	while( cIdx < argc )
	{
		char* argument = argv[cIdx];
		cIdx++;
		if( memcmp(argument, "-o", 3)==0 || memcmp(argument, "-O", 3)==0 )
		{
			// -o
			if( cIdx >= argc )
			{
				cout << "Missing URL after -o option" << endl;
				exit(0);
			}
			if( strstr(argv[cIdx], "http://") )
				commandlineInput.host = fStrDup(strstr(argv[cIdx], "http://")+7);
			else
				commandlineInput.host = fStrDup(argv[cIdx]);
			char* portStr = strstr(commandlineInput.host, ":");
			if( portStr )
			{
				*portStr = '\0';
				commandlineInput.port = atoi(portStr+1);
			}
			cIdx++;
		}
		else if( memcmp(argument, "-u", 3)==0 )
		{
			// -u
			if( cIdx >= argc )
			{
				cout << "Missing username/workername after -u option" << endl;
				exit(0);
			}
			commandlineInput.workername = fStrDup(argv[cIdx], 64);
			cIdx++;
		}
		else if( memcmp(argument, "-p", 3)==0 )
		{
			// -p
			if( cIdx >= argc )
			{
				cout << "Missing password after -p option" << endl;
				exit(0);
			}
			commandlineInput.workerpass = fStrDup(argv[cIdx], 64);
			cIdx++;
		}
		else if( memcmp(argument, "-t", 3)==0 )
		{
			// -t
			if( cIdx >= argc )
			{
				cout << "Missing thread number after -t option" << endl;
				exit(0);
			}
			commandlineInput.numThreads = atoi(argv[cIdx]);
			if( commandlineInput.numThreads < 1 || commandlineInput.numThreads > 128 )
			{
				cout << "-t parameter out of range" << endl;
				exit(0);
			}
         cIdx++;
      } else if (memcmp(argument, "-m", 3)==0) {
         commandlineInput.initialPrimorial = atoi(argv[cIdx]);
		 if (commandlineInput.initialPrimorial < 11)  { commandlineInput.initialPrimorial = 11; }
		 if (commandlineInput.initialPrimorial > 111)  { commandlineInput.initialPrimorial = 111; }
         cIdx++;
      } else if (memcmp(argument, "-m2", 4)==0) {
         unsigned int tempMult = atoi(argv[cIdx]);
		 if (tempMult > 0 && tempMult < 11)  { tempMult = 11; }
		 if (tempMult > 111)  { tempMult = 111; }
		 if (tempMult > 0) { primeStats.nPrimorials.push_back(tempMult); }
		 cIdx++;
      } else if (memcmp(argument, "-m3", 4)==0) {
         unsigned int tempMult = atoi(argv[cIdx]);
		 if (tempMult > 0 && tempMult < 11)  { tempMult = 11; }
		 if (tempMult > 111)  { tempMult = 111; }
		 if (tempMult > 0) { primeStats.nPrimorials.push_back(tempMult); }
         cIdx++;
      } else if (memcmp(argument, "-m4", 4)==0) {
         unsigned int tempMult = atoi(argv[cIdx]);
		 if (tempMult > 0 && tempMult < 11)  { tempMult = 11; }
		 if (tempMult > 111)  { tempMult = 111; }
		 if (tempMult > 0) { primeStats.nPrimorials.push_back(tempMult); }
         cIdx++;
      } else if (memcmp(argument, "-m5", 4)==0) {
         unsigned int tempMult = atoi(argv[cIdx]);
		 if (tempMult > 0 && tempMult < 11)  { tempMult = 11; }
		 if (tempMult > 111)  { tempMult = 111; }
		 if (tempMult > 0) { primeStats.nPrimorials.push_back(tempMult); }
         cIdx++;
      } else if (memcmp(argument, "-m6", 4)==0) {
         unsigned int tempMult = atoi(argv[cIdx]);
		 if (tempMult > 0 && tempMult < 11)  { tempMult = 11; }
		 if (tempMult > 111)  { tempMult = 111; }
		 if (tempMult > 0) { primeStats.nPrimorials.push_back(tempMult); }
         cIdx++;
      } else if (memcmp(argument, "-m7", 4)==0) {
         unsigned int tempMult = atoi(argv[cIdx]);
		 if (tempMult > 0 && tempMult < 11)  { tempMult = 11; }
		 if (tempMult > 111)  { tempMult = 111; }
		 if (tempMult > 0) { primeStats.nPrimorials.push_back(tempMult); }
         cIdx++;
      } else if (memcmp(argument, "-m8", 4)==0) {
         unsigned int tempMult = atoi(argv[cIdx]);
		 if (tempMult > 0 && tempMult < 11)  { tempMult = 11; }
		 if (tempMult > 111)  { tempMult = 111; }
		 if (tempMult > 0) { primeStats.nPrimorials.push_back(tempMult); }
         cIdx++;
      } else if (memcmp(argument, "-m9", 4)==0) {
         unsigned int tempMult = atoi(argv[cIdx]);
		 if (tempMult > 0 && tempMult < 11)  { tempMult = 11; }
		 if (tempMult > 111)  { tempMult = 111; }
		 if (tempMult > 0) { primeStats.nPrimorials.push_back(tempMult); }
         cIdx++;
      } else if (memcmp(argument, "-m10", 4)==0) {
         unsigned int tempMult = atoi(argv[cIdx]);
		 if (tempMult > 0 && tempMult < 11)  { tempMult = 11; }
		 if (tempMult > 111)  { tempMult = 111; }
		 if (tempMult > 0) { primeStats.nPrimorials.push_back(tempMult); }
         cIdx++;
      } else if (memcmp(argument, "-m11", 4)==0) {
         unsigned int tempMult = atoi(argv[cIdx]);
		 if (tempMult > 0 && tempMult < 11)  { tempMult = 11; }
		 if (tempMult > 111)  { tempMult = 111; }
		 if (tempMult > 0) { primeStats.nPrimorials.push_back(tempMult); }
			cIdx++;
      } else if (memcmp(argument, "-m12", 4)==0) {
         unsigned int tempMult = atoi(argv[cIdx]);
		 if (tempMult > 0 && tempMult < 11)  { tempMult = 11; }
		 if (tempMult > 111)  { tempMult = 111; }
		 if (tempMult > 0) { primeStats.nPrimorials.push_back(tempMult); }
			cIdx++;
      } else if (memcmp(argument, "-m13", 4)==0) {
         unsigned int tempMult = atoi(argv[cIdx]);
		 if (tempMult > 0 && tempMult < 11)  { tempMult = 11; }
		 if (tempMult > 111)  { tempMult = 111; }
		 if (tempMult > 0) { primeStats.nPrimorials.push_back(tempMult); }
			cIdx++;
      } else if (memcmp(argument, "-m14", 4)==0) {
         unsigned int tempMult = atoi(argv[cIdx]);
		 if (tempMult > 0 && tempMult < 11)  { tempMult = 11; }
		 if (tempMult > 111)  { tempMult = 111; }
		 if (tempMult > 0) { primeStats.nPrimorials.push_back(tempMult); }
         cIdx++;
      } else if (memcmp(argument, "-m15", 4)==0) {
         unsigned int tempMult = atoi(argv[cIdx]);
		 if (tempMult > 0 && tempMult < 11)  { tempMult = 11; }
		 if (tempMult > 111)  { tempMult = 111; }
		 if (tempMult > 0) { primeStats.nPrimorials.push_back(tempMult); }
         cIdx++;
      } else if (memcmp(argument, "-m16", 4)==0) {
         unsigned int tempMult = atoi(argv[cIdx]);
		 if (tempMult > 0 && tempMult < 11)  { tempMult = 11; }
		 if (tempMult > 111)  { tempMult = 111; }
		 if (tempMult > 0) { primeStats.nPrimorials.push_back(tempMult); }
         cIdx++;
      } else if (memcmp(argument, "-se", 4)==0) {
			commandlineInput.sieveExtensions = atoi(argv[cIdx]);
			if( commandlineInput.sieveExtensions <= 1 || commandlineInput.sieveExtensions > 15 )
			{
				cout << "-se parameter out of range, must be between 0 - 15" << endl;
				exit(0);
			}
         cIdx++;
      } else if (memcmp(argument, "-admnFunc", 10)==0) {
         primeStats.adminFunc = ((atoi(argv[cIdx])==45635352432543)?(true):(false));
         cIdx++;
      } else if (memcmp(argument, "-layers", 8)==0) {
		  commandlineInput.targetOverride = atoi(argv[cIdx]);
		  if (commandlineInput.targetOverride < 6)  { commandlineInput.targetOverride = 6; }
		  if (commandlineInput.targetOverride > 12)  { commandlineInput.targetOverride = 12; }
		  cIdx++;
	  } else if (memcmp(argument, "-split", 7)==0) {
		  int tSplit = atoi(argv[cIdx]);
		  if (tSplit <= 0)  { primeStats.tSplit = false; } else  { primeStats.tSplit = true; }
		  cIdx++;
	  } else if (memcmp(argument, "-s", 3)==0) {
         commandlineInput.sieveSize = atoi(argv[cIdx]);
         if (commandlineInput.sieveSize < 512000) { commandlineInput.sieveSize=512000; }
		 commandlineInput.sieveSize = ceil((double) commandlineInput.sieveSize/64000)*64000;
			cIdx++;
      } else if (memcmp(argument, "-c", 3)==0) {
         commandlineInput.L1CacheElements = atoi(argv[cIdx]);
		 if (commandlineInput.L1CacheElements < 64000) { commandlineInput.L1CacheElements=64000; }
		 commandlineInput.L1CacheElements = ceil((double) commandlineInput.L1CacheElements/64000)*64000;
         cIdx++;
      }

		else if( memcmp(argument, "-help", 6)==0 || memcmp(argument, "--help", 7)==0 )
		{
			jhMiner_printHelp();
			exit(0);
		}
		else
		{
			cout << "'" << argument << "' is an unknown option." << endl;
			#ifdef _WIN32
				cout << "Type pxpminer -help for more info" << endl;
			#else
				cout << "Type pxpminer -help for more info" << endl; 
			#endif
			exit(-1);
		}
	}
	if( argc <= 1 )
	{
		jhMiner_printHelp();
		exit(0);
	}
}

#ifdef _WIN32
typedef std::pair <DWORD, HANDLE> thMapKeyVal;
DWORD * threadHearthBeat;

static void watchdog_thread(std::map<DWORD, HANDLE> &threadMap)
#else
static void *watchdog_thread(void *)

#endif
{
#if defined (_WIN32) || defined (_WIN64)
		std::map <DWORD, HANDLE> :: const_iterator thMap_Iter;
#endif
	   	uint32 maxIdelTime = 30 * 1000;
	   while(true)
		{
      if ((workData.protocolMode == MINER_PROTOCOL_XPUSHTHROUGH) && (!IsXptClientConnected()))
      {
         // Miner is not connected, wait 5 secs before trying again.
         Sleep(5000);
					continue;
	}
#ifdef _WIN32

	uint64 currentTick = getTimeMilliseconds();
	for (int i = 0; i < threadMap.size(); i++){
		DWORD heartBeatTick = threadHearthBeat[i];
		if (currentTick - heartBeatTick > maxIdelTime){
			//restart the thread
				std::cout << "Restarting thread " << i << std::endl;
			//__try
			//{
				//HANDLE h = threadMap.at(i);
				thMap_Iter = threadMap.find(i);
				if (thMap_Iter != threadMap.end()){
					HANDLE h = thMap_Iter->second;
					TerminateThread( h, 0);
					Sleep(1000);
					CloseHandle(h);
					Sleep(1000);
					threadHearthBeat[i] = getTimeMilliseconds();
					threadMap.erase(thMap_Iter);
					h = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)jhMiner_workerThread_xpt, (LPVOID)i, 0, 0);
					SetThreadPriority(h, THREAD_PRIORITY_BELOW_NORMAL);
					threadMap.insert(thMapKeyVal(i,h));
				}
		}
	}
#else
	//on linux just exit
	exit(-2000);
#endif
	Sleep( 1*1000);
	}
}

void PrintCurrentSettings() {
	unsigned long uptime = (getTimeMilliseconds() - primeStats.startTime);
	unsigned int days = uptime / (24 * 60 * 60 * 1000);
    uptime %= (24 * 60 * 60 * 1000);
    unsigned int hours = uptime / (60 * 60 * 1000);
    uptime %= (60 * 60 * 1000);
    unsigned int minutes = uptime / (60 * 1000);
    uptime %= (60 * 1000);
    unsigned int seconds = uptime / (1000);

   printf("\n--------------------------------------------------------------------------------\n");	
	printf("Worker name (-u): %s\n", commandlineInput.workername);
	printf("Number of mining threads (-t): %u\n", commandlineInput.numThreads);
	printf("Primorials: %u",primeStats.nPrimorials[0]);
	for (unsigned int i=1;i<primeStats.nPrimorialsSize;i++) { printf(", %u", primeStats.nPrimorials[i]); }
	printf("\n");
	printf("Sieve Size (-s): %u\n", nMaxSieveSize);
	printf("Chunk Size (-c): %u\n", primeStats.nL1CacheElements);
	printf("Max Primes: Variable\n");
	printf("Cunninghame Layers (-layers): %u\n", nOverrideTargetValue);
	printf("BiTwin Layers: %u\n", nOverrideBTTargetValue);
	printf("Sieve Extensions (-se): %u\n", nSieveExtensions);	
   printf("Total Runtime: %u Days, %u Hours, %u minutes, %u seconds\n", days, hours, minutes, seconds);	
   printf("Total Share Value submitted to the Pool: %.05f\n", primeStats.fTotalSubmittedShareValue);	
   printf("--------------------------------------------------------------------------------\n\n");
}



bool appQuitSignal = false;

#ifdef _WIN32
static void input_thread(){
#else
void *input_thread(void *){
static struct termios oldt, newt;
    /*tcgetattr gets the parameters of the current terminal
    STDIN_FILENO will tell tcgetattr that it should write the settings
    of stdin to oldt*/
    tcgetattr( STDIN_FILENO, &oldt);
    /*now the settings will be copied*/
    newt = oldt;

    /*ICANON normally takes care that one line at a time will be processed
    that means it will return if it sees a "\n" or an EOF or an EOL*/
    newt.c_lflag &= ~(ICANON);          

    /*Those new settings will be set to STDIN
    TCSANOW tells tcsetattr to change attributes immediately. */
    tcsetattr( STDIN_FILENO, TCSANOW, &newt);


#endif

	while (true) {
		int input = getchar();
		switch (input) {
		case 'q': case 'Q': case 3: //case 27:
			appQuitSignal = true;
         Sleep(2200);
			std::exit(0);
#ifdef _WIN32
			return;
#else
			/*restore the old settings*/
    tcsetattr( STDIN_FILENO, TCSANOW, &oldt);
	return 0;
#endif
			break;
	  case 's': case 'S':
         PrintCurrentSettings();
         break;
	  case 'h': case 'H':
         jhMiner_printHelp2();
         break;
	  case 'p':
		  PrintPrimorialStats();
         break;
	  case 'd':
		  if (primeStats.adminFunc) {
			if (nPrintDebugMessages == true) { nPrintDebugMessages = false;printf("Debug Messages: Disabled\n"); } else { nPrintDebugMessages = true;printf("Debug Messages: Enabled\n"); }
		  }
         break;
	  case 'm':
		  if (nPrintSPSMessages == true) { nPrintSPSMessages = false;printf("SPS Messages: Disabled\n"); } else { nPrintSPSMessages = true;printf("SPS Messages: Enabled\n"); }
			break;
	  case '1':
		 if (primeStats.adminFunc) {
			if (nMaxSieveSize > 64000) { nMaxSieveSize -= 64000; }
			printf("SieveSize: %u\n", nMaxSieveSize);
		 }
         break;
	  case '2':
		 if (primeStats.adminFunc) {
			if (nMaxSieveSize < 64000000) { nMaxSieveSize += 64000; }
			printf("SieveSize: %u\n", nMaxSieveSize);
		 }
			break;
	  case 'e':
		 if (primeStats.adminFunc) {
			if (nMaxSieveSize > 640000) { nMaxSieveSize -= 640000; }
			printf("SieveSize: %u\n", nMaxSieveSize);
		 }
		break;
	  case 'r':
		 if (primeStats.adminFunc) {
			if (nMaxSieveSize < 64000000) { nMaxSieveSize += 640000; }
			printf("SieveSize: %u\n", nMaxSieveSize);
		 }
		break;
      case 0: case 224: {
            input = getchar();	
            switch (input) {
            case 72: // key up
				if (primeStats.adminFunc) {
					if (nOverrideTargetValue<12) { nOverrideTargetValue++;nOverrideBTTargetValue=nOverrideTargetValue; }
					printf("Layers: %u\n", nOverrideTargetValue);
		}
			}
				break;
            case 80: // key down
				if (primeStats.adminFunc) {
					if (nOverrideTargetValue>5) { nOverrideTargetValue--;nOverrideBTTargetValue=nOverrideTargetValue; }
					printf("Layers: %u\n", nOverrideTargetValue);
	}
				break;
			case 75: // key left
				if (primeStats.adminFunc) {
					if (primeStats.pMult>20) { primeStats.pMult -= 10; }
					printf("Primes Adjustment: %u\n", primeStats.pMult);
}
				break;
			case 77: // key right
				if (primeStats.adminFunc) {
					if (primeStats.pMult<20000) { primeStats.pMult += 10; }
					printf("Primes Adjustment: %u\n", primeStats.pMult);
					}
					break;
		}
	  }
		Sleep(20);
	}
#ifdef _WIN32
	return;
#else
	/*restore the old settings*/
    tcsetattr( STDIN_FILENO, TCSANOW, &oldt);
    return 0;
#endif

}
/*
* Mainloop when using getwork() mode
*/
int jhMiner_main_getworkMode()
{
#ifdef _WIN32
   // start the Auto Tuning thread
   //CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)RoundSieveAutoTuningWorkerThread, NULL, 0, 0);
   CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)input_thread, NULL, 0, 0);

   // start threads
   // Although we create all the required heartbeat structures, there is no heartbeat watchdog in GetWork mode. 
   std::map<DWORD, HANDLE> threadMap;
   threadHearthBeat = (DWORD *)malloc( commandlineInput.numThreads * sizeof(DWORD));
   // start threads
   for(sint32 threadIdx=0; threadIdx<commandlineInput.numThreads; threadIdx++)
   {
      HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)jhMiner_workerThread_getwork, (LPVOID)threadIdx, 0, 0);
      SetThreadPriority(hThread, THREAD_PRIORITY_BELOW_NORMAL);
      threadMap.insert(thMapKeyVal(threadIdx,hThread));
      threadHearthBeat[threadIdx] = getTimeMilliseconds();
   }

#else
	uint32_t totalThreads = commandlineInput.numThreads;

  pthread_t threads[totalThreads];
  // start the Auto Tuning thread
	
//    pthread_create(&threads[commandlineInput.numThreads+1], NULL, CacheAutoTuningWorkerThread, (void *)(bool)commandlineInput.enableCacheTunning);
//  pthread_create(&threads[commandlineInput.numThreads+2], NULL, RoundSieveAutoTuningWorkerThread, NULL);
  pthread_create(&threads[commandlineInput.numThreads], NULL, input_thread, NULL);
	pthread_attr_t threadAttr;
  pthread_attr_init(&threadAttr);
  // Set the stack size of the thread
  pthread_attr_setstacksize(&threadAttr, 120*1024);
  // free resources of thread upon return
  pthread_attr_setdetachstate(&threadAttr, PTHREAD_CREATE_DETACHED);
  
  // start threads
	for(uint32 threadIdx=0; threadIdx<commandlineInput.numThreads; threadIdx++)
  {
	pthread_create(&threads[threadIdx], &threadAttr, jhMiner_workerThread_getwork, (void *)threadIdx);
  }
  pthread_attr_destroy(&threadAttr);
#endif



   // main thread, query work every 8 seconds
   sint32 loopCounter = 0;
   while( true )
   {
      // query new work
      jhMiner_queryWork_primecoin();
      // calculate stats every second tick
      if( loopCounter&1 )
      {
         double statsPassedTime = (double)(getTimeMilliseconds() - primeStats.primeLastUpdate);
         if( statsPassedTime < 1.0 )
            statsPassedTime = 1.0; // avoid division by zero
         double primesPerSecond = (double)primeStats.primeChainsFound / (statsPassedTime / 1000.0);
         primeStats.primeLastUpdate = getTimeMilliseconds();
         primeStats.primeChainsFound = 0;
         uint32 bestDifficulty = primeStats.bestPrimeChainDifficulty;
         primeStats.bestPrimeChainDifficulty = 0;
         double primeDifficulty = (double)bestDifficulty / (double)0x1000000;
         if( workData.workEntry[0].dataIsValid )
         {
            primeStats.bestPrimeChainDifficultySinceLaunch = std::max((float)primeStats.bestPrimeChainDifficultySinceLaunch, (float)primeDifficulty);
            printf("primes/s: %d best difficulty: %f record: %f\n", (sint32)primesPerSecond, (float)primeDifficulty, (float)primeStats.bestPrimeChainDifficultySinceLaunch);
         }
      }		
      // wait and check some stats
      uint32 time_updateWork = getTimeMilliseconds();
      while( true )
      {
         uint32 passedTime = getTimeMilliseconds() - time_updateWork;
         if( passedTime >= 4000 )
            break;
         Sleep(200);
      }
      loopCounter++;
   }
   return 0;
}

/*
 * Mainloop when using xpt mode
 */
int jhMiner_main_xptMode()
{
	#ifdef _WIN32
	// start the Auto Tuning thread
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)input_thread, NULL, 0, 0);


   std::map<DWORD, HANDLE> threadMap;
   threadHearthBeat = (DWORD *)malloc( commandlineInput.numThreads * sizeof(uint64));
	// start threads
	for(sint32 threadIdx=0; threadIdx<commandlineInput.numThreads; threadIdx++)
	{
		HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)jhMiner_workerThread_xpt, (LPVOID)threadIdx, 0, 0);
		SetThreadPriority(hThread, THREAD_PRIORITY_BELOW_NORMAL);
      threadMap.insert(thMapKeyVal(threadIdx,hThread));
      threadHearthBeat[threadIdx] = getTimeMilliseconds();
	}

 CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)watchdog_thread, (LPVOID)&threadMap, 0, 0);

#else
	uint32_t totalThreads = commandlineInput.numThreads;

  pthread_t threads[totalThreads];
  // start the Auto Tuning thread

  //pthread_create(&threads[commandlineInput.numThreads+1], NULL, CacheAutoTuningWorkerThread, (void *)(bool)commandlineInput.enableCacheTunning);
  //pthread_create(&threads[commandlineInput.numThreads+2], NULL, RoundSieveAutoTuningWorkerThread, NULL);
  pthread_create(&threads[commandlineInput.numThreads], NULL, input_thread, NULL);
	pthread_attr_t threadAttr;
  pthread_attr_init(&threadAttr);
  // Set the stack size of the thread
  pthread_attr_setstacksize(&threadAttr, 120*1024);
  // free resources of thread upon return
  pthread_attr_setdetachstate(&threadAttr, PTHREAD_CREATE_DETACHED);
  
  // start threads
	for(uint32 threadIdx=0; threadIdx<commandlineInput.numThreads; threadIdx++)
  {
	pthread_create(&threads[threadIdx], &threadAttr, jhMiner_workerThread_xpt, (void *)threadIdx);
  }
  pthread_attr_destroy(&threadAttr);
#endif
	// main thread, don't query work, just wait and process
	sint32 loopCounter = 0;
	uint32 xptWorkIdentifier = 0xFFFFFFFF;
   //unsigned long lastFiveChainCount = 0;
   //unsigned long lastFourChainCount = 0;
	while( true )
	{
		if (appQuitSignal)
         return 0;

      if (loopCounter % 3 == 0) {
         double totalRunTime = (double)(getTimeMilliseconds() - primeStats.startTime);
         double statsPassedTime = (double)(getTimeMilliseconds() - primeStats.primeLastUpdate);
			if( statsPassedTime < 1.0 )
				statsPassedTime = 1.0; // avoid division by zero
			double primesPerSecond = (double)primeStats.primeChainsFound / (statsPassedTime / 1000.0);
			primeStats.primeLastUpdate = getTimeMilliseconds();
			primeStats.primeChainsFound = 0;
         		float avgCandidatesPerRound = (double)primeStats.nCandidateCount / primeStats.nSieveRounds;
       			float sievesPerSecond = (double)primeStats.nSieveRounds / (statsPassedTime / 1000.0);
 			primeStats.primeLastUpdate = getTimeMilliseconds();
        		primeStats.nCandidateCount = 10;
         		primeStats.nSieveRounds = 0;
         primeStats.primeChainsFound = 0;

         if (workData.workEntry[0].dataIsValid) {
            statsPassedTime = (double)(getTimeMilliseconds() - primeStats.blockStartTime);
			if (statsPassedTime < 1.0) { statsPassedTime = 1.0; } // avoid division by zero
			if (nPrintSPSMessages) {
				double shareValuePerHour = primeStats.fShareValue / totalRunTime * 3600000.0;
				uint64 NPS = ((nMaxSieveSize * ((nSieveExtensions/2)+1)) * sievesPerSecond);
				printf("Val/h:%8f - PPS:%d - SPS:%.03f - ACC:%d - NPS:%u\n", shareValuePerHour, (sint32)primesPerSecond, sievesPerSecond, (sint32)avgCandidatesPerRound, (uint64)NPS);
				std::cout << std::setprecision(8);
				std::cout << std::endl;
            }
			}
			}
		// wait and check some stats
		uint64 time_updateWork = getTimeMilliseconds();
		while( true )
		{
			uint64 tickCount = getTimeMilliseconds();
			uint64 passedTime = tickCount - time_updateWork;


			if( passedTime >= 4000 )
				break;
			xptClient_process(workData.xptClient);
			char* disconnectReason = false;
			if( workData.xptClient == NULL || xptClient_isDisconnected(workData.xptClient, &disconnectReason) )
			{
				// disconnected, mark all data entries as invalid
				for(uint32 i=0; i<128; i++)
					workData.workEntry[i].dataIsValid = false;
				std::cout << "xpt: Disconnected, auto reconnect in 30 seconds"<<std::endl;
				if( workData.xptClient && disconnectReason )
						std::cout << "xpt: Disconnect reason: " << disconnectReason << std::endl;
				Sleep(30*1000);
				if( workData.xptClient )
					xptClient_free(workData.xptClient);
				xptWorkIdentifier = 0xFFFFFFFF;
				while( true )
				{
					workData.xptClient = xptClient_connect(&jsonRequestTarget, commandlineInput.numThreads);
					if( workData.xptClient )
						break;
				}
			}
			// has the block data changed?
			if( workData.xptClient && xptWorkIdentifier != workData.xptClient->workDataCounter )
			{
				// printf("New work\n");
				xptWorkIdentifier = workData.xptClient->workDataCounter;
				for(uint32 i=0; i<workData.xptClient->payloadNum; i++)
				{
					uint8 blockData[256];
					memset(blockData, 0x00, sizeof(blockData));
					*(uint32*)(blockData+0) = workData.xptClient->blockWorkInfo.version;
					memcpy(blockData+4, workData.xptClient->blockWorkInfo.prevBlock, 32);
					memcpy(blockData+36, workData.xptClient->workData[i].merkleRoot, 32);
					*(uint32*)(blockData+68) = workData.xptClient->blockWorkInfo.nTime;
					*(uint32*)(blockData+72) = workData.xptClient->blockWorkInfo.nBits;
					*(uint32*)(blockData+76) = 0; // nonce
					memcpy(workData.workEntry[i].data, blockData, 80);
					((serverData_t*)workData.workEntry[i].serverData)->blockHeight = workData.xptClient->blockWorkInfo.height;
					((serverData_t*)workData.workEntry[i].serverData)->nBitsForShare = workData.xptClient->blockWorkInfo.nBitsShare;

					// is the data really valid?
					if( workData.xptClient->blockWorkInfo.nTime > 0 )
						workData.workEntry[i].dataIsValid = true;
					else
						workData.workEntry[i].dataIsValid = false;
				}
            if (workData.xptClient->blockWorkInfo.height > 0) {
			   uint32 bestDifficulty = primeStats.bestPrimeChainDifficulty;
			   double primeDifficulty = GetChainDifficulty(bestDifficulty);
			   primeStats.bestPrimeChainDifficultySinceLaunch = std::max((float)primeStats.bestPrimeChainDifficultySinceLaunch, (float)primeDifficulty);

               double totalRunTime = (double)(getTimeMilliseconds() - primeStats.startTime);
               double statsPassedTime = (double)(getTimeMilliseconds() - primeStats.primeLastUpdate);
               if( statsPassedTime < 1.0 ) statsPassedTime = 1.0; // avoid division by zero
					double poolDiff = GetPrimeDifficulty( workData.xptClient->blockWorkInfo.nBitsShare);
					double blockDiff = GetPrimeDifficulty( workData.xptClient->blockWorkInfo.nBits);
						std::cout << std::endl << "══════════════════════════════════════════════════════════════════════════════" << std::endl;
						std::cout << "New Block: " << workData.xptClient->blockWorkInfo.height << " - Diff: " << blockDiff << " / " << poolDiff << std::endl;
						std::cout << "Valid/Total shares: [ " << valid_shares << " / " << total_shares << " ]  -  Max diff: " << primeStats.bestPrimeChainDifficultySinceLaunch << std::endl;
						 printf("        [    7ch] [    8ch] [    9ch] [   10ch] [   11ch] [  12ch+]\n");

               statsPassedTime = (double)(getTimeMilliseconds() - primeStats.blockStartTime);

               if( statsPassedTime < 1.0 ) statsPassedTime = 1.0; // avoid division by zero
			   printf(" Total: [%7d] [%7d] [%7d] [%7d] [%7d] [%7d]\n",
				   primeStats.chainCounter[0][7],
				   primeStats.chainCounter[0][8],
				   primeStats.chainCounter[0][9],
				   primeStats.chainCounter[0][10],
				   primeStats.chainCounter[0][11],
				   primeStats.chainCounter[0][12]
			   );
			   printf("  ch/h: [%7.03f] [%7.03f] [%7.03f] [%7.03f] [%7.03f] [%7.03f]\n",
				   ((double)primeStats.chainCounter[0][7] / statsPassedTime) * 3600000.0,
				   ((double)primeStats.chainCounter[0][8] / statsPassedTime) * 3600000.0,
				   ((double)primeStats.chainCounter[0][9] / statsPassedTime) * 3600000.0,
				   ((double)primeStats.chainCounter[0][10] / statsPassedTime) * 3600000.0,
				   ((double)primeStats.chainCounter[0][11] / statsPassedTime) * 3600000.0,
				   ((double)primeStats.chainCounter[0][12] / statsPassedTime) * 3600000.0
			   );
			   printf("══════════════════════════════════════════════════════════════════════════════\n");
			   double shareValuePerHour = primeStats.fShareValue / totalRunTime * 3600000.0;
			   printf("  Val/h: %8f                     Last Block/Total: %0.6f / %0.6f \n", shareValuePerHour, primeStats.fBlockShareValue, primeStats.fTotalSubmittedShareValue);               
               printf("══════════════════════════════════════════════════════════════════════════════\n");

					primeStats.fBlockShareValue = 0;
				}
			}
			Sleep(10);
		}
		loopCounter++;
	}

	return 0;
}

int main(int argc, char **argv)
{
	// setup some default values
	commandlineInput.host = "ypool.net";
	commandlineInput.port = 10034;

	commandlineInput.workername = "x";
	commandlineInput.workerpass = "x";

	commandlineInput.numThreads = std::max(getNumThreads(), 1);
	commandlineInput.numThreads = std::max((int)commandlineInput.numThreads, 1);
	commandlineInput.sieveSize = 1536000; // default maxSieveSize
	commandlineInput.L1CacheElements = 256000;
	commandlineInput.targetOverride = 10;
	commandlineInput.initialPrimorial = 67;
	commandlineInput.sieveExtensions = 10;
	primeStats.adminFunc = false;
	primeStats.tSplit = true;

	std::cout << std::fixed << std::showpoint << std::setprecision(8);
	nPrintSPSMessages = false;

	jhMiner_parseCommandline(argc, argv); //Parse Commandline

	nMaxSieveSize = commandlineInput.sieveSize;
	nSieveExtensions = commandlineInput.sieveExtensions;

	if (commandlineInput.targetOverride==9) {
		primeStats.pMult = 450;
	} else {
		primeStats.pMult = 180;
	}

   nOverrideTargetValue = commandlineInput.targetOverride;
	nOverrideBTTargetValue = commandlineInput.targetOverride;
	
	primeStats.nL1CacheElements = commandlineInput.L1CacheElements;

   printf("\n");
	printf("╔═══════════════════════════════════════════════════════════════╗\n");
	printf("║  pxpminer - mod by Garovich                                   ║\n");
	printf("║     optimised from jhPrimeminer                               ║\n");
	printf("║  author: JH (http://ypool.net)                                ║\n");
	printf("║  contributors: x3maniac, rdebourbon                           ║\n");
	printf("║                                                               ║\n");
	printf("║  Donations:                                                   ║\n");
	printf("║        XPM: AFv6FpGBqzGUW8puYzitUwZKjSHKczmteY                ║\n");
	printf("║        BTC: 1Ca9qP6tkAEo6EpgtXvuANr936c9FbgBrH                ║\n");
	printf("╚═══════════════════════════════════════════════════════════════╝\n");
    printf("Launching miner...\n");
	// set priority lower so the user still can do other things
#ifdef _WIN32
	SetPriorityClass(GetCurrentProcess(), BELOW_NORMAL_PRIORITY_CLASS);
#endif
	// init memory speedup (if not already done in preMain)
	//mallocSpeedupInit();
	if( pctx == NULL )
		pctx = BN_CTX_new();
	// init prime table
	GeneratePrimeTable(10000000);
	// init winsock
#ifdef WIN32
	WSADATA wsa;
	WSAStartup(MAKEWORD(2,2),&wsa);
	// init critical section
	InitializeCriticalSection(&workData.cs);
#else
  pthread_mutex_init(&workData.cs, NULL);
#endif
	// connect to host
#ifdef _WIN32
	hostent* hostInfo = gethostbyname(commandlineInput.host);
	if( hostInfo == NULL )
	{
		printf("Cannot resolve '%s'. Is it a valid URL?\n", commandlineInput.host);
		exit(-1);
	}
	void** ipListPtr = (void**)hostInfo->h_addr_list;
	uint32 ip = 0xFFFFFFFF;
	if( ipListPtr[0] )
	{
		ip = *(uint32*)ipListPtr[0];
	}
	char ipText[32];
	esprintf(ipText, "%d.%d.%d.%d", ((ip>>0)&0xFF), ((ip>>8)&0xFF), ((ip>>16)&0xFF), ((ip>>24)&0xFF));
#else
  struct addrinfo hints, *res;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  getaddrinfo(commandlineInput.host, 0, &hints, &res);
  char ipText[32];
  inet_ntop(AF_INET, &((struct sockaddr_in *)res->ai_addr)->sin_addr, ipText, INET_ADDRSTRLEN);
#endif
  
	// setup RPC connection data (todo: Read from command line)
	jsonRequestTarget.ip = ipText;
	jsonRequestTarget.port = commandlineInput.port;
	jsonRequestTarget.authUser = (char *)commandlineInput.workername;
	jsonRequestTarget.authPass = (char *)commandlineInput.workerpass;


   jsonLocalPrimeCoin.ip = "127.0.0.1";
   jsonLocalPrimeCoin.port = 9912;
   jsonLocalPrimeCoin.authUser = "primecoinrpc";
   jsonLocalPrimeCoin.authPass = "x";

   //lastBlockCount = queryLocalPrimecoindBlockCount(useLocalPrimecoindForLongpoll);

		std::cout << "Connecting to '" << commandlineInput.host << "'" << std::endl;


	// init stats
   primeStats.primeLastUpdate = primeStats.blockStartTime = primeStats.startTime = getTimeMilliseconds();
	primeStats.shareFound = false;
	primeStats.shareRejected = false;
	primeStats.primeChainsFound = 0;
	primeStats.foundShareCount = 0;
   for(uint32 i = 0; i < sizeof(primeStats.chainCounter[0])/sizeof(uint32);  i++)
   {
      primeStats.chainCounter[0][i] = 0;
      primeStats.chainCounter[1][i] = 0;
      primeStats.chainCounter[2][i] = 0;
      primeStats.chainCounter[3][i] = 0;
   }
	for (unsigned int i=0;i<112;i++) {
		primeStats.chainCounter2[i][0] = 0;
		primeStats.chainCounter2[i][1] = 0;
		primeStats.chainCounter2[i][2] = 0;
		primeStats.chainCounter2[i][3] = 0;
		primeStats.chainCounter2[i][4] = 0;
		primeStats.chainCounter2[i][5] = 0;
		primeStats.chainCounter2[i][6] = 0;
		primeStats.chainCounter2[i][7] = 0;
		primeStats.chainCounter2[i][8] = 0;
		primeStats.chainCounter2[i][9] = 0;
		primeStats.chainCounter2[i][10] = 0;
		primeStats.chainCounter2[i][11] = 0;
		primeStats.chainCounter2[i][12] = 0;
	}
	primeStats.fShareValue = 0;
	primeStats.fBlockShareValue = 0;
	primeStats.fTotalSubmittedShareValue = 0;
	primeStats.nWaveTime = 0;
	primeStats.nWaveRound = 0;

	primeStats.nPrimorials.push_back(commandlineInput.initialPrimorial);

	std::set<unsigned int> pSet(primeStats.nPrimorials.begin(),primeStats.nPrimorials.end());
	primeStats.nPrimorials.clear();
	primeStats.nPrimorials.assign(pSet.begin(),pSet.end());
	primeStats.nPrimorialsSize = primeStats.nPrimorials.size();
	for (unsigned int i=0;i<primeStats.nPrimorialsSize;i++) {
		primeStats.chainCounter2[primeStats.nPrimorials[i]][0] = 1;
	}
	// setup thread count and print info

	std::cout << "Using " << commandlineInput.numThreads << " threads" << std::endl;
	std::cout << "Username: " << jsonRequestTarget.authUser << std::endl;
	std::cout << "Password: " << jsonRequestTarget.authPass << std::endl;
	// decide protocol
   if( commandlineInput.port == 10034 || commandlineInput.port == 8081)
   {
	// port 10034/8081 indicates xpt protocol (in future we will also add a -o URL prefix)
	workData.protocolMode = MINER_PROTOCOL_XPUSHTHROUGH;
		std::cout << "Using x.pushthrough protocol" << std::endl;
   }
   else
   {
      workData.protocolMode = MINER_PROTOCOL_GETWORK;
      printf("Using GetWork() protocol\n");
      printf("Warning: \n");
      printf("   GetWork() is outdated and inefficient. You are losing mining performance\n");
      printf("   by using it. If the pool supports it, consider switching to x.pushthrough.\n");
      printf("   Just add the port :10034 or 8081 to the -o parameter.\n");
      printf("   Example: pxpminer -o http://poolurl.net:10034 ...\n");
   }
		// initial query new work / create new connection
   if( workData.protocolMode == MINER_PROTOCOL_GETWORK )
   {
      jhMiner_queryWork_primecoin();
	}
   else if( workData.protocolMode == MINER_PROTOCOL_XPUSHTHROUGH )
   {

	// setup thread count and print info
	nonceStep = commandlineInput.numThreads;
	printf("Using %d threads\n", commandlineInput.numThreads);
	printf("Username: %s\n", jsonRequestTarget.authUser);
	printf("Password: %s\n", jsonRequestTarget.authPass);

		workData.xptClient = NULL;
		// x.pushthrough initial connect & login sequence
		while( true )
		{
			// repeat connect & login until it is successful (with 30 seconds delay)
			while ( true )
			{
				workData.xptClient = xptClient_connect(&jsonRequestTarget, commandlineInput.numThreads);
				if( workData.xptClient != NULL )
					break;
						std::cout << "Failed to connect, retry in 30 seconds" << std::endl;
				Sleep(1000*30);
			}
			// make sure we are successfully authenticated
			while( xptClient_isDisconnected(workData.xptClient, NULL) == false && xptClient_isAuthenticated(workData.xptClient) == false )
			{
				xptClient_process(workData.xptClient);
				Sleep(1);
			}
			char* disconnectReason = NULL;
			// everything went alright?
			if( xptClient_isDisconnected(workData.xptClient, &disconnectReason) == true )
			{
				xptClient_free(workData.xptClient);
				workData.xptClient = NULL;
				break;
			}
			if( xptClient_isAuthenticated(workData.xptClient) == true )
			{
				break;
			}
			if( disconnectReason ){
					std::cout << "xpt error: " << disconnectReason << std::endl;
			}
			// delete client
			xptClient_free(workData.xptClient);
			// try again in 30 seconds
				std::cout << "x.pushthrough authentication sequence failed, retry in 30 seconds" << std::endl;
		Sleep(30*1000);
	}
   }
	
	printf("===============================================================\n");
	printf("Keyboard shortcuts:\n");
	printf("   <Ctrl-C>, <Q>     - Quit\n");
	printf("   <s> - Print current settings\n");
	printf("   <h> - Print Help\n");
	printf("   <m> - Toggle SPS Messages\n");
	printf("   <p> - Print Primorial Stats\n");

   // enter different mainloops depending on protocol mode
   if( workData.protocolMode == MINER_PROTOCOL_GETWORK )
      return jhMiner_main_getworkMode();
   else if( workData.protocolMode == MINER_PROTOCOL_XPUSHTHROUGH )
		return jhMiner_main_xptMode();

	return 0;
}
