#include"global.h"
#include"ticker.h"
#ifndef _WIN32
#include <errno.h>
#endif
#include <iostream>
#ifdef _WIN32
SOCKET xptClient_openConnection(char *IP, int Port)
{
	SOCKET s=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
	SOCKADDR_IN addr;
	memset(&addr,0,sizeof(SOCKADDR_IN));
	addr.sin_family=AF_INET;
	addr.sin_port=htons(Port);
	addr.sin_addr.s_addr=inet_addr(IP);
	int result = connect(s,(SOCKADDR*)&addr,sizeof(SOCKADDR_IN));
  if( result )
	{
		return 0;
	}
#else
int xptClient_openConnection(char *IP, int Port)
{
  int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(sockaddr_in));
  addr.sin_family = AF_INET;
  addr.sin_port=htons(Port);
  addr.sin_addr.s_addr = inet_addr(IP);
  int result = connect(s, (sockaddr*)&addr, sizeof(sockaddr_in));
#endif
  if( result < 0)
{
		return 0;
	}
	return s;
}

/*
 * Opens a new x.pushthrough connection
 * target is the server address + worker login data to use for connecting
 */
xptClient_t* xptClient_connect(jsonRequestTarget_t* target, uint32 payloadNum)
{
	// first try to connect to the given host/port
#ifdef _WIN32
	SOCKET clientSocket = xptClient_openConnection(target->ip, target->port);
#else
  int clientSocket = xptClient_openConnection(target->ip, target->port);
#endif
	if( clientSocket == 0 )
		return NULL;
#ifdef _WIN32
	// set socket as non-blocking
	unsigned int nonblocking=1;
	unsigned int cbRet;
	WSAIoctl(clientSocket, FIONBIO, &nonblocking, sizeof(nonblocking), NULL, 0, (LPDWORD)&cbRet, NULL, NULL);
#else
  int flags, err;
  flags = fcntl(clientSocket, F_GETFL, 0); 
  flags |= O_NONBLOCK;
  err = fcntl(clientSocket, F_SETFL, flags); //ignore errors for now..
#endif
	// initialize the client object
	xptClient_t* xptClient = (xptClient_t*)malloc(sizeof(xptClient_t));
	memset(xptClient, 0x00, sizeof(xptClient_t));
	xptClient->clientSocket = clientSocket;
	xptClient->sendBuffer = xptPacketbuffer_create(256*1024);
	xptClient->recvBuffer = xptPacketbuffer_create(256*1024);
	fStrCpy(xptClient->username, target->authUser, 127);
	fStrCpy(xptClient->password, target->authPass, 127);
	xptClient->payloadNum = std::max<uint32>(1, std::min<uint32>(127, payloadNum));
#ifdef _WIN32
	InitializeCriticalSection(&xptClient->cs_shareSubmit);
#else
  pthread_mutex_init(&xptClient->cs_shareSubmit, NULL);
#endif
	xptClient->list_shareSubmitQueue = simpleList_create(4);
	// send worker login
	xptClient_sendWorkerLogin(xptClient);
	// return client object
	return xptClient;
}

/*
 * Disconnects and frees the xptClient instance
 */
void xptClient_free(xptClient_t* xptClient)
{
	xptPacketbuffer_free(xptClient->sendBuffer);
	xptPacketbuffer_free(xptClient->recvBuffer);
	if( xptClient->clientSocket != 0 )
	{
#ifdef _WIN32
		closesocket(xptClient->clientSocket);
#else
    close(xptClient->clientSocket);
#endif
	}
	simpleList_free(xptClient->list_shareSubmitQueue);
	free(xptClient);
}

#define XPT_CLIENT_SERVER_PING_INTERVAL 10000UL

void xptClient_client2ServerSent(xptClient_t* xptClient)
{
	xptClient->lastClient2ServerInteractionTimestamp = getTimeMilliseconds();
}

/*
 * Sends the worker login packet
 */
void xptClient_sendClientServerPing(xptClient_t* xptClient, uint64 timestamp)
{
	uint32 tsLow = (uint32) timestamp;
	uint32 tsHigh = (uint32) (timestamp >> 32);
	// build the packet
	bool sendError = false;
	xptPacketbuffer_beginWritePacket(xptClient->sendBuffer, XPT_OPC_C_PING);
	xptPacketbuffer_writeU32(xptClient->sendBuffer, &sendError, 5);								// version
	xptPacketbuffer_writeU32(xptClient->sendBuffer, &sendError, tsLow);							// lower 32 bits of timestamp
	xptPacketbuffer_writeU32(xptClient->sendBuffer, &sendError, tsHigh);						// upper 32 bits of timestamp
	// finalize
	xptPacketbuffer_finalizeWritePacket(xptClient->sendBuffer);
	// send to client
	send(xptClient->clientSocket, (const char*)(xptClient->sendBuffer->buffer), xptClient->sendBuffer->parserIndex, 0);
	xptClient_client2ServerSent(xptClient);
}

void xptClient_processClientServerPing(xptClient_t* xptClient)
{
	uint64 now = getTimeMilliseconds();
	if ((xptClient->lastClient2ServerInteractionTimestamp + XPT_CLIENT_SERVER_PING_INTERVAL) < now)
	{
		xptClient_sendClientServerPing(xptClient, now);
	}
}

/*
 * Sends the worker login packet
 */
void xptClient_sendWorkerLogin(xptClient_t* xptClient)
{
	
//	uint32 usernameLength = std::min(127, fStrLen(xptClient->username)); //unused
//	uint32 passwordLength = std::min(127, fStrLen(xptClient->password)); //unused
	// build the packet
	bool sendError = false;
	xptPacketbuffer_beginWritePacket(xptClient->sendBuffer, XPT_OPC_C_AUTH_REQ);
	xptPacketbuffer_writeU32(xptClient->sendBuffer, &sendError, 5);								// version
	xptPacketbuffer_writeString(xptClient->sendBuffer, xptClient->username, 128, &sendError);	// username
	xptPacketbuffer_writeString(xptClient->sendBuffer, xptClient->password, 128, &sendError);	// password
	xptPacketbuffer_writeU32(xptClient->sendBuffer, &sendError, xptClient->payloadNum);			// payloadNum
	// write worker version to server
	xptPacketbuffer_writeString(xptClient->sendBuffer, minerVersionString, 45, &sendError);	// minerVersionString
	// finalize
	xptPacketbuffer_finalizeWritePacket(xptClient->sendBuffer);
	// send to client
	send(xptClient->clientSocket, (const char*)(xptClient->sendBuffer->buffer), xptClient->sendBuffer->parserIndex, 0);
	xptClient_client2ServerSent(xptClient);
}

/*
 * Sends the share packet
 */
void xptClient_sendShare(xptClient_t* xptClient, xptShareToSubmit_t* xptShareToSubmit)
{
	//printf("Send share\n");
	// build the packet
	bool sendError = false;
	xptPacketbuffer_beginWritePacket(xptClient->sendBuffer, XPT_OPC_C_SUBMIT_SHARE);
	xptPacketbuffer_writeData(xptClient->sendBuffer, xptShareToSubmit->merkleRoot, 32, &sendError);		// merkleRoot
	xptPacketbuffer_writeData(xptClient->sendBuffer, xptShareToSubmit->prevBlockHash, 32, &sendError);	// prevBlock
	xptPacketbuffer_writeU32(xptClient->sendBuffer, &sendError, xptShareToSubmit->version);				// version
	xptPacketbuffer_writeU32(xptClient->sendBuffer, &sendError, xptShareToSubmit->nTime);				// nTime
	xptPacketbuffer_writeU32(xptClient->sendBuffer, &sendError, xptShareToSubmit->nonce);				// nNonce
	xptPacketbuffer_writeU32(xptClient->sendBuffer, &sendError, xptShareToSubmit->nBits);				// nBits
	xptPacketbuffer_writeU32(xptClient->sendBuffer, &sendError, xptShareToSubmit->sieveSize);			// sieveSize
	xptPacketbuffer_writeU32(xptClient->sendBuffer, &sendError, xptShareToSubmit->sieveCandidate);		// sieveCandidate
	// bnFixedMultiplier
	xptPacketbuffer_writeU8(xptClient->sendBuffer, &sendError, xptShareToSubmit->fixedMultiplierSize);
	xptPacketbuffer_writeData(xptClient->sendBuffer, xptShareToSubmit->fixedMultiplier, xptShareToSubmit->fixedMultiplierSize, &sendError);
	// bnChainMultiplier
	xptPacketbuffer_writeU8(xptClient->sendBuffer, &sendError, xptShareToSubmit->chainMultiplierSize);
	xptPacketbuffer_writeData(xptClient->sendBuffer, xptShareToSubmit->chainMultiplier, xptShareToSubmit->chainMultiplierSize, &sendError);
	// share id (server sends this back in shareAck, so we can identify share response)
        xptPacketbuffer_writeU32(xptClient->sendBuffer, &sendError, 0);
	// finalize
	xptPacketbuffer_finalizeWritePacket(xptClient->sendBuffer);
	// send to client
	send(xptClient->clientSocket, (const char*)(xptClient->sendBuffer->buffer), xptClient->sendBuffer->parserIndex, 0);
	xptClient_client2ServerSent(xptClient);
}

/*
 * Processes a fully received packet
 */
bool xptClient_processPacket(xptClient_t* xptClient)
{
	// printf("Received packet with opcode %d and size %d\n", xptClient->opcode, xptClient->recvSize+4);
	if( xptClient->opcode == XPT_OPC_S_AUTH_ACK )
		return xptClient_processPacket_authResponse(xptClient);
	else if( xptClient->opcode == XPT_OPC_S_WORKDATA1 )
		return xptClient_processPacket_blockData1(xptClient);
	else if( xptClient->opcode == XPT_OPC_S_SHARE_ACK )
		return xptClient_processPacket_shareAck(xptClient);
	else if( xptClient->opcode == XPT_OPC_S_PING )
		return xptClient_processPacket_client2ServerPing(xptClient);
	else if( xptClient->opcode == XPT_OPC_S_MESSAGE )
		return xptClient_processPacket_message(xptClient);


	// unknown opcodes are accepted too, for later backward compatibility
	return true;
}

/*
 * Checks for new received packets and connection events (e.g. closed connection)
 */
bool xptClient_process(xptClient_t* xptClient)
{
	
	if( xptClient == NULL )
		return false;
	// are there shares to submit?
#ifdef _WIN32
	EnterCriticalSection(&xptClient->cs_shareSubmit);
#else
    pthread_mutex_lock(&xptClient->cs_shareSubmit);
#endif
	if( xptClient->list_shareSubmitQueue->objectCount > 0 )
	{
		for(uint32 i=0; i<xptClient->list_shareSubmitQueue->objectCount; i++)
		{
			xptShareToSubmit_t* xptShareToSubmit = (xptShareToSubmit_t*)xptClient->list_shareSubmitQueue->objects[i];
			xptClient_sendShare(xptClient, xptShareToSubmit);
			free(xptShareToSubmit);
		}
		// clear list
		xptClient->list_shareSubmitQueue->objectCount = 0;
	}
#ifdef _WIN32
	LeaveCriticalSection(&xptClient->cs_shareSubmit);
#else
  pthread_mutex_unlock(&xptClient->cs_shareSubmit);
#endif
	// check for packets
	uint32 packetFullSize = 4; // the packet always has at least the size of the header
	if( xptClient->recvSize > 0 )
		packetFullSize += xptClient->recvSize;
	sint32 bytesToReceive = (sint32)(packetFullSize - xptClient->recvIndex);
	// packet buffer is always large enough at this point
	sint32 r = recv(xptClient->clientSocket, (char*)(xptClient->recvBuffer->buffer+xptClient->recvIndex), bytesToReceive, 0);
	if( r <= 0 )
	{
#ifdef _WIN32
		// receive error, is it a real error or just because of non blocking sockets?
		if( WSAGetLastError() != WSAEWOULDBLOCK )
		{
			xptClient->disconnected = true;
			return false;
		}
#else
    if(errno != EAGAIN)
    {
    xptClient->disconnected = true;
    return false;
    }
#endif

		// Check if we shall send ping, because of no other activity happened
		xptClient_processClientServerPing(xptClient);

		return true;
	}
	xptClient->recvIndex += r;
	// header just received?
	if( xptClient->recvIndex == packetFullSize && packetFullSize == 4 )
	{
		// process header
		uint32 headerVal = *(uint32*)xptClient->recvBuffer->buffer;
		uint32 opcode = (headerVal&0xFF);
		uint32 packetDataSize = (headerVal>>8)&0xFFFFFF;
		// validate header size
		if( packetDataSize >= (1024*1024*2-4) )
		{
			// packets larger than 2mb are not allowed
				std::cout << "xptServer_receiveData(): Packet exceeds 2mb size limit" << std::endl;
			return false;
		}
		xptClient->recvSize = packetDataSize;
		xptClient->opcode = opcode;
		// enlarge packetBuffer if too small
		if( (xptClient->recvSize+4) > xptClient->recvBuffer->bufferLimit )
		{
			xptPacketbuffer_changeSizeLimit(xptClient->recvBuffer, (xptClient->recvSize+4));
		}
	}
	// have we received the full packet?
	if( xptClient->recvIndex >= (xptClient->recvSize+4) )
	{
		// process packet
		xptClient->recvBuffer->bufferSize = (xptClient->recvSize+4);
		if( xptClient_processPacket(xptClient) == false )
		{
			xptClient->recvIndex = 0;
			xptClient->recvSize = 0;
			xptClient->opcode = 0;
			// disconnect
			if( xptClient->clientSocket != 0 )
			{
#ifdef _WIN32
				closesocket(xptClient->clientSocket);
#else
	        close(xptClient->clientSocket);
#endif
				xptClient->clientSocket = 0;
			}
			xptClient->disconnected = true;
			return false;
		}
		xptClient->recvIndex = 0;
		xptClient->recvSize = 0;
		xptClient->opcode = 0;
	}
	// return
	return true;
}

/*
 * Returns true if the xptClient connection was disconnected from the server or should disconnect because login was invalid or awkward data received
 */
bool xptClient_isDisconnected(xptClient_t* xptClient, char** reason)
{
	if( reason )
		*reason = xptClient->disconnectReason;
	return xptClient->disconnected;
}

/*
 * Returns true if the worker login was successful
 */
bool xptClient_isAuthenticated(xptClient_t* xptClient)
{
	return (xptClient->clientState == XPT_CLIENT_STATE_LOGGED_IN);
}

void xptClient_foundShare(xptClient_t* xptClient, xptShareToSubmit_t* xptShareToSubmit)
{
#ifdef _WIN32
	EnterCriticalSection(&xptClient->cs_shareSubmit);
	simpleList_add(xptClient->list_shareSubmitQueue, xptShareToSubmit);
	LeaveCriticalSection(&xptClient->cs_shareSubmit);
#else
  pthread_mutex_lock(&xptClient->cs_shareSubmit);
  simpleList_add(xptClient->list_shareSubmitQueue, xptShareToSubmit);
  pthread_mutex_unlock(&xptClient->cs_shareSubmit);
#endif
}