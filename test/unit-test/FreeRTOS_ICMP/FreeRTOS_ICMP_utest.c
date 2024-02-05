/*
 * FreeRTOS+TCP <DEVELOPMENT BRANCH>
 * Copyright (C) 2022 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * SPDX-License-Identifier: MIT
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * http://aws.amazon.com/freertos
 * http://www.FreeRTOS.org
 */


/* Include Unity header */
#include "unity.h"

/* Include standard libraries */
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "mock_task.h"
#include "mock_list.h"

/* This must come after list.h is included (in this case, indirectly
 * by mock_list.h). */
#include "mock_ICMP_list_macros.h"
#include "mock_queue.h"
#include "mock_event_groups.h"

#include "mock_FreeRTOS_IP_Private.h"
#include "mock_FreeRTOS_IP_Utils.h"
#include "mock_FreeRTOS_IP_Timers.h"
#include "mock_FreeRTOS_TCP_IP.h"
#include "mock_FreeRTOS_IP.h"
#include "mock_FreeRTOS_ARP.h"
#include "mock_NetworkBufferManagement.h"
#include "mock_NetworkInterface.h"
#include "mock_FreeRTOS_DHCP.h"
#include "mock_FreeRTOS_Sockets.h"
#include "mock_FreeRTOS_DNS.h"
#include "mock_FreeRTOS_Stream_Buffer.h"
#include "mock_FreeRTOS_TCP_WIN.h"
#include "mock_FreeRTOS_UDP_IP.h"

#include "FreeRTOS_ICMP.h"

#include "FreeRTOS_ICMP_stubs.c"
#include "catch_assert.h"

#include "FreeRTOSIPConfig.h"

/* Setting IPv6 address as "fe80::7009" */
static const IPv6_Address_t xDefaultIPAddress =
{
    0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x70, 0x09
};

void test_eProcessICMPPacket_CatchAssert( void )
{
    eFrameProcessingResult_t eResult;
    NetworkBufferDescriptor_t * pxNetworkBuffer, xNetworkBuffer;

    pxNetworkBuffer = &xNetworkBuffer;
    pxNetworkBuffer->xDataLength = sizeof( ICMPPacket_t ) - 1;

    catch_assert( eProcessICMPPacket( pxNetworkBuffer ) );
}

void test_eProcessICMPPacket_AllZeroData( void )
{
    eFrameProcessingResult_t eResult;
    NetworkBufferDescriptor_t * pxNetworkBuffer, xNetworkBuffer;
    uint8_t ucEthBuffer[ ipconfigTCP_MSS ];

    pxNetworkBuffer = &xNetworkBuffer;
    pxNetworkBuffer->pucEthernetBuffer = ucEthBuffer;
    pxNetworkBuffer->xDataLength = ipconfigTCP_MSS;

    memset( ucEthBuffer, 0, ipconfigTCP_MSS );

    vApplicationPingReplyHook_Expect( eInvalidData, 0 );

    eResult = eProcessICMPPacket( pxNetworkBuffer );

    TEST_ASSERT_EQUAL( eReleaseBuffer, eResult );
}

void test_eProcessICMPPacket_EchoRequest( void )
{
    eFrameProcessingResult_t eResult;
    NetworkBufferDescriptor_t * pxNetworkBuffer, xNetworkBuffer;
    uint8_t ucEthBuffer[ ipconfigTCP_MSS ];
    IPHeader_t * pxIPHeader;
    ICMPPacket_t * pxICMPPacket;
    ICMPHeader_t * pxICMPHeader;

    pxNetworkBuffer = &xNetworkBuffer;
    pxNetworkBuffer->pucEthernetBuffer = ucEthBuffer;
    pxNetworkBuffer->xDataLength = ipconfigTCP_MSS;

    memset( ucEthBuffer, 0, ipconfigTCP_MSS );

    pxICMPPacket = ( ICMPPacket_t * ) pxNetworkBuffer->pucEthernetBuffer;
    pxICMPHeader = ( ( ICMPHeader_t * ) &( pxICMPPacket->xICMPHeader ) );
    pxIPHeader = &( pxICMPPacket->xIPHeader );

    pxICMPPacket->xICMPHeader.ucTypeOfMessage = ipICMP_ECHO_REQUEST;

    uxIPHeaderSizePacket_ExpectAnyArgsAndReturn( 0 );

    usGenerateChecksum_ExpectAnyArgsAndReturn( 0xAA );

    usGenerateProtocolChecksum_ExpectAnyArgsAndReturn( 0 );

    eResult = eProcessICMPPacket( pxNetworkBuffer );

    TEST_ASSERT_EQUAL( eReturnEthernetFrame, eResult );
    TEST_ASSERT_EQUAL( ( uint8_t ) ipICMP_ECHO_REPLY, pxICMPHeader->ucTypeOfMessage );
    TEST_ASSERT_EQUAL( pxIPHeader->ulSourceIPAddress, pxIPHeader->ulDestinationIPAddress );
    TEST_ASSERT_EQUAL( *ipLOCAL_IP_ADDRESS_POINTER, pxIPHeader->ulSourceIPAddress );
    TEST_ASSERT_EQUAL( ipconfigICMP_TIME_TO_LIVE, pxIPHeader->ucTimeToLive );
    TEST_ASSERT_EQUAL( 0, pxIPHeader->usFragmentOffset );
    TEST_ASSERT_EQUAL( ( uint16_t ) ~FreeRTOS_htons( 0xAA ), pxIPHeader->usHeaderChecksum );
}

void test_eProcessICMPPacket_UnknownICMPPacket( void )
{
    eFrameProcessingResult_t eResult;
    NetworkBufferDescriptor_t * pxNetworkBuffer, xNetworkBuffer;
    uint8_t ucEthBuffer[ ipconfigTCP_MSS ];
    ICMPPacket_t * pxICMPPacket;

    pxNetworkBuffer = &xNetworkBuffer;
    pxNetworkBuffer->pucEthernetBuffer = ucEthBuffer;
    pxNetworkBuffer->xDataLength = ipconfigTCP_MSS;

    memset( ucEthBuffer, 0, ipconfigTCP_MSS );

    pxICMPPacket = ( ICMPPacket_t * ) pxNetworkBuffer->pucEthernetBuffer;

    /* Unknown ICMP Packet. */
    pxICMPPacket->xICMPHeader.ucTypeOfMessage = ipICMP_ECHO_REQUEST + 2;

    eResult = eProcessICMPPacket( pxNetworkBuffer );

    TEST_ASSERT_EQUAL( eReleaseBuffer, eResult );
}

void test_eProcessICMPPacket_ICMPEchoReply_NULLData( void )
{
    eFrameProcessingResult_t eResult;
    NetworkBufferDescriptor_t * pxNetworkBuffer, xNetworkBuffer;
    uint8_t ucEthBuffer[ ipconfigTCP_MSS ];
    ICMPPacket_t * pxICMPPacket;

    pxNetworkBuffer = &xNetworkBuffer;
    pxNetworkBuffer->pucEthernetBuffer = ucEthBuffer;
    pxNetworkBuffer->xDataLength = ipconfigTCP_MSS;

    memset( ucEthBuffer, 0, ipconfigTCP_MSS );

    pxICMPPacket = ( ICMPPacket_t * ) pxNetworkBuffer->pucEthernetBuffer;

    pxICMPPacket->xIPHeader.usLength = FreeRTOS_htons( ipSIZE_OF_IPv4_HEADER + ipSIZE_OF_ICMPv4_HEADER );

    /* ICMP Reply. */
    pxICMPPacket->xICMPHeader.ucTypeOfMessage = ipICMP_ECHO_REPLY;

    vApplicationPingReplyHook_Expect( eSuccess, 0 );

    eResult = eProcessICMPPacket( pxNetworkBuffer );

    TEST_ASSERT_EQUAL( eReleaseBuffer, eResult );
}

void test_eProcessICMPPacket_ICMPEchoReply_ProperData( void )
{
    eFrameProcessingResult_t eResult;
    NetworkBufferDescriptor_t * pxNetworkBuffer, xNetworkBuffer;
    uint8_t ucEthBuffer[ ipconfigTCP_MSS ];
    ICMPPacket_t * pxICMPPacket;
    uint8_t * pucByte;

    pxNetworkBuffer = &xNetworkBuffer;
    pxNetworkBuffer->pucEthernetBuffer = ucEthBuffer;
    pxNetworkBuffer->xDataLength = ipconfigTCP_MSS;

    memset( ucEthBuffer, 0, ipconfigTCP_MSS );

    pxICMPPacket = ( ICMPPacket_t * ) pxNetworkBuffer->pucEthernetBuffer;

    pxICMPPacket->xIPHeader.usLength = FreeRTOS_htons( ipSIZE_OF_IPv4_HEADER + ipSIZE_OF_ICMPv4_HEADER + 10 );

    /* ICMP Reply. */
    pxICMPPacket->xICMPHeader.ucTypeOfMessage = ipICMP_ECHO_REPLY;

    pucByte = ( uint8_t * ) pxICMPPacket;
    pucByte = &( pucByte[ sizeof( ICMPPacket_t ) ] );
    memset( pucByte, ipECHO_DATA_FILL_BYTE, 10 );

    vApplicationPingReplyHook_Expect( eSuccess, 0 );

    eResult = eProcessICMPPacket( pxNetworkBuffer );

    TEST_ASSERT_EQUAL( eReleaseBuffer, eResult );
}

void test_eProcessICMPPacket_ICMPEchoReply_ImproperData( void )
{
    eFrameProcessingResult_t eResult;
    NetworkBufferDescriptor_t * pxNetworkBuffer, xNetworkBuffer;
    uint8_t ucEthBuffer[ ipconfigTCP_MSS ];
    ICMPPacket_t * pxICMPPacket;
    uint8_t * pucByte;

    pxNetworkBuffer = &xNetworkBuffer;
    pxNetworkBuffer->pucEthernetBuffer = ucEthBuffer;
    pxNetworkBuffer->xDataLength = ipconfigTCP_MSS;

    memset( ucEthBuffer, 0, ipconfigTCP_MSS );

    pxICMPPacket = ( ICMPPacket_t * ) pxNetworkBuffer->pucEthernetBuffer;

    pxICMPPacket->xIPHeader.usLength = FreeRTOS_htons( ipSIZE_OF_IPv4_HEADER + ipSIZE_OF_ICMPv4_HEADER + 10 );

    /* ICMP Reply. */
    pxICMPPacket->xICMPHeader.ucTypeOfMessage = ipICMP_ECHO_REPLY;

    pucByte = ( uint8_t * ) pxICMPPacket;
    pucByte = &( pucByte[ sizeof( ICMPPacket_t ) ] );
    memset( pucByte, ipECHO_DATA_FILL_BYTE, 5 );

    vApplicationPingReplyHook_Expect( eInvalidData, 0 );

    eResult = eProcessICMPPacket( pxNetworkBuffer );

    TEST_ASSERT_EQUAL( eSuccess, eResult );
}

void test_CastingFunctions( void )
{
    void * pvTemp;

    const ICMPHeader_t * pxICMPHeader = ( ( const ICMPHeader_t * ) pvTemp );
}

/**
 * @brief This function process ICMP message when message type is
 *        ipICMP_NEIGHBOR_ADVERTISEMENT_IPv6.
 *        It handles case when pxARPWaitingNetworkBuffer is NULL.
 */
void test_eProcessICMPv6Packet_NeighborAdvertisement1( void )
{
    NetworkBufferDescriptor_t xNetworkBuffer, * pxNetworkBuffer = &xNetworkBuffer;
    ICMPPacket_IPv6_t xICMPPacket;
    ICMPHeader_IPv6_t * pxICMPHeader_IPv6 = ( ( ICMPHeader_IPv6_t * ) &( xICMPPacket.xICMPHeaderIPv6 ) );
    NetworkEndPoint_t xEndPoint;
    eFrameProcessingResult_t eReturn;

    xEndPoint.bits.bIPv6 = pdTRUE_UNSIGNED;
    pxNetworkBuffer->pucEthernetBuffer = ( uint8_t * ) &xICMPPacket;
    pxNetworkBuffer->pxEndPoint = &xEndPoint;
    xICMPPacket.xICMPHeaderIPv6.ucTypeOfMessage = ipICMPv6_NEIGHBOR_ADVERTISEMENT;
    pxARPWaitingNetworkBuffer = NULL;


    eReturn = eProcessICMPv6Packet( pxNetworkBuffer );

    TEST_ASSERT_EQUAL( eReturn, eReleaseBuffer );
}

/**
 * @brief This function process ICMP message when message type is
 *        ipICMPv6_NEIGHBOR_ADVERTISEMENT.
 *        It handles case header is of ipSIZE_OF_IPv4_HEADER type.
 */
void test_eProcessICMPv6Packet_NeighborAdvertisement2( void )
{
    NetworkBufferDescriptor_t xNetworkBuffer, * pxNetworkBuffer = &xNetworkBuffer;
    ICMPPacket_IPv6_t xICMPPacket;
    ICMPHeader_IPv6_t * pxICMPHeader_IPv6 = ( ( ICMPHeader_IPv6_t * ) &( xICMPPacket.xICMPHeaderIPv6 ) );
    NetworkEndPoint_t xEndPoint;
    eFrameProcessingResult_t eReturn;
    NetworkBufferDescriptor_t xARPWaitingNetworkBuffer;

    xEndPoint.bits.bIPv6 = pdTRUE_UNSIGNED;
    pxNetworkBuffer->pucEthernetBuffer = ( uint8_t * ) &xICMPPacket;
    pxNetworkBuffer->pxEndPoint = &xEndPoint;
    xICMPPacket.xICMPHeaderIPv6.ucTypeOfMessage = ipICMPv6_NEIGHBOR_ADVERTISEMENT;

    pxARPWaitingNetworkBuffer = &xARPWaitingNetworkBuffer;
    uxIPHeaderSizePacket_IgnoreAndReturn( ipSIZE_OF_IPv4_HEADER );

    eReturn = eProcessICMPv6Packet( pxNetworkBuffer );

    TEST_ASSERT_EQUAL( eReturn, eReleaseBuffer );
}

/**
 * @brief This function process ICMP message when message type is
 *        ipICMPv6_NEIGHBOR_ADVERTISEMENT.
 *        This verifies a case 'pxARPWaitingNetworkBuffer' was
 *        not waiting for this new address look-up.
 */
void test_eProcessICMPv6Packet_NeighborAdvertisement3( void )
{
    NetworkBufferDescriptor_t xNetworkBuffer, * pxNetworkBuffer = &xNetworkBuffer;
    ICMPPacket_IPv6_t xICMPPacket;
    ICMPHeader_IPv6_t * pxICMPHeader_IPv6 = ( ( ICMPHeader_IPv6_t * ) &( xICMPPacket.xICMPHeaderIPv6 ) );
    NetworkEndPoint_t xEndPoint;
    eFrameProcessingResult_t eReturn;
    NetworkBufferDescriptor_t xARPWaitingNetworkBuffer;
    IPPacket_IPv6_t xIPPacket;
    IPHeader_IPv6_t * pxIPHeader = &( xIPPacket.xIPHeader );

    pxARPWaitingNetworkBuffer = &xARPWaitingNetworkBuffer;
    pxARPWaitingNetworkBuffer->pucEthernetBuffer = ( uint8_t * ) &xIPPacket;
    xEndPoint.bits.bIPv6 = pdTRUE_UNSIGNED;
    pxNetworkBuffer->pucEthernetBuffer = ( uint8_t * ) &xICMPPacket;
    pxNetworkBuffer->pxEndPoint = &xEndPoint;
    ( void ) memcpy( pxICMPHeader_IPv6->xIPv6Address.ucBytes, xDefaultIPAddress.ucBytes, ipSIZE_OF_IPv6_ADDRESS );
    xICMPPacket.xICMPHeaderIPv6.ucTypeOfMessage = ipICMPv6_NEIGHBOR_ADVERTISEMENT;

    uxIPHeaderSizePacket_IgnoreAndReturn( ipSIZE_OF_IPv6_HEADER );

    eReturn = eProcessICMPv6Packet( pxNetworkBuffer );

    TEST_ASSERT_EQUAL( eReturn, eReleaseBuffer );
}

/**
 * @brief This function process ICMP message when message type is
 *        ipICMPv6_NEIGHBOR_ADVERTISEMENT_IPv6.
 *        This verifies a case where a packet is handled as a new
 *        incoming IP packet when a neighbour advertisement has been received,
 *        and 'pxARPWaitingNetworkBuffer' was waiting for this new address look-up.
 */
void test_eProcessICMPv6Packet_NeighborAdvertisement4( void )
{
    NetworkBufferDescriptor_t xNetworkBuffer, * pxNetworkBuffer = &xNetworkBuffer;
    ICMPPacket_IPv6_t xICMPPacket;
    ICMPHeader_IPv6_t * pxICMPHeader_IPv6 = ( ( ICMPHeader_IPv6_t * ) &( xICMPPacket.xICMPHeaderIPv6 ) );
    NetworkEndPoint_t xEndPoint;
    eFrameProcessingResult_t eReturn;
    NetworkBufferDescriptor_t xARPWaitingNetworkBuffer;
    IPPacket_IPv6_t xIPPacket;
    IPHeader_IPv6_t * pxIPHeader = &( xIPPacket.xIPHeader );

    pxARPWaitingNetworkBuffer = &xARPWaitingNetworkBuffer;
    pxARPWaitingNetworkBuffer->pucEthernetBuffer = ( uint8_t * ) &xIPPacket;

    xEndPoint.bits.bIPv6 = pdTRUE_UNSIGNED;
    pxNetworkBuffer->pucEthernetBuffer = ( uint8_t * ) &xICMPPacket;
    pxNetworkBuffer->pxEndPoint = &xEndPoint;
    xICMPPacket.xICMPHeaderIPv6.ucTypeOfMessage = ipICMPv6_NEIGHBOR_ADVERTISEMENT;
    ( void ) memcpy( pxICMPHeader_IPv6->xIPv6Address.ucBytes, xDefaultIPAddress.ucBytes, ipSIZE_OF_IPv6_ADDRESS );
    ( void ) memcpy( pxIPHeader->xSourceAddress.ucBytes, xDefaultIPAddress.ucBytes, ipSIZE_OF_IPv6_ADDRESS );


    uxIPHeaderSizePacket_IgnoreAndReturn( ipSIZE_OF_IPv6_HEADER );
    xSendEventStructToIPTask_IgnoreAndReturn( pdFAIL );
    vReleaseNetworkBufferAndDescriptor_Ignore();
    vIPSetARPResolutionTimerEnableState_ExpectAnyArgs();

    eReturn = eProcessICMPv6Packet( pxNetworkBuffer );

    TEST_ASSERT_EQUAL( eReturn, eReleaseBuffer );
    TEST_ASSERT_EQUAL( pxARPWaitingNetworkBuffer, NULL );
}

/**
 * @brief This function process ICMP message when message type is
 *        ipICMPv6_NEIGHBOR_ADVERTISEMENT.
 *        This verifies a case where a packet is handled as a new
 *        incoming IP packet when a neighbour advertisement has been received,
 *        and 'pxARPWaitingNetworkBuffer' was waiting for this new address look-up.
 */
void test_eProcessICMPv6Packet_NeighborAdvertisement5( void )
{
    NetworkBufferDescriptor_t xNetworkBuffer, * pxNetworkBuffer = &xNetworkBuffer;
    ICMPPacket_IPv6_t xICMPPacket;
    ICMPHeader_IPv6_t * pxICMPHeader_IPv6 = ( ( ICMPHeader_IPv6_t * ) &( xICMPPacket.xICMPHeaderIPv6 ) );
    NetworkEndPoint_t xEndPoint;
    eFrameProcessingResult_t eReturn;
    NetworkBufferDescriptor_t xARPWaitingNetworkBuffer;
    IPPacket_IPv6_t xIPPacket;
    IPHeader_IPv6_t * pxIPHeader = &( xIPPacket.xIPHeader );

    pxARPWaitingNetworkBuffer = &xARPWaitingNetworkBuffer;
    pxARPWaitingNetworkBuffer->pucEthernetBuffer = ( uint8_t * ) &xIPPacket;

    xEndPoint.bits.bIPv6 = pdTRUE_UNSIGNED;
    pxNetworkBuffer->pucEthernetBuffer = ( uint8_t * ) &xICMPPacket;
    pxNetworkBuffer->pxEndPoint = &xEndPoint;
    xICMPPacket.xICMPHeaderIPv6.ucTypeOfMessage = ipICMPv6_NEIGHBOR_ADVERTISEMENT;
    ( void ) memcpy( pxICMPHeader_IPv6->xIPv6Address.ucBytes, xDefaultIPAddress.ucBytes, ipSIZE_OF_IPv6_ADDRESS );
    ( void ) memcpy( pxIPHeader->xSourceAddress.ucBytes, xDefaultIPAddress.ucBytes, ipSIZE_OF_IPv6_ADDRESS );


    uxIPHeaderSizePacket_IgnoreAndReturn( ipSIZE_OF_IPv6_HEADER );
    xSendEventStructToIPTask_IgnoreAndReturn( pdPASS );
    vIPSetARPResolutionTimerEnableState_ExpectAnyArgs();

    eReturn = eProcessICMPv6Packet( pxNetworkBuffer );

    TEST_ASSERT_EQUAL( eReturn, eReleaseBuffer );
    TEST_ASSERT_EQUAL( pxARPWaitingNetworkBuffer, NULL );
}

/**
 * @brief This function process ICMP message when message type is incorrect.
 */
void test_eProcessICMPv6Packet_Default( void )
{
    NetworkBufferDescriptor_t xNetworkBuffer, * pxNetworkBuffer = &xNetworkBuffer;
    ICMPPacket_IPv6_t xICMPPacket;
    NetworkEndPoint_t xEndPoint;
    eFrameProcessingResult_t eReturn;

    xEndPoint.bits.bIPv6 = pdTRUE_UNSIGNED;
    xICMPPacket.xICMPHeaderIPv6.ucTypeOfMessage = 0;
    pxNetworkBuffer->pxEndPoint = &xEndPoint;
    pxNetworkBuffer->pucEthernetBuffer = ( uint8_t * ) &xICMPPacket;

    eReturn = eProcessICMPv6Packet( pxNetworkBuffer );

    TEST_ASSERT_EQUAL( eReturn, eReleaseBuffer );
}
