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

/**
 * @file FreeRTOS_ICMP.c
 * @brief Implements the Internet Control Message Protocol for the FreeRTOS+TCP network stack.
 */

/* Standard includes. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* FreeRTOS includes. */
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "semphr.h"

/* FreeRTOS+TCP includes. */
#include "FreeRTOS_IP.h"
#include "FreeRTOS_IP_Private.h"
#include "FreeRTOS_ICMP.h"
#include "FreeRTOS_Sockets.h"
#include "FreeRTOS_ARP.h"
#include "FreeRTOS_ND.h"
#include "FreeRTOS_UDP_IP.h"
#include "FreeRTOS_DHCP.h"
#include "NetworkInterface.h"
#include "NetworkBufferManagement.h"
#include "FreeRTOS_DNS.h"

#if ipconfigIS_ENABLED( ipconfigUSE_IPV4 )

/** @brief Turns around an incoming ping request to convert it into a ping reply.
 */
    #if ipconfigIS_ENABLED( ipconfigREPLY_TO_INCOMING_PINGS )
        static eFrameProcessingResult_t prvProcessICMPEchoRequest( ICMPPacket_t * const pxICMPPacket,
                                                                   const NetworkBufferDescriptor_t * const pxNetworkBuffer );
    #endif

/** @brief Processes incoming ping replies.  The application callback function
 *  vApplicationPingReplyHook() is called with the results.
 */
    #if ipconfigIS_ENABLED( ipconfigSUPPORT_OUTGOING_PINGS )
        static void prvProcessICMPEchoReply( ICMPPacket_t * const pxICMPPacket );
    #endif

#endif

#if ipconfigIS_ENABLED( ipconfigUSE_IPV6 )

    static void prvReturnICMPv6( NetworkBufferDescriptor_t * const pxNetworkBuffer,
                                 size_t uxICMPSize );

    #if ipconfigIS_ENABLED( ipconfigHAS_DEBUG_PRINTF )
        static const char * prvMessageType( BaseType_t xType );
    #endif

#endif

#if ipconfigIS_ENABLED( ipconfigUSE_IPV4 )

/**
 * @brief Process an ICMP packet. Only echo requests and echo replies are recognised and handled.
 *
 * @param[in,out] pxNetworkBuffer The pointer to the network buffer descriptor
 *  that contains the ICMP message.
 *
 * @return eReleaseBuffer when the message buffer should be released, or eReturnEthernetFrame
 *                        when the packet should be returned.
 */
    eFrameProcessingResult_t eProcessICMPPacket( const NetworkBufferDescriptor_t * const pxNetworkBuffer )
    {
        eFrameProcessingResult_t eReturn = eReleaseBuffer;

        iptraceICMP_PACKET_RECEIVED();

        configASSERT( pxNetworkBuffer->xDataLength >= sizeof( ICMPPacket_t ) );

        if( pxNetworkBuffer->xDataLength >= sizeof( ICMPPacket_t ) )
        {
            /* Map the buffer onto a ICMP-Packet struct to easily access the
             * fields of ICMP packet. */

            /* MISRA Ref 11.3.1 [Misaligned access] */
            /* More details at: https://github.com/FreeRTOS/FreeRTOS-Plus-TCP/blob/main/MISRA.md#rule-113 */
            /* coverity[misra_c_2012_rule_11_3_violation] */
            ICMPPacket_t * const pxICMPPacket = ( ( ICMPPacket_t * ) pxNetworkBuffer->pucEthernetBuffer );

            switch( pxICMPPacket->xICMPHeader.ucTypeOfMessage )
            {
                case ipICMP_ECHO_REQUEST:
                    #if ipconfigIS_ENABLED( ipconfigREPLY_TO_INCOMING_PINGS )
                        eReturn = prvProcessICMPEchoRequest( pxICMPPacket, pxNetworkBuffer );
                    #endif
                    break;

                case ipICMP_ECHO_REPLY:
                    #if ipconfigIS_ENABLED( ipconfigSUPPORT_OUTGOING_PINGS )
                        prvProcessICMPEchoReply( pxICMPPacket );
                    #endif
                    break;

                default:
                    /* Only ICMP echo packets are handled. */
                    break;
            }
        }

        return eReturn;
    }

/*-----------------------------------------------------------*/

    #if ipconfigIS_ENABLED( ipconfigREPLY_TO_INCOMING_PINGS )

/**
 * @brief Process an ICMP echo request.
 *
 * @param[in,out] pxICMPPacket The IP packet that contains the ICMP message.
 * @param pxNetworkBuffer Pointer to the network buffer containing the ICMP packet.
 * @returns Function returns eReturnEthernetFrame.
 */
        static eFrameProcessingResult_t prvProcessICMPEchoRequest( ICMPPacket_t * const pxICMPPacket,
                                                                   const NetworkBufferDescriptor_t * const pxNetworkBuffer )
        {
            ICMPHeader_t * pxICMPHeader;
            IPHeader_t * pxIPHeader;
            uint32_t ulIPAddress;

            pxICMPHeader = &( pxICMPPacket->xICMPHeader );
            pxIPHeader = &( pxICMPPacket->xIPHeader );

            /* HT:endian: changed back */
            iptraceSENDING_PING_REPLY( pxIPHeader->ulSourceIPAddress );

            /* The checksum can be checked here - but a ping reply should be
             * returned even if the checksum is incorrect so the other end can
             * tell that the ping was received - even if the ping reply contains
             * invalid data. */
            pxICMPHeader->ucTypeOfMessage = ( uint8_t ) ipICMP_ECHO_REPLY;
            ulIPAddress = pxIPHeader->ulDestinationIPAddress;
            pxIPHeader->ulDestinationIPAddress = pxIPHeader->ulSourceIPAddress;
            pxIPHeader->ulSourceIPAddress = ulIPAddress;
            /* Update the TTL field. */
            pxIPHeader->ucTimeToLive = ipconfigICMP_TIME_TO_LIVE;

            /* The stack doesn't support fragments, so the fragment offset field must always be zero.
             * The header was never memset to zero, so set both the fragment offset and fragmentation flags in one go.
             */
            #if ( ipconfigFORCE_IP_DONT_FRAGMENT != 0 )
                pxIPHeader->usFragmentOffset = ipFRAGMENT_FLAGS_DONT_FRAGMENT;
            #else
                pxIPHeader->usFragmentOffset = 0U;
            #endif

            #if ( ipconfigDRIVER_INCLUDED_TX_IP_CHECKSUM == 0 )
            {
                /* calculate the IP header checksum, in case the driver won't do that. */
                pxIPHeader->usHeaderChecksum = 0x00U;
                pxIPHeader->usHeaderChecksum = usGenerateChecksum( 0U, ( uint8_t * ) &( pxIPHeader->ucVersionHeaderLength ), uxIPHeaderSizePacket( pxNetworkBuffer ) );
                pxIPHeader->usHeaderChecksum = ( uint16_t ) ~FreeRTOS_htons( pxIPHeader->usHeaderChecksum );

                /* calculate the ICMP checksum for an outgoing packet. */
                ( void ) usGenerateProtocolChecksum( ( uint8_t * ) pxICMPPacket, pxNetworkBuffer->xDataLength, pdTRUE );
            }
            #else
            {
                /* Just to prevent compiler warnings about unused parameters. */
                ( void ) pxNetworkBuffer;

                /* Many EMAC peripherals will only calculate the ICMP checksum
                 * correctly if the field is nulled beforehand. */
                pxICMPHeader->usChecksum = 0U;
            }
            #endif /* if ( ipconfigDRIVER_INCLUDED_TX_IP_CHECKSUM == 0 ) */

            return eReturnEthernetFrame;
        }

    #endif /* ipconfigIS_ENABLED( ipconfigREPLY_TO_INCOMING_PINGS ) */
/*-----------------------------------------------------------*/

    #if ipconfigIS_ENABLED( ipconfigSUPPORT_OUTGOING_PINGS )

/**
 * @brief Process an ICMP echo reply.
 *
 * @param[in] pxICMPPacket The IP packet that contains the ICMP message.
 */
        static void prvProcessICMPEchoReply( ICMPPacket_t * const pxICMPPacket )
        {
            ePingReplyStatus_t eStatus = eSuccess;
            uint16_t usDataLength, usCount;
            uint8_t * pucByte;

            /* Find the total length of the IP packet. */
            usDataLength = pxICMPPacket->xIPHeader.usLength;
            usDataLength = FreeRTOS_ntohs( usDataLength );

            /* Remove the length of the IP headers to obtain the length of the ICMP
             * message itself. */
            usDataLength = ( uint16_t ) ( ( ( uint32_t ) usDataLength ) - ipSIZE_OF_IPv4_HEADER );

            /* Remove the length of the ICMP header, to obtain the length of
             * data contained in the ping. */
            usDataLength = ( uint16_t ) ( ( ( uint32_t ) usDataLength ) - ipSIZE_OF_ICMPv4_HEADER );

            /* Checksum has already been checked before in prvProcessIPPacket */

            /* Find the first byte of the data within the ICMP packet. */
            pucByte = ( uint8_t * ) pxICMPPacket;
            pucByte = &( pucByte[ sizeof( ICMPPacket_t ) ] );

            /* Check each byte. */
            for( usCount = 0; usCount < usDataLength; usCount++ )
            {
                if( *pucByte != ( uint8_t ) ipECHO_DATA_FILL_BYTE )
                {
                    eStatus = eInvalidData;
                    break;
                }

                pucByte++;
            }

            /* Call back into the application to pass it the result. */
            vApplicationPingReplyHook( eStatus, pxICMPPacket->xICMPHeader.usIdentifier );
        }

    #endif /* if ipconfigIS_ENABLED( ipconfigSUPPORT_OUTGOING_PINGS ) */
/*-----------------------------------------------------------*/

#endif /* if ipconfigIS_ENABLED( ipconfigUSE_IPV4 ) */
/*-----------------------------------------------------------*/

#if ipconfigIS_ENABLED( ipconfigUSE_IPV6 )

/**
 * @brief Process an ICMPv6 packet and send replies when applicable.
 *
 * @param[in] pxNetworkBuffer The Ethernet packet which contains an IPv6 message.
 *
 * @return A const value 'eReleaseBuffer' which means that the network must still be released.
 */
    eFrameProcessingResult_t eProcessICMPv6Packet( NetworkBufferDescriptor_t * const pxNetworkBuffer )
    {
        /* MISRA Ref 11.3.1 [Misaligned access] */
        /* More details at: https://github.com/FreeRTOS/FreeRTOS-Plus-TCP/blob/main/MISRA.md#rule-113 */
        /* coverity[misra_c_2012_rule_11_3_violation] */
        ICMPPacket_IPv6_t * pxICMPPacket = ( ( ICMPPacket_IPv6_t * ) pxNetworkBuffer->pucEthernetBuffer );
        /* coverity[misra_c_2012_rule_11_3_violation] */
        ICMPHeader_IPv6_t * pxICMPHeader_IPv6 = ( ( ICMPHeader_IPv6_t * ) &( pxICMPPacket->xICMPHeaderIPv6 ) );
        NetworkEndPoint_t * pxEndPoint = pxNetworkBuffer->pxEndPoint;
        size_t uxNeededSize;

        #if ipconfigIS_ENABLED( ipconfigHAS_DEBUG_PRINTF )
            if( pxICMPHeader_IPv6->ucTypeOfMessage != ipICMPv6_PING_REQUEST )
            {
                char pcAddress[ 40 ];
                FreeRTOS_debug_printf( ( "ICMPv6_recv %d (%s) from %pip to %pip end-point = %s\n",
                                   pxICMPHeader_IPv6->ucTypeOfMessage,
                                   pcMessageType( ( BaseType_t ) pxICMPHeader_IPv6->ucTypeOfMessage ),
                                   ( void * ) pxICMPPacket->xIPHeader.xSourceAddress.ucBytes,
                                   ( void * ) pxICMPPacket->xIPHeader.xDestinationAddress.ucBytes,
                                   pcEndpointName( pxEndPoint, pcAddress, sizeof( pcAddress ) ) ) );
            }
        #endif

        if( ( pxEndPoint != NULL ) && ( pxEndPoint->bits.bIPv6 != pdFALSE_UNSIGNED ) )
        {
            switch( pxICMPHeader_IPv6->ucTypeOfMessage )
            {
                case ipICMPv6_PING_REQUEST:
                {
                    size_t uxICMPSize;
                    uint16_t usICMPSize;

                    /* Lint would complain about casting '()' immediately. */
                    usICMPSize = FreeRTOS_ntohs( pxICMPPacket->xIPHeader.usPayloadLength );
                    uxICMPSize = ( size_t ) usICMPSize;
                    uxNeededSize = ( size_t ) ( ipSIZE_OF_ETH_HEADER + ipSIZE_OF_IPv6_HEADER + uxICMPSize );

                    if( uxNeededSize > pxNetworkBuffer->xDataLength )
                    {
                        FreeRTOS_debug_printf( ( "Too small\n" ) );
                        break;
                    }

                    pxICMPHeader_IPv6->ucTypeOfMessage = ipICMPv6_PING_REPLY;

                    /* MISRA Ref 4.14.1 [The validity of values received from external sources]. */
                    /* More details at: https://github.com/FreeRTOS/FreeRTOS-Plus-TCP/blob/main/MISRA.md#directive-414. */
                    /* coverity[misra_c_2012_directive_4_14_violation] */
                    prvReturnICMPv6( pxNetworkBuffer, uxICMPSize );
                    break;
                }

                #if ipconfigIS_ENABLED( ipconfigSUPPORT_OUTGOING_PINGS )
                    case ipICMPv6_PING_REPLY:
                    {
                        ePingReplyStatus_t eStatus = eSuccess;
                        /* MISRA Ref 11.3.1 [Misaligned access] */
                        /* More details at: https://github.com/FreeRTOS/FreeRTOS-Plus-TCP/blob/main/MISRA.md#rule-113 */
                        /* coverity[misra_c_2012_rule_11_3_violation] */
                        const ICMPEcho_IPv6_t * pxICMPEchoHeader = ( ( const ICMPEcho_IPv6_t * ) pxICMPHeader_IPv6 );
                        size_t uxDataLength, uxCount;
                        const uint8_t * pucByte;

                        /* Find the total length of the IP packet. */
                        uxDataLength = ipNUMERIC_CAST( size_t, FreeRTOS_ntohs( pxICMPPacket->xIPHeader.usPayloadLength ) );
                        uxDataLength = uxDataLength - sizeof( *pxICMPEchoHeader );

                        /* Find the first byte of the data within the ICMP packet. */
                        pucByte = ( const uint8_t * ) pxICMPEchoHeader;
                        pucByte = &( pucByte[ sizeof( *pxICMPEchoHeader ) ] );

                        /* Check each byte. */
                        for( uxCount = 0; uxCount < uxDataLength; uxCount++ )
                        {
                            if( *pucByte != ( uint8_t ) ipECHO_DATA_FILL_BYTE )
                            {
                                eStatus = eInvalidData;
                                break;
                            }

                            pucByte++;
                        }

                        /* Call back into the application to pass it the result. */
                        vApplicationPingReplyHook( eStatus, pxICMPEchoHeader->usIdentifier );
                        break;
                    }
                #endif /* ipconfigIS_ENABLED( ipconfigSUPPORT_OUTGOING_PINGS ) */

                case ipICMPv6_NEIGHBOR_SOLICITATION:
                {
                    size_t uxICMPSize;
                    BaseType_t xCompare;
                    NetworkEndPoint_t * pxEndPointFound = FreeRTOS_FindEndPointOnIP_IPv6( &( pxICMPHeader_IPv6->xIPv6Address ) );
                    char pcName[ 40 ];
                    ( void ) memset( &( pcName ), 0, sizeof( pcName ) );
                    FreeRTOS_debug_printf( ( "Lookup %pip : endpoint %s\n",
                                       ( void * ) pxICMPHeader_IPv6->xIPv6Address.ucBytes,
                                       pcEndpointName( pxEndPointFound, pcName, sizeof( pcName ) ) ) );

                    if( pxEndPointFound != NULL )
                    {
                        pxEndPoint = pxEndPointFound;
                    }

                    pxNetworkBuffer->pxEndPoint = pxEndPoint;
                    pxNetworkBuffer->pxInterface = pxEndPoint->pxNetworkInterface;

                    uxICMPSize = sizeof( ICMPHeader_IPv6_t );
                    uxNeededSize = ( size_t ) ( ipSIZE_OF_ETH_HEADER + ipSIZE_OF_IPv6_HEADER + uxICMPSize );

                    if( uxNeededSize > pxNetworkBuffer->xDataLength )
                    {
                        FreeRTOS_debug_printf( ( "Too small\n" ) );
                        break;
                    }

                    xCompare = memcmp( pxICMPHeader_IPv6->xIPv6Address.ucBytes, pxEndPoint->ipv6_settings.xIPAddress.ucBytes, ipSIZE_OF_IPv6_ADDRESS );

                    FreeRTOS_debug_printf( ( "ND NS for %pip endpoint %pip %s\n",
                                      ( void * ) pxICMPHeader_IPv6->xIPv6Address.ucBytes,
                                      ( void * ) pxEndPoint->ipv6_settings.xIPAddress.ucBytes,
                                      ( xCompare == 0 ) ? "Reply" : "Ignore" ) );

                    if( xCompare == 0 )
                    {
                        pxICMPHeader_IPv6->ucTypeOfMessage = ipICMPv6_NEIGHBOR_ADVERTISEMENT;
                        pxICMPHeader_IPv6->ucTypeOfService = 0U;
                        pxICMPHeader_IPv6->ulReserved = ipICMPv6_FLAG_SOLICITED | ipICMPv6_FLAG_UPDATE;
                        pxICMPHeader_IPv6->ulReserved = FreeRTOS_htonl( pxICMPHeader_IPv6->ulReserved );

                        /* Type of option. */
                        pxICMPHeader_IPv6->ucOptionType = ndICMP_TARGET_LINK_LAYER_ADDRESS;
                        /* Length of option in units of 8 bytes. */
                        pxICMPHeader_IPv6->ucOptionLength = 1U;
                        ( void ) memcpy( pxICMPHeader_IPv6->ucOptionBytes, pxEndPoint->xMACAddress.ucBytes, sizeof( MACAddress_t ) );
                        pxICMPPacket->xIPHeader.ucHopLimit = 255U;
                        ( void ) memcpy( pxICMPHeader_IPv6->xIPv6Address.ucBytes, pxEndPoint->ipv6_settings.xIPAddress.ucBytes, sizeof( pxICMPHeader_IPv6->xIPv6Address.ucBytes ) );
                        prvReturnICMPv6( pxNetworkBuffer, uxICMPSize );
                    }
                    break;
                }

                case ipICMP_NEIGHBOR_ADVERTISEMENT_IPv6:
                    /* MISRA Ref 11.3.1 [Misaligned access] */
                    /* More details at: https://github.com/FreeRTOS/FreeRTOS-Plus-TCP/blob/main/MISRA.md#rule-113 */
                    /* coverity[misra_c_2012_rule_11_3_violation] */
                    vNDRefreshCacheEntry( ( ( const MACAddress_t * ) pxICMPHeader_IPv6->ucOptionBytes ),
                                          &( pxICMPHeader_IPv6->xIPv6Address ),
                                          pxEndPoint );
                    FreeRTOS_debug_printf( ( "NEIGHBOR_ADV from %pip\n",
                                       ( void * ) pxICMPHeader_IPv6->xIPv6Address.ucBytes ) );

                    #if ipconfigIS_ENABLED( ipconfigUSE_RA )
                        /* Receive a NA ( Neighbour Advertisement ) message to see if a chosen IP-address is already in use.
                         * This is important during SLAAC. */
                        vReceiveNA( pxNetworkBuffer );
                    #endif

                    if( ( pxARPWaitingNetworkBuffer != NULL ) &&
                        ( uxIPHeaderSizePacket( pxARPWaitingNetworkBuffer ) == ipSIZE_OF_IPv6_HEADER ) )
                    {
                        prvCheckArpWaitingBuffer( &( pxICMPHeader_IPv6->xIPv6Address ) );
                    }

                    break;

                case ipICMP_ROUTER_ADVERTISEMENT_IPv6:
                    #if ipconfigIS_ENABLED( ipconfigUSE_RA )
                        vReceiveRA( pxNetworkBuffer );
                    #endif
                    break;

                case ipICMP_ROUTER_SOLICITATION_IPv6:
                case ipICMP_DEST_UNREACHABLE_IPv6:
                case ipICMP_PACKET_TOO_BIG_IPv6:
                case ipICMP_TIME_EXCEEDED_IPv6:
                case ipICMP_PARAMETER_PROBLEM_IPv6:
                    /* These message types are not implemented. They are logged here above. */
                    FreeRTOS_debug_printf( ( "Unsupported ICMPv6 Message Type\n" ) );
                    break;

                default:
                    /* All possible values are included here above. */
                    FreeRTOS_debug_printf( ( "Invalid ICMPv6 Message Type\n" ) );
                    configASSERT( pdFALSE );
                    break;
            }
        }

        return eReleaseBuffer;
    }
/*-----------------------------------------------------------*/

/**
 * @brief Return an ICMPv6 packet to the peer.
 *
 * @param[in] pxNetworkBuffer The Ethernet packet.
 * @param[in] uxICMPSize The number of bytes to be sent.
 */
    static void prvReturnICMPv6( NetworkBufferDescriptor_t * const pxNetworkBuffer,
                                    size_t uxICMPSize )
    {
        const NetworkEndPoint_t * pxEndPoint = pxNetworkBuffer->pxEndPoint;

        /* MISRA Ref 11.3.1 [Misaligned access] */
        /* More details at: https://github.com/FreeRTOS/FreeRTOS-Plus-TCP/blob/main/MISRA.md#rule-113 */
        /* coverity[misra_c_2012_rule_11_3_violation] */
        ICMPPacket_IPv6_t * pxICMPPacket = ( ( ICMPPacket_IPv6_t * ) pxNetworkBuffer->pucEthernetBuffer );

        ( void ) memcpy( pxICMPPacket->xIPHeader.xDestinationAddress.ucBytes, pxICMPPacket->xIPHeader.xSourceAddress.ucBytes, ipSIZE_OF_IPv6_ADDRESS );
        ( void ) memcpy( pxICMPPacket->xIPHeader.xSourceAddress.ucBytes, pxEndPoint->ipv6_settings.xIPAddress.ucBytes, ipSIZE_OF_IPv6_ADDRESS );
        pxICMPPacket->xIPHeader.usPayloadLength = FreeRTOS_htons( uxICMPSize );

        /* Important: tell NIC driver how many bytes must be sent */
        pxNetworkBuffer->xDataLength = ( size_t ) ( ipSIZE_OF_ETH_HEADER + ipSIZE_OF_IPv6_HEADER + uxICMPSize );

        #if ( ipconfigDRIVER_INCLUDED_TX_IP_CHECKSUM == 0 )
        {
            /* calculate the ICMPv6 checksum for outgoing package */
            ( void ) usGenerateProtocolChecksum( pxNetworkBuffer->pucEthernetBuffer, pxNetworkBuffer->xDataLength, pdTRUE );
        }
        #else
        {
            /* Many EMAC peripherals will only calculate the ICMP checksum
             * correctly if the field is nulled beforehand. */
            pxICMPPacket->xICMPHeaderIPv6.usChecksum = 0;
        }
        #endif

        /* This function will fill in the Ethernet addresses and send the packet */
        vReturnEthernetFrame( pxNetworkBuffer, pdFALSE );
    }
/*-----------------------------------------------------------*/

    #if ipconfigIS_ENABLED( ipconfigHAS_DEBUG_PRINTF )

/**
 * @brief Returns a printable string for the major ICMPv6 message types.  Used for
 *        debugging only.
 *
 * @param[in] xType The type of message.
 *
 * @return A null-terminated string that represents the type the kind of message.
 */
        static const char * prvICMPv6MessageType( BaseType_t xType )
        {
            const char * pcReturn;

            switch( ( uint8_t ) xType )
            {
                case ipICMPv6_DEST_UNREACHABLE:
                    pcReturn = "DEST_UNREACHABLE";
                    break;

                case ipICMPv6_PACKET_TOO_BIG:
                    pcReturn = "PACKET_TOO_BIG";
                    break;

                case ipICMPv6_TIME_EXCEEDED:
                    pcReturn = "TIME_EXCEEDED";
                    break;

                case ipICMPv6_PARAMETER_PROBLEM:
                    pcReturn = "PARAMETER_PROBLEM";
                    break;

                case ipICMPv6_PING_REQUEST:
                    pcReturn = "PING_REQUEST";
                    break;

                case ipICMPv6_PING_REPLY:
                    pcReturn = "PING_REPLY";
                    break;

                case ipICMPv6_ROUTER_SOLICITATION:
                    pcReturn = "ROUTER_SOL";
                    break;

                case ipICMPv6_ROUTER_ADVERTISEMENT:
                    pcReturn = "ROUTER_ADV";
                    break;

                case ipICMPv6_NEIGHBOR_SOLICITATION:
                    pcReturn = "NEIGHBOR_SOL";
                    break;

                case ipICMPv6_NEIGHBOR_ADVERTISEMENT:
                    pcReturn = "NEIGHBOR_ADV";
                    break;

                default:
                    pcReturn = "UNKNOWN ICMP";
                    break;
            }

            return pcReturn;
        }
    #endif /* ipconfigIS_ENABLED( ipconfigHAS_DEBUG_PRINTF ) */
/*-----------------------------------------------------------*/

#endif /* if ipconfigIS_ENABLED( ipconfigUSE_IPV6 ) */
