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
 * @file FreeRTOS_ICMP.h
 * @brief Header file for Internet Control Message Protocol for the FreeRTOS+TCP network stack.
 */

#ifndef FREERTOS_ICMP_H
#define FREERTOS_ICMP_H

/* FreeRTOS+TCP includes. */
#include "FreeRTOS_IP.h"
#include "FreeRTOS_IP_Private.h"

/* *INDENT-OFF* */
#ifdef __cplusplus
    extern "C" {
#endif
/* *INDENT-ON* */

/* ICMP protocol definitions. */
#define ipICMP_ECHO_REQUEST    ( ( uint8_t ) 8 )
#define ipICMP_ECHO_REPLY      ( ( uint8_t ) 0 )

/* ICMPv6 protocol message types. */
#define ipICMPv6_DEST_UNREACHABLE             ( ( uint8_t ) 1U )
#define ipICMPv6_PACKET_TOO_BIG               ( ( uint8_t ) 2U )
#define ipICMPv6_TIME_EXCEEDED                ( ( uint8_t ) 3U )
#define ipICMPv6_PARAMETER_PROBLEM            ( ( uint8_t ) 4U )
#define ipICMPv6_PING_REQUEST                 ( ( uint8_t ) 128U )
#define ipICMPv6_PING_REPLY                   ( ( uint8_t ) 129U )
#define ipICMPv6_ROUTER_SOLICITATION          ( ( uint8_t ) 133U )
#define ipICMPv6_ROUTER_ADVERTISEMENT         ( ( uint8_t ) 134U )
#define ipICMPv6_NEIGHBOR_SOLICITATION        ( ( uint8_t ) 135U )
#define ipICMPv6_NEIGHBOR_ADVERTISEMENT       ( ( uint8_t ) 136U )
#define ipICMPv6_REDIRECT_MESSAGE             ( ( uint8_t ) 137U )

/* Types of Neighbour Advertisement packets. */
#define ipICMPv6_FLAG_SOLICITED                       0x40000000U
#define ipICMPv6_FLAG_UPDATE                          0x20000000U

/** @brief Process incoming ICMP packets. */
eFrameProcessingResult_t eProcessICMPPacket( const struct xNETWORK_BUFFER * const pxNetworkBuffer );

/** @brief Process incoming ICMPv6 packets. */
eFrameProcessingResult_t eProcessICMPv6Packet( struct xNETWORK_BUFFER * const pxNetworkBuffer );

/* *INDENT-OFF* */
#ifdef __cplusplus
    } /* extern "C" */
#endif
/* *INDENT-ON* */

#endif /* FREERTOS_ICMP_H */
