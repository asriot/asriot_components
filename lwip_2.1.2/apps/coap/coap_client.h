/*
 * Copyright (c) 2015 Keith Cullen.
 * All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR "AS IS" AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 *  @file coap_client.h
 *
 *  @brief Include file for the FreeCoAP client library
 */

#ifndef COAP_CLIENT_H
#define COAP_CLIENT_H

//#include <time.h>
//#include <netinet/in.h>
#include <sockets.h>
#ifdef COAP_DTLS_EN
#include "tinydtls.h"
#include "dtls.h"
#endif
#include "coap_msg.h"
#include "coap_ipv.h"

#define COAP_CLIENT_HOST_BUF_LEN  128                                           /**< Buffer length for host addresses */
#define COAP_CLIENT_PORT_BUF_LEN  8                                             /**< Buffer length for port numbers */

#ifdef COAP_DTLS_EN

/**
 *  @brief Client DTLS state enumeration
 */
typedef enum
{
    COAP_CLIENT_DTLS_UNCONNECTED = 0,                                           /**< DTLS session is not active */
    COAP_CLIENT_DTLS_CONNECTED,                                                 /**< DTLS session is active */
    COAP_CLIENT_DTLS_ALERT                                                      /**< A DTLS alert message was received from the server */
}
coap_client_dtls_state_t;

#define coap_client_dtls_get_state(client)  ((client)->state)                   /**< Get DTLS state */

#endif

struct timespec_coap {
long unsigned int tv_sec;
long unsigned int tv_nsec;
};
/**
 *  @brief Client structure
 */
typedef struct
{
    int sd;                                                                     /**< Socket descriptor */
    int timer_fd;                                                               /**< Timer file descriptor */
    struct timespec_coap timeout;                                                    /**< Timeout value */
    unsigned num_retrans;                                                       /**< Current number of retransmissions */
    coap_ipv_sockaddr_in_t server_sin;                                          /**< Socket structture */
    socklen_t server_sin_len;                                                   /**< Socket structure length */
    char server_host[COAP_CLIENT_HOST_BUF_LEN];                                 /**< String to hold the server host address */
    char server_port[COAP_CLIENT_PORT_BUF_LEN];                                 /**< String to hold the server port number */
#ifdef COAP_DTLS_EN
    coap_client_dtls_state_t state;                                             /**< Current state of the DTLS session */
    dtls_context_t *ctx;                                                        /**< DTLS context */
    session_t sess;                                                             /**< DTLS session */
    dtls_ecdsa_key_t ecdsa_key;                                                 /**< ECDSA keys */
    const unsigned char *ecdsa_access_x;                                        /**< Buffer containing the x components of the ECDSA access control list */
    const unsigned char *ecdsa_access_y;                                        /**< Buffer containing the y components of the ECDSA access control list */
    unsigned ecdsa_access_num;                                                  /**< Number of entries in the ECDSA access control list */
    unsigned ecdsa_size;                                                        /**< Size of an ECDSA component */
    char *app_start;                                                            /**< Start of application data */
    size_t app_len;                                                             /**< Length of application data */
#endif
}
coap_client_t;

#ifdef COAP_DTLS_EN

/**
 *  @brief Initialise a client structure
 *
 *  @param[out] client Pointer to a client structure
 *  @param[in] host Pointer to a string containing the host address of the server
 *  @param[in] port Port number of the server
 *  @param[in] ecdsa_priv_key Buffer containing the ECDSA private key
 *  @param[in] ecdsa_pub_key_x Buffer containing the x component of the ECDSA public key
 *  @param[in] ecdsa_pub_key_y Buffer containing the y component of the ECDSA public key
 *  @param[in] ecdsa_access_x Buffer containing the x components of the ECDSA access control list
 *  @param[in] ecdsa_access_y Buffer containing the y components of the ECDSA access control list
 *  @param[in] ecdsa_access_num Number of entries in the ECDSA access control list
 *  @param[in] ecdsa_size Size of an ECDSA component
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
int coap_client_create(coap_client_t *client,
                       const char *host,
                       const char *port,
                       const unsigned char *ecdsa_priv_key,
                       const unsigned char *ecdsa_pub_key_x,
                       const unsigned char *ecdsa_pub_key_y,
                       const unsigned char *ecdsa_access_x,
                       const unsigned char *ecdsa_access_y,
                       unsigned ecdsa_access_num,
                       unsigned ecdsa_size);

#else  /* !COAP_DTLS_EN */

/**
 *  @brief Initialise a client structure
 *
 *  @param[out] client Pointer to a client structure
 *  @param[in] host Pointer to a string containing the host address of the server
 *  @param[in] port Port number of the server
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
int coap_client_create(coap_client_t *client,
                       const char *host,
                       const char *port);

#endif  /* COAP_DTLS_EN */

/**
 *  @brief Deinitialise a client structure
 *
 *  @param[in,out] client Pointer to a client structure
 */
void coap_client_destroy(coap_client_t *client);

/**
 *  @brief Send a request to the server and receive the response
 *
 *  This function sets the message ID and token fields of
 *  the request message overriding any values set by the
 *  calling function.
 *
 *  @param[in,out] client Pointer to a client structure
 *  @param[in] req Pointer to the request message
 *  @param[out] resp Pointer to the response message
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 **/
int coap_client_exchange(coap_client_t *client, coap_msg_t *req, coap_msg_t *resp);

/**
 *  @brief Exchange with the server using blockwise transfers
 *
 *  The calling application should not pass in a request
 *  message that contains a block1 or block2 option. This
 *  function will add block1 and block2 options internally.
 *  This function sets the message ID and token fields of
 *  the request message overriding any values set by the
 *  calling function.
 *
 *  @param[in,out] client Pointer to a client structure
 *  @param[in] req Pointer to the request message
 *  @param[out] resp Pointer to the response message
 *  @param[in] block1_size Block1 size
 *  @param[in] block2_size Block2 size
 *  @param[in] body Pointer to a buffer to hold the body
 *  @param[in] body_len Length of the buffer to hold the body
 *  @param[in] have_resp Flag to indicate that the first response has already been received
 *
 *  @returns Operation status
 *  @retval >=0 Length of the data received
 *  @retval <0 Error
 **/
ssize_t coap_client_exchange_blockwise(coap_client_t *client,
                                       coap_msg_t *req, coap_msg_t *resp,
                                       unsigned block1_size, unsigned block2_size,
                                       char *body, size_t body_len, int have_resp);

#endif
