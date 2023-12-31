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
 *  @file coap_log.h
 *
 *  @brief Include file for the FreeCoAP logging module
 */

#ifndef COAP_LOG_H
#define COAP_LOG_H

#define COAP_LOG_DEF_LEVEL  COAP_LOG_ERROR                                      /**< Default log level */

/**
 *  @brief Log level
 */
typedef enum
{
    COAP_LOG_ERROR = 0,                                                         /**< Error log level */
    COAP_LOG_WARN = 1,                                                          /**< Warning log level */
    COAP_LOG_NOTICE = 2,                                                        /**< Notice log level */
    COAP_LOG_INFO = 3,                                                          /**< Informational log level */
    COAP_LOG_DEBUG = 4                                                          /**< Debug log level */
}
coap_log_level_t;

extern coap_log_level_t coap_log_level;


/**
 *  @brief Set the log level
 *
 *  Messages with a severity below this level will be filtered.
 *  Error messages cannot be filtered.
 *
 *  @param[in] level The new log level
 */
void coap_log_set_level(coap_log_level_t level);

/**
 *  @brief Get the log level
 *
 *  @returns The current log level
 */
coap_log_level_t coap_log_get_level(void);

#define coap_log_error(Fmt, ...)\
    do {\
        if (COAP_LOG_ERROR <= coap_log_level) {\
            printf("Error   : ");\
            printf(Fmt "\r\n", ## __VA_ARGS__);\
        }\
    }while(0)

#define coap_log_warn(Fmt, ...)\
    do {\
        if (COAP_LOG_WARN <= coap_log_level) {\
            printf("Warn   : ");\
            printf(Fmt "\r\n", ## __VA_ARGS__);\
        }\
    }while(0)
            
#define coap_log_notice(Fmt, ...)\
    do {\
        if (COAP_LOG_NOTICE <= coap_log_level) {\
            printf("Notice   : ");\
            printf(Fmt "\r\n", ## __VA_ARGS__);\
        }\
    }while(0)

#define coap_log_info(Fmt, ...)\
    do {\
        if (COAP_LOG_INFO <= coap_log_level) {\
            printf("Info   : ");\
            printf(Fmt "\r\n", ## __VA_ARGS__);\
        }\
    }while(0)

#define coap_log_debug(Fmt, ...)\
    do {\
        if (COAP_LOG_DEBUG <= coap_log_level) {\
            printf("Info   : ");\
            printf(Fmt "\r\n", ## __VA_ARGS__);\
        }\
    }while(0)


#endif
