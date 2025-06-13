/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <string.h>
#include <stdio.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <unistd.h>  // For read()
#include <sys/socket.h>


ssize_t
ngx_unix_recv(ngx_connection_t *c, u_char *buf, size_t size)
{
    ssize_t       n;
    ngx_err_t     err;
    ngx_event_t  *rev;
    u_char       *vulnerable_buf;
    size_t        alloc_size;
    u_char       *second_vulnerable_buf;
    size_t        second_alloc_size;

    // Structure to track processing state
    struct {
        size_t current_size;
        size_t max_size;
        u_char *data_ptr;
        int processing_stage;
        size_t compressed_size;
        int compression_ratio;
    } processing_state;

    rev = c->read;

    // Debug message to track when vulnerable code path is executed
    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "VULN: Starting vulnerable recv path");

#if (NGX_HAVE_KQUEUE)
    size_t        user_index;  // Attacker controlled index
    size_t        write_size;  // Size to write
    char         *dest_buffer; // Second vulnerability buffer
    size_t        array_size;  // Size of the array
    char          read_buf[8]; // Buffer for read operation

    rev = c->read;

    do {
        // SOURCE: Network input - receives attacker controlled data from socket
        // This is the entry point where attacker data enters the system
        n = recv(c->fd, buf, size, 0);  //SOURCE

        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "recv: fd:%d %z of %uz", c->fd, n, size);

        if (n == 0) {
            rev->ready = 0;
            rev->eof = 1;
            return 0;
        }

        if (n > 0) {
            // First CWE-787 example: Fixed Buffer Overflow
            // SOURCE: Network input - receives attacker controlled data from socket
            n = recv(c->fd, buf, size, 0);  

            // Create multiple buffers for data manipulation
            char *buf1 = ngx_alloc(n, c->log);
            char *buf2 = ngx_alloc(n, c->log);
            char *buf3 = ngx_alloc(n, c->log);
            char *buf4 = ngx_alloc(n, c->log);
            char *buf5 = ngx_alloc(n, c->log);
            char *buf6 = ngx_alloc(n, c->log);
            char *buf7 = ngx_alloc(n, c->log);
            char *buf8 = ngx_alloc(n, c->log);
            char *buf9 = ngx_alloc(n, c->log);
            char *buf10 = ngx_alloc(n, c->log);
            char *buf11 = ngx_alloc(n, c->log);
            char *buf12 = ngx_alloc(n, c->log);
            char *buf13 = ngx_alloc(n, c->log);
            char *buf14 = ngx_alloc(n, c->log);
            char *buf15 = ngx_alloc(n, c->log);
            char *buf16 = ngx_alloc(n, c->log);
            char *buf17 = ngx_alloc(n, c->log);
            char *buf18 = ngx_alloc(n, c->log);
            char *buf19 = ngx_alloc(n, c->log);
            char *buf20 = ngx_alloc(n, c->log);
            char *buf21 = ngx_alloc(n, c->log);
            char *buf22 = ngx_alloc(n, c->log);
            char *buf23 = ngx_alloc(n, c->log);
            char *buf24 = ngx_alloc(n, c->log);
            char *buf25 = ngx_alloc(n, c->log);

            if (!buf1 || !buf2 || !buf3 || !buf4 || !buf5 || !buf6 || !buf7 || !buf8 || 
                !buf9 || !buf10 || !buf11 || !buf12 || !buf13 || !buf14 || !buf15 ||
                !buf16 || !buf17 || !buf18 || !buf19 || !buf20 || !buf21 || !buf22 ||
                !buf23 || !buf24 || !buf25) {
                if (buf1) ngx_free(buf1);
                if (buf2) ngx_free(buf2);
                if (buf3) ngx_free(buf3);
                if (buf4) ngx_free(buf4);
                if (buf5) ngx_free(buf5);
                if (buf6) ngx_free(buf6);
                if (buf7) ngx_free(buf7);
                if (buf8) ngx_free(buf8);
                if (buf9) ngx_free(buf9);
                if (buf10) ngx_free(buf10);
                if (buf11) ngx_free(buf11);
                if (buf12) ngx_free(buf12);
                if (buf13) ngx_free(buf13);
                if (buf14) ngx_free(buf14);
                if (buf15) ngx_free(buf15);
                if (buf16) ngx_free(buf16);
                if (buf17) ngx_free(buf17);
                if (buf18) ngx_free(buf18);
                if (buf19) ngx_free(buf19);
                if (buf20) ngx_free(buf20);
                if (buf21) ngx_free(buf21);
                if (buf22) ngx_free(buf22);
                if (buf23) ngx_free(buf23);
                if (buf24) ngx_free(buf24);
                if (buf25) ngx_free(buf25);
                return NGX_ERROR;
            }

            // Start data flow with input
            ngx_memcpy(buf1, buf, n);

            // First set of operations
            for (size_t i = 0; i < n; i++) {
                buf2[i] = buf1[i] + 1;  // Add 1
            }

            for (size_t i = 0; i < n; i++) {
                buf3[i] = buf2[i] - 1;  // Subtract 1
            }

            for (size_t i = 0; i < n; i++) {
                buf4[i] = buf3[i] ^ 0xFF;  // XOR with 0xFF
            }

            for (size_t i = 0; i < n; i++) {
                buf5[i] = buf4[i] ^ 0xFF;  // XOR again to get back
            }

            for (size_t i = 0; i < n; i++) {
                buf6[i] = buf5[i] << 1;  // Shift left
            }

            for (size_t i = 0; i < n; i++) {
                buf7[i] = buf6[i] >> 1;  // Shift right
            }

            // Second set of operations
            for (size_t i = 0; i < n; i++) {
                buf8[i] = buf7[i] + 2;  // Add 2
            }

            for (size_t i = 0; i < n; i++) {
                buf9[i] = buf8[i] - 2;  // Subtract 2
            }

            for (size_t i = 0; i < n; i++) {
                buf10[i] = buf9[i] ^ 0xAA;  // XOR with 0xAA
            }

            for (size_t i = 0; i < n; i++) {
                buf11[i] = buf10[i] ^ 0xAA;  // XOR again to get back
            }

            for (size_t i = 0; i < n; i++) {
                buf12[i] = buf11[i] << 2;  // Shift left by 2
            }

            for (size_t i = 0; i < n; i++) {
                buf13[i] = buf12[i] >> 2;  // Shift right by 2
            }

            // Third set of operations
            for (size_t i = 0; i < n; i++) {
                buf14[i] = buf13[i] + 3;  // Add 3
            }

            for (size_t i = 0; i < n; i++) {
                buf15[i] = buf14[i] - 3;  // Subtract 3
            }

            // First CWE-122 example - triggered by GET requests
            if (n >= 4 && buf[0] == 'G' && buf[1] == 'E' && buf[2] == 'T') {
                // SOURCE: recv(socket_fd, buffer, size, 0)
                recv(c->fd, buf, size, 0); 
            }

            // Clean up allocated buffers
            ngx_free(buf1);
            ngx_free(buf2);
            ngx_free(buf3);
            ngx_free(buf4);
            ngx_free(buf5);
            ngx_free(buf6);
            ngx_free(buf7);
            ngx_free(buf8);
            ngx_free(buf9);
            ngx_free(buf10);
            ngx_free(buf11);
            ngx_free(buf12);
            ngx_free(buf13);
            ngx_free(buf14);
            ngx_free(buf15);
            ngx_free(buf16);
            ngx_free(buf17);
            ngx_free(buf18);
            ngx_free(buf19);
            ngx_free(buf20);
            ngx_free(buf21);
            ngx_free(buf22);
            ngx_free(buf23);
            ngx_free(buf24);
            ngx_free(buf25);

            return n;
        }

        err = ngx_socket_errno;

        if (err == NGX_EAGAIN || err == NGX_EINTR) {
            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, err,
                           "recv() not ready");
            n = NGX_AGAIN;
        } else {
            n = ngx_connection_error(c, err, "recv() failed");
            break;
        }

    } while (err == NGX_EINTR);

    rev->ready = 0;

    if (n == NGX_ERROR) {
        rev->error = 1;
    }

    return n;
#endif

    return NGX_ERROR;
}
