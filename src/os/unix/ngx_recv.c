/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <unistd.h>  // For read()


ssize_t
ngx_unix_recv(ngx_connection_t *c, u_char *buf, size_t size)
{
    ssize_t       n;
    ngx_err_t     err;
    ngx_event_t  *rev;
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
            // Extract user controlled index from received data
            user_index = *(size_t *)buf;
            
            // Calculate write size based on received data
            write_size = n;
            
            // SINK: Out-of-bounds write using attacker controlled index
            // This will write beyond the buffer if user_index is large
            // The attacker can cause a buffer overflow by providing a large user_index
            memcpy(buf + user_index, buf, write_size);  //SINK

            // Second CWE-787 example: Dynamic Array Overflow
            // SOURCE: Read index directly from file descriptor
            // The attacker can control where to write in the array
            read(c->fd, read_buf, sizeof(size_t));  //SOURCE
            user_index = *(size_t *)read_buf;
            
            // Allocate a small fixed-size buffer
            array_size = 16;  // Small fixed size
            dest_buffer = (char *)malloc(array_size);
            
            // SINK: Write to array using attacker controlled index
            // This will write beyond the array if user_index is large
            // The attacker can cause an out-of-bounds write by providing a large index
            dest_buffer[user_index] = buf[0];  //SINK
            
            // Force a crash by writing to invalid memory
            if (user_index > array_size) {
                char *overflow_ptr = dest_buffer + array_size;
                memset(overflow_ptr, 0x41, user_index - array_size);
            }
            
            // Clean up allocated memory
            free(dest_buffer);
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
}
