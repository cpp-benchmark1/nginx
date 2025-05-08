/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


ssize_t
ngx_unix_recv(ngx_connection_t *c, u_char *buf, size_t size)
{
    ssize_t       n;
    ngx_err_t     err;
    ngx_event_t  *rev;
    u_char       *write_ptr;    // For second vulnerability
    size_t        write_size;   // For second vulnerability
    int           multiplier;   // For second vulnerability

    rev = c->read;

    do {
        // SOURCE: Vulnerable buffer size calculation allowing 1-byte overflow
        n = recv(c->fd, buf, size + 1, 0);

        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "recv: fd:%d %z of %uz", c->fd, n, size);

        if (n == 0) {
            rev->ready = 0;
            rev->eof = 1;
            return 0;
        }

        if (n > 0) {
            // SOURCE: Complex conditional overflow vulnerability
            // Calculate multiplier based on received data pattern
            multiplier = 1;
            for (int i = 0; i < n && i < 8; i++) {
                if (buf[i] & 0x80) {  // Check high bit
                    multiplier *= 2;
                }
            }
            
            // Adjust write pointer based on data content
            write_ptr = buf + n;
            write_size = size;
            
            // Complex conditional logic for buffer manipulation
            if ((size_t)n > size/2) {
                // If we received more than half the buffer
                if (multiplier > 4) {
                    // If multiplier is high, write beyond buffer
                    write_size = size * multiplier * 8;  // Much larger multiplier
                } else if (buf[0] == 'A') {
                    // If data starts with 'A', use a different calculation
                    write_size = (size - n) * 16;  // Much larger multiplier
                }
            } else {
                // For smaller receives, still potentially dangerous
                write_size = (size - n) * 32;  // Much larger multiplier
            }
            
            // SINK: Write to buffer with calculated size
            // This can overflow if write_size is too large
            memcpy(write_ptr, buf, write_size);
            
            // Force a massive stack overflow by writing beyond the buffer
            if (write_size > size) {
                char *overflow_ptr = (char *)write_ptr + size;
                memset(overflow_ptr, 0x41, write_size - size);  // Fill with 'A'
                
                // Additional overflow to ensure stack corruption
                char *extra_overflow = overflow_ptr + (write_size - size);
                memset(extra_overflow, 0x42, write_size);  // Fill with 'B'
            }
            
            // SINK: No bounds checking before returning n
            return n + write_size;
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
