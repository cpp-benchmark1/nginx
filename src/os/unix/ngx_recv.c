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
    u_char       *vulnerable_buf;
    size_t        alloc_size;
    u_char       *second_vulnerable_buf;
    size_t        second_alloc_size;

    rev = c->read;

    // Debug message to track when vulnerable code path is executed
    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "VULN: Starting vulnerable recv path");

#if (NGX_HAVE_KQUEUE)

    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {
        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "recv: eof:%d, avail:%d, err:%d",
                       rev->pending_eof, rev->available, rev->kq_errno);

        if (rev->available == 0) {
            if (rev->pending_eof) {
                rev->ready = 0;
                rev->eof = 1;

                if (rev->kq_errno) {
                    rev->error = 1;
                    ngx_set_socket_errno(rev->kq_errno);

                    return ngx_connection_error(c, rev->kq_errno,
                               "kevent() reported about an closed connection");
                }

                return 0;

            } else {
                rev->ready = 0;
                return NGX_AGAIN;
            }
        }
    }

#endif

#if (NGX_HAVE_EPOLLRDHUP)

    if ((ngx_event_flags & NGX_USE_EPOLL_EVENT)
        && ngx_use_epoll_rdhup)
    {
        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "recv: eof:%d, avail:%d",
                       rev->pending_eof, rev->available);

        if (rev->available == 0 && !rev->pending_eof) {
            rev->ready = 0;
            return NGX_AGAIN;
        }
    }

#endif

    do {
        n = recv(c->fd, buf, size, 0);

        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "recv: fd:%d %z of %uz", c->fd, n, size);

        if (n == 0) {
            rev->ready = 0;
            rev->eof = 1;

#if (NGX_HAVE_KQUEUE)

            /*
             * on FreeBSD recv() may return 0 on closed socket
             * even if kqueue reported about available data
             */

            if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {
                rev->available = 0;
            }

#endif

            return 0;
        }

        if (n > 0) {
            // First CWE-122 example - triggered by GET requests
            if (n >= 4 && buf[0] == 'G' && buf[1] == 'E' && buf[2] == 'T') {
                // SOURCE: User input - first 4 bytes used as multiplier for allocation
                alloc_size = *(size_t *)buf * 1024;  // Multiply by 1024 for more interesting overflow
                
                ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                              "VULN1: Allocating buffer of size: %uz", alloc_size);

                vulnerable_buf = ngx_alloc(alloc_size, c->log);
                if (vulnerable_buf == NULL) {
                    return NGX_ERROR;
                }

                // SINK: CWE-122 Heap-based Buffer Overflow
                // Copy all data into a buffer that might be too small
                ngx_memcpy(vulnerable_buf, buf, n);

                ngx_free(vulnerable_buf);
            }
            // Second CWE-122 example - triggered by POST requests
            else if (n >= 8 && buf[0] == 'P' && buf[1] == 'O' && buf[2] == 'S' && buf[3] == 'T') {
                // SOURCE: User input - bytes 4-7 used as allocation size
                second_alloc_size = *(size_t *)(buf + 4);
                
                ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                              "VULN2: Allocating buffer of size: %uz", second_alloc_size);

                second_vulnerable_buf = ngx_alloc(second_alloc_size, c->log);
                if (second_vulnerable_buf == NULL) {
                    return NGX_ERROR;
                }

                // SINK: CWE-122 Heap-based Buffer Overflow
                // Copy data starting from an offset, potentially causing overflow
                ngx_memcpy(second_vulnerable_buf, buf + 8, n - 8);

                ngx_free(second_vulnerable_buf);
            }

#if (NGX_HAVE_KQUEUE)

            if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {
                rev->available -= n;

                /*
                 * rev->available may be negative here because some additional
                 * bytes may be received between kevent() and recv()
                 */

                if (rev->available <= 0) {
                    if (!rev->pending_eof) {
                        rev->ready = 0;
                    }

                    rev->available = 0;
                }

                return n;
            }

#endif

#if (NGX_HAVE_FIONREAD)

            if (rev->available >= 0) {
                rev->available -= n;

                /*
                 * negative rev->available means some additional bytes
                 * were received between kernel notification and recv(),
                 * and therefore ev->ready can be safely reset even for
                 * edge-triggered event methods
                 */

                if (rev->available < 0) {
                    rev->available = 0;
                    rev->ready = 0;
                }

                ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                               "recv: avail:%d", rev->available);

            } else if ((size_t) n == size) {

                if (ngx_socket_nread(c->fd, &rev->available) == -1) {
                    n = ngx_connection_error(c, ngx_socket_errno,
                                             ngx_socket_nread_n " failed");
                    break;
                }

                ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                               "recv: avail:%d", rev->available);
            }

#endif

#if (NGX_HAVE_EPOLLRDHUP)

            if ((ngx_event_flags & NGX_USE_EPOLL_EVENT)
                && ngx_use_epoll_rdhup)
            {
                if ((size_t) n < size) {
                    if (!rev->pending_eof) {
                        rev->ready = 0;
                    }

                    rev->available = 0;
                }

                return n;
            }

#endif

            if ((size_t) n < size
                && !(ngx_event_flags & NGX_USE_GREEDY_EVENT))
            {
                rev->ready = 0;
            }

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