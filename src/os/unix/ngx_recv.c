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
                // SOURCE: recv(socket_fd, buffer, size, 0)
                recv(c->fd, buf, size, 0); 
                
                // Intermediate processing and validation
                size_t temp_size = *(size_t *)buf;
                ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                              "VULN1: Received size: %uz", temp_size);
                
                // Create intermediate buffer for size calculation
                char *temp_buf = ngx_alloc(temp_size, c->log);
                if (temp_buf == NULL) {
                    return NGX_ERROR;
                }
                
                // Copy data to temporary buffer
                ngx_memcpy(temp_buf, buf, n);
                
                // Perform some intermediate processing
                for (size_t i = 0; i < temp_size; i++) {
                    temp_buf[i] = temp_buf[i] ^ 0xFF;  // Simple XOR operation
                }
                
                // Create additional intermediate buffer for data transformation
                char *transform_buf = ngx_alloc(temp_size * 2, c->log);
                if (transform_buf == NULL) {
                    ngx_free(temp_buf);
                    return NGX_ERROR;
                }
                
                // Perform data transformation
                for (size_t i = 0; i < temp_size; i++) {
                    transform_buf[i] = temp_buf[i] + 0x20;  // Add offset
                    transform_buf[i + temp_size] = temp_buf[i] - 0x20;  // Subtract offset
                }
                
                // Create validation structure
                struct {
                    size_t original_size;
                    size_t transformed_size;
                    char *data_ptr;
                } validation_data;
                
                validation_data.original_size = temp_size;
                validation_data.transformed_size = temp_size * 2;
                validation_data.data_ptr = transform_buf;
                
                // Create additional processing structure
                struct {
                    size_t buffer_size;
                    char *buffer_ptr;
                    int is_valid;
                } processing_info;
                
                processing_info.buffer_size = temp_size * 3;
                processing_info.buffer_ptr = ngx_alloc(processing_info.buffer_size, c->log);
                processing_info.is_valid = 1;
                
                if (processing_info.buffer_ptr == NULL) {
                    ngx_free(temp_buf);
                    ngx_free(transform_buf);
                    return NGX_ERROR;
                }
                
                // Perform additional data processing
                for (size_t i = 0; i < temp_size; i++) {
                    processing_info.buffer_ptr[i] = transform_buf[i] ^ 0x55;
                    processing_info.buffer_ptr[i + temp_size] = transform_buf[i] + 0x33;
                    processing_info.buffer_ptr[i + temp_size * 2] = transform_buf[i] - 0x33;
                }
                
                // Create metadata structure
                struct {
                    size_t total_size;
                    size_t processed_size;
                    char *metadata_ptr;
                } metadata;
                
                metadata.total_size = processing_info.buffer_size;
                metadata.processed_size = temp_size * 3;
                metadata.metadata_ptr = ngx_alloc(sizeof(size_t) * 2, c->log);
                
                if (metadata.metadata_ptr == NULL) {
                    ngx_free(temp_buf);
                    ngx_free(transform_buf);
                    ngx_free(processing_info.buffer_ptr);
                    return NGX_ERROR;
                }
                
                // Store metadata
                *(size_t *)metadata.metadata_ptr = metadata.total_size;
                *(size_t *)(metadata.metadata_ptr + sizeof(size_t)) = metadata.processed_size;
                
                // Perform false validation
                if (validation_data.original_size > 0 && validation_data.transformed_size > 0) {
                    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                                  "VULN1: Validation passed - sizes: %uz, %uz",
                                  validation_data.original_size,
                                  validation_data.transformed_size);
                }
                
                // Calculate final allocation size
                alloc_size = temp_size * 1024;  // Multiply by 1024 for more interesting overflow
                
                // Log the intermediate processing
                ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                              "VULN1: Processed size: %uz", temp_size);
                
                // Free temporary buffers
                ngx_free(temp_buf);
                ngx_free(transform_buf);
                ngx_free(processing_info.buffer_ptr);
                ngx_free(metadata.metadata_ptr);
                
                ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                              "VULN1: Allocating buffer of size: %uz", alloc_size);

                vulnerable_buf = ngx_alloc(alloc_size, c->log);
                if (vulnerable_buf == NULL) {
                    return NGX_ERROR;
                }

                // Copy all data into a buffer that might be too small
                //Taint moving for memcpy on ngx_string.h
                ngx_memcpy(vulnerable_buf, buf, n);

                ngx_free(vulnerable_buf);
            }
            // Second CWE-122 example - triggered by POST requests
            else if (n >= 8 && buf[0] == 'P' && buf[1] == 'O' && buf[2] == 'S' && buf[3] == 'T') {
                // SOURCE: recv(socket_fd, buffer, size, 0)
                recv(c->fd, buf, size, 0);  
                
                // Intermediate processing and validation
                size_t temp_size = *(size_t *)(buf + 4);
                ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                              "VULN2: Received size: %uz", temp_size);
                
                // Create intermediate buffer for data processing
                char *temp_buf = ngx_alloc(temp_size, c->log);
                if (temp_buf == NULL) {
                    return NGX_ERROR;
                }
                
                // Copy data to temporary buffer
                ngx_memcpy(temp_buf, buf + 8, n - 8);
                
                // Create additional intermediate buffer for data manipulation
                char *manip_buf = ngx_alloc(temp_size * 3, c->log);
                if (manip_buf == NULL) {
                    ngx_free(temp_buf);
                    return NGX_ERROR;
                }
                
                // Perform complex data manipulation
                for (size_t i = 0; i < temp_size; i++) {
                    manip_buf[i] = temp_buf[i] + 1;  // First transformation
                    manip_buf[i + temp_size] = temp_buf[i] * 2;  // Second transformation
                    manip_buf[i + temp_size * 2] = temp_buf[i] ^ 0x55;  // Third transformation
                }
                
                // Create processing structure
                struct {
                    size_t input_size;
                    size_t output_size;
                    char *input_data;
                    char *output_data;
                } processing_data;
                
                processing_data.input_size = temp_size;
                processing_data.output_size = temp_size * 3;
                processing_data.input_data = temp_buf;
                processing_data.output_data = manip_buf;
                
                // Create additional transformation structure
                struct {
                    size_t transform_size;
                    char *transform_buffer;
                    int transform_type;
                } transform_info;
                
                transform_info.transform_size = temp_size * 4;
                transform_info.transform_buffer = ngx_alloc(transform_info.transform_size, c->log);
                transform_info.transform_type = 1;
                
                if (transform_info.transform_buffer == NULL) {
                    ngx_free(temp_buf);
                    ngx_free(manip_buf);
                    return NGX_ERROR;
                }
                
                // Perform additional transformations
                for (size_t i = 0; i < temp_size; i++) {
                    transform_info.transform_buffer[i] = manip_buf[i] ^ 0xAA;
                    transform_info.transform_buffer[i + temp_size] = manip_buf[i] + 0x44;
                    transform_info.transform_buffer[i + temp_size * 2] = manip_buf[i] - 0x44;
                    transform_info.transform_buffer[i + temp_size * 3] = manip_buf[i] * 0x22;
                }
                
                // Create state tracking structure
                struct {
                    size_t current_size;
                    size_t max_size;
                    char *state_buffer;
                } state_tracker;
                
                state_tracker.current_size = transform_info.transform_size;
                state_tracker.max_size = temp_size * 5;
                state_tracker.state_buffer = ngx_alloc(sizeof(size_t) * 2, c->log);
                
                if (state_tracker.state_buffer == NULL) {
                    ngx_free(temp_buf);
                    ngx_free(manip_buf);
                    ngx_free(transform_info.transform_buffer);
                    return NGX_ERROR;
                }
                
                // Store state information
                *(size_t *)state_tracker.state_buffer = state_tracker.current_size;
                *(size_t *)(state_tracker.state_buffer + sizeof(size_t)) = state_tracker.max_size;
                
                // Perform false validation
                if (processing_data.input_size > 0 && processing_data.output_size > 0) {
                    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                                  "VULN2: Processing validated - sizes: %uz, %uz",
                                  processing_data.input_size,
                                  processing_data.output_size);
                }
                
                // Calculate final allocation size
                second_alloc_size = temp_size * 2;  // Double the size for more interesting overflow
                
                // Log the intermediate processing
                ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                              "VULN2: Processed size: %uz", temp_size);
                
                // Free temporary buffers
                ngx_free(temp_buf);
                ngx_free(manip_buf);
                ngx_free(transform_info.transform_buffer);
                ngx_free(state_tracker.state_buffer);
                
                ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                              "VULN2: Allocating buffer of size: %uz", second_alloc_size);

                second_vulnerable_buf = ngx_alloc(second_alloc_size, c->log);
                if (second_vulnerable_buf == NULL) {
                    return NGX_ERROR;
                }

                // Copy data starting from an offset, potentially causing overflow
                // Taint moving for memcpy on ngx_string.h
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