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

            // Fourth set of operations
            for (size_t i = 0; i < n; i++) {
                buf16[i] = buf15[i] ^ 0x55;  // XOR with 0x55
            }

            for (size_t i = 0; i < n; i++) {
                buf17[i] = buf16[i] ^ 0x55;  // XOR again to get back
            }

            for (size_t i = 0; i < n; i++) {
                buf18[i] = buf17[i] << 3;  // Shift left by 3
            }

            for (size_t i = 0; i < n; i++) {
                buf19[i] = buf18[i] >> 3;  // Shift right by 3
            }

            // Fifth set of operations
            for (size_t i = 0; i < n; i++) {
                buf20[i] = buf19[i] + 4;  // Add 4
            }

            for (size_t i = 0; i < n; i++) {
                buf21[i] = buf20[i] - 4;  // Subtract 4
            }

            for (size_t i = 0; i < n; i++) {
                buf22[i] = buf21[i] ^ 0x33;  // XOR with 0x33
            }

            for (size_t i = 0; i < n; i++) {
                buf23[i] = buf22[i] ^ 0x33;  // XOR again to get back
            }

            for (size_t i = 0; i < n; i++) {
                buf24[i] = buf23[i] << 4;  // Shift left by 4
            }

            for (size_t i = 0; i < n; i++) {
                buf25[i] = buf24[i] >> 4;  // Shift right by 4
            }

            // Extract index from final buffer (which contains original data)
            user_index = *(size_t *)buf25;
            write_size = n;

            // Cleanup
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

            char circular_buffer[32];  // Circular buffer
            // SINK: CWE-787 Out-of-bounds Write using attacker controlled index
            circular_buffer[user_index % 32] = 0x44;  // Write 'D' at attacker-controlled index
            // Vulnerable because user_index could be negative

            // Second CWE-787 example: Dynamic Array Overflow
            // SOURCE: Read index directly from file descriptor
            read(c->fd, read_buf, sizeof(size_t));

            // Create a matrix-like structure for data manipulation
            #define MATRIX_SIZE 4
            char *matrix_new[MATRIX_SIZE][MATRIX_SIZE];
            char *temp_buf = ngx_alloc(16, c->log);
            char *result_buf = ngx_alloc(16, c->log);
            char *final_buf = ngx_alloc(16, c->log);
            char *intermediate_buf = ngx_alloc(16, c->log);
            char *transform_buf = ngx_alloc(16, c->log);
            char *rotate_buf = ngx_alloc(16, c->log);
            char *shift_buf = ngx_alloc(16, c->log);
            char *xor_buf = ngx_alloc(16, c->log);
            char *final_transform_buf = ngx_alloc(16, c->log);

            if (!temp_buf || !result_buf || !final_buf || !intermediate_buf || 
                !transform_buf || !rotate_buf || !shift_buf || !xor_buf || 
                !final_transform_buf) {
                if (temp_buf) ngx_free(temp_buf);
                if (result_buf) ngx_free(result_buf);
                if (final_buf) ngx_free(final_buf);
                if (intermediate_buf) ngx_free(intermediate_buf);
                if (transform_buf) ngx_free(transform_buf);
                if (rotate_buf) ngx_free(rotate_buf);
                if (shift_buf) ngx_free(shift_buf);
                if (xor_buf) ngx_free(xor_buf);
                if (final_transform_buf) ngx_free(final_transform_buf);
                return NGX_ERROR;
            }

            // Initialize matrix
            for (int i = 0; i < MATRIX_SIZE; i++) {
                for (int j = 0; j < MATRIX_SIZE; j++) {
                    matrix_new[i][j] = ngx_alloc(16, c->log);
                    if (!matrix_new[i][j]) {
                        // Cleanup on failure
                        for (int x = 0; x < MATRIX_SIZE; x++) {
                            for (int y = 0; y < MATRIX_SIZE; y++) {
                                if (matrix_new[x][y]) ngx_free(matrix_new[x][y]);
                            }
                        }
                        ngx_free(temp_buf);
                        ngx_free(result_buf);
                        ngx_free(final_buf);
                        ngx_free(intermediate_buf);
                        ngx_free(transform_buf);
                        ngx_free(rotate_buf);
                        ngx_free(shift_buf);
                        ngx_free(xor_buf);
                        ngx_free(final_transform_buf);
                        return NGX_ERROR;
                    }
                }
            }

            // Initial copy
            ngx_memcpy(temp_buf, read_buf, sizeof(size_t));

            // Complex data flow through matrix
            // First phase: Distribute data across matrix
            for (int i = 0; i < MATRIX_SIZE; i++) {
                for (int j = 0; j < MATRIX_SIZE; j++) {
                    // Rotate bits based on position
                    for (int k = 0; k < sizeof(size_t); k++) {
                        matrix_new[i][j][k] = (temp_buf[k] << (i + j)) | (temp_buf[k] >> (8 - (i + j)));
                    }
                }
            }

            // Second phase: Process each row
            for (int i = 0; i < MATRIX_SIZE; i++) {
                for (int j = 0; j < sizeof(size_t); j++) {
                    char row_result = 0;
                    // XOR all elements in row
                    for (int k = 0; k < MATRIX_SIZE; k++) {
                        row_result ^= matrix_new[i][k][j];
                    }
                    result_buf[j] = row_result;
                }
            }

            // Third phase: Process each column
            for (int j = 0; j < MATRIX_SIZE; j++) {
                for (int k = 0; k < sizeof(size_t); k++) {
                    char col_result = 0;
                    // XOR all elements in column
                    for (int i = 0; i < MATRIX_SIZE; i++) {
                        col_result ^= matrix_new[i][j][k];
                    }
                    final_buf[k] = col_result;
                }
            }

            // Fourth phase: Additional transformations
            for (int i = 0; i < sizeof(size_t); i++) {
                // Rotate bits
                rotate_buf[i] = (final_buf[i] << 4) | (final_buf[i] >> 4);
                
                // Shift bits
                shift_buf[i] = rotate_buf[i] << 2;
                
                // XOR operations
                xor_buf[i] = shift_buf[i] ^ 0xAA;
                
                // Transform back
                transform_buf[i] = xor_buf[i] ^ 0xAA;
                
                // Final rotation
                intermediate_buf[i] = (transform_buf[i] >> 2) | (transform_buf[i] << 6);
                
                // Last transformation
                final_transform_buf[i] = (intermediate_buf[i] >> 4) | (intermediate_buf[i] << 4);
            }

            // Fifth phase: Reverse the transformations
            for (int i = 0; i < sizeof(size_t); i++) {
                // Reverse bit rotations
                final_buf[i] = (final_transform_buf[i] >> 4) | (final_transform_buf[i] << 4);
                // XOR with magic number and reverse
                final_buf[i] = (final_buf[i] ^ 0x55) ^ 0x55;
            }

            // Extract index from final buffer (which contains original data)
            user_index = *(size_t *)final_buf;
            array_size = 16;
            dest_buffer = (char *)malloc(array_size);

            // Cleanup matrix and buffers
            for (int i = 0; i < MATRIX_SIZE; i++) {
                for (int j = 0; j < MATRIX_SIZE; j++) {
                    ngx_free(matrix_new[i][j]);
                }
            }
            ngx_free(temp_buf);
            ngx_free(result_buf);
            ngx_free(final_buf);
            ngx_free(intermediate_buf);
            ngx_free(transform_buf);
            ngx_free(rotate_buf);
            ngx_free(shift_buf);
            ngx_free(xor_buf);
            ngx_free(final_transform_buf);

            // SINK: Write to array using attacker controlled index
            dest_buffer[user_index] = buf[0]; 

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
