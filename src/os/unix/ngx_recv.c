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

                return 0;
            } else {
                rev->ready = 0;
                return NGX_AGAIN;
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

    do {
        n = recv(c->fd, buf, size, 0);
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

        if (n > 0) {
            // First CWE-122 example - triggered by GET requests
            if (n >= 4 && buf[0] == 'G' && buf[1] == 'E' && buf[2] == 'T') {
                // SOURCE: recv(socket_fd, buffer, size, 0)
                recv(c->fd, buf, size, 0); 
                
                // Vulnerability: User-controlled input from socket is directly used to determine buffer size
                // and copied into heap buffer without proper bounds checking. The size value is read from
                // the beginning of the buffer and used to allocate memory, which can lead to heap overflow
                // if the size value is manipulated. This is a classic example of integer overflow leading
                // to buffer overflow.
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
                
                // Create intermediate processing buffers
                char *stage1_buf = ngx_alloc(temp_size * 2, c->log);
                char *stage2_buf = ngx_alloc(temp_size * 3, c->log);
                char *stage3_buf = ngx_alloc(temp_size * 4, c->log);
                
                if (!stage1_buf || !stage2_buf || !stage3_buf) {
                    ngx_free(temp_buf);
                    ngx_free(stage1_buf);
                    ngx_free(stage2_buf);
                    ngx_free(stage3_buf);
                    return NGX_ERROR;
                }
                
                // Stage 1: Data transformation with bit manipulation
                for (size_t i = 0; i < temp_size; i++) {
                    stage1_buf[i] = temp_buf[i] ^ 0xFF;
                    stage1_buf[i + temp_size] = ~temp_buf[i];
                }
                
                // Stage 2: Data transformation with arithmetic operations
                for (size_t i = 0; i < temp_size * 2; i++) {
                    stage2_buf[i] = stage1_buf[i] + 0x20;
                    stage2_buf[i + temp_size * 2] = stage1_buf[i] - 0x20;
                }
                
                // Stage 3: Complex data transformation
                for (size_t i = 0; i < temp_size * 3; i++) {
                    stage3_buf[i] = stage2_buf[i] ^ 0x55;
                    stage3_buf[i + temp_size * 3] = stage2_buf[i] + 0x33;
                }

                // Additional Stage 4: Advanced bit manipulation
                char *stage4_buf = ngx_alloc(temp_size * 5, c->log);
                if (stage4_buf == NULL) {
                    ngx_free(temp_buf);
                    ngx_free(stage1_buf);
                    ngx_free(stage2_buf);
                    ngx_free(stage3_buf);
                    return NGX_ERROR;
                }

                // Perform advanced bit operations
                for (size_t i = 0; i < temp_size * 4; i++) {
                    stage4_buf[i] = stage3_buf[i] << 2;  // Left shift
                    stage4_buf[i + temp_size * 4] = stage3_buf[i] >> 2;  // Right shift
                }

                // Additional Stage 5: Data compression simulation
                char *stage5_buf = ngx_alloc(temp_size * 6, c->log);
                if (stage5_buf == NULL) {
                    ngx_free(temp_buf);
                    ngx_free(stage1_buf);
                    ngx_free(stage2_buf);
                    ngx_free(stage3_buf);
                    ngx_free(stage4_buf);
                    return NGX_ERROR;
                }

                // Simulate compression by removing null bytes
                size_t compressed_size = 0;
                for (size_t i = 0; i < temp_size * 5; i++) {
                    if (stage4_buf[i] != 0) {
                        stage5_buf[compressed_size++] = stage4_buf[i];
                    }
                }

                // Additional Stage 6: Data encryption simulation
                char *stage6_buf = ngx_alloc(temp_size * 7, c->log);
                if (stage6_buf == NULL) {
                    ngx_free(temp_buf);
                    ngx_free(stage1_buf);
                    ngx_free(stage2_buf);
                    ngx_free(stage3_buf);
                    ngx_free(stage4_buf);
                    ngx_free(stage5_buf);
                    return NGX_ERROR;
                }

                // Simulate encryption with XOR and rotation
                for (size_t i = 0; i < temp_size * 6; i++) {
                    stage6_buf[i] = stage5_buf[i] ^ 0xAA;
                    stage6_buf[i] = (stage6_buf[i] << 4) | (stage6_buf[i] >> 4);
                    stage6_buf[i + temp_size * 6] = stage5_buf[i] ^ 0x55;
                }

                // Additional Stage 7: Data encoding
                char *stage7_buf = ngx_alloc(temp_size * 8, c->log);
                if (stage7_buf == NULL) {
                    ngx_free(temp_buf);
                    ngx_free(stage1_buf);
                    ngx_free(stage2_buf);
                    ngx_free(stage3_buf);
                    ngx_free(stage4_buf);
                    ngx_free(stage5_buf);
                    ngx_free(stage6_buf);
                    return NGX_ERROR;
                }

                // Perform base64-like encoding
                for (size_t i = 0; i < temp_size * 7; i++) {
                    stage7_buf[i] = (stage6_buf[i] & 0x3F) + 'A';
                    stage7_buf[i + temp_size * 7] = ((stage6_buf[i] >> 6) & 0x3F) + 'A';
                }

                // Additional Stage 8: Data compression
                char *stage8_buf = ngx_alloc(temp_size * 9, c->log);
                if (stage8_buf == NULL) {
                    ngx_free(temp_buf);
                    ngx_free(stage1_buf);
                    ngx_free(stage2_buf);
                    ngx_free(stage3_buf);
                    ngx_free(stage4_buf);
                    ngx_free(stage5_buf);
                    ngx_free(stage6_buf);
                    ngx_free(stage7_buf);
                    return NGX_ERROR;
                }

                // Simulate RLE compression
                size_t compressed_idx = 0;
                for (size_t i = 0; i < temp_size * 8; i++) {
                    if (i > 0 && stage7_buf[i] == stage7_buf[i-1]) {
                        stage8_buf[compressed_idx-2]++;
                    } else {
                        stage8_buf[compressed_idx++] = 1;
                        stage8_buf[compressed_idx++] = stage7_buf[i];
                    }
                }

                // Additional Stage 9: Data validation
                char *stage9_buf = ngx_alloc(temp_size * 10, c->log);
                if (stage9_buf == NULL) {
                    ngx_free(temp_buf);
                    ngx_free(stage1_buf);
                    ngx_free(stage2_buf);
                    ngx_free(stage3_buf);
                    ngx_free(stage4_buf);
                    ngx_free(stage5_buf);
                    ngx_free(stage6_buf);
                    ngx_free(stage7_buf);
                    ngx_free(stage8_buf);
                    return NGX_ERROR;
                }

                // Add checksums and validation data
                uint32_t checksum = 0;
                for (size_t i = 0; i < compressed_idx; i++) {
                    checksum ^= stage8_buf[i];
                    stage9_buf[i] = stage8_buf[i];
                }
                *(uint32_t *)(stage9_buf + compressed_idx) = checksum;

                // Additional Stage 10: Final processing
                char *stage10_buf = ngx_alloc(temp_size * 11, c->log);
                if (stage10_buf == NULL) {
                    ngx_free(temp_buf);
                    ngx_free(stage1_buf);
                    ngx_free(stage2_buf);
                    ngx_free(stage3_buf);
                    ngx_free(stage4_buf);
                    ngx_free(stage5_buf);
                    ngx_free(stage6_buf);
                    ngx_free(stage7_buf);
                    ngx_free(stage8_buf);
                    ngx_free(stage9_buf);
                    return NGX_ERROR;
                }

                // Final data transformation
                for (size_t i = 0; i < compressed_idx + 4; i++) {
                    stage10_buf[i] = stage9_buf[i] ^ checksum;
                    stage10_buf[i] = (stage10_buf[i] << 2) | (stage10_buf[i] >> 6);
                }

                // Additional Stage 11: Advanced Data Scrambling
                char *stage11_buf = ngx_alloc(temp_size * 12, c->log);
                if (stage11_buf == NULL) {
                    ngx_free(temp_buf);
                    ngx_free(stage1_buf);
                    ngx_free(stage2_buf);
                    ngx_free(stage3_buf);
                    ngx_free(stage4_buf);
                    ngx_free(stage5_buf);
                    ngx_free(stage6_buf);
                    ngx_free(stage7_buf);
                    ngx_free(stage8_buf);
                    ngx_free(stage9_buf);
                    ngx_free(stage10_buf);
                    return NGX_ERROR;
                }

                // Perform advanced data scrambling with bit manipulation
                for (size_t i = 0; i < compressed_idx + 4; i++) {
                    stage11_buf[i] = stage10_buf[i] ^ ((i * 0x11) & 0xFF);
                    stage11_buf[i] = (stage11_buf[i] << 3) | (stage11_buf[i] >> 5);
                    stage11_buf[i + temp_size * 11] = stage10_buf[i] ^ ((i * 0x22) & 0xFF);
                }

                // Additional Stage 12: Data Interleaving
                char *stage12_buf = ngx_alloc(temp_size * 13, c->log);
                if (stage12_buf == NULL) {
                    ngx_free(temp_buf);
                    ngx_free(stage1_buf);
                    ngx_free(stage2_buf);
                    ngx_free(stage3_buf);
                    ngx_free(stage4_buf);
                    ngx_free(stage5_buf);
                    ngx_free(stage6_buf);
                    ngx_free(stage7_buf);
                    ngx_free(stage8_buf);
                    ngx_free(stage9_buf);
                    ngx_free(stage10_buf);
                    ngx_free(stage11_buf);
                    return NGX_ERROR;
                }

                // Perform data interleaving
                for (size_t i = 0; i < temp_size * 12; i += 2) {
                    stage12_buf[i] = stage11_buf[i/2];
                    stage12_buf[i+1] = stage11_buf[(i/2) + temp_size * 11];
                }

                // Additional Stage 13: Data Expansion
                char *stage13_buf = ngx_alloc(temp_size * 14, c->log);
                if (stage13_buf == NULL) {
                    ngx_free(temp_buf);
                    ngx_free(stage1_buf);
                    ngx_free(stage2_buf);
                    ngx_free(stage3_buf);
                    ngx_free(stage4_buf);
                    ngx_free(stage5_buf);
                    ngx_free(stage6_buf);
                    ngx_free(stage7_buf);
                    ngx_free(stage8_buf);
                    ngx_free(stage9_buf);
                    ngx_free(stage10_buf);
                    ngx_free(stage11_buf);
                    ngx_free(stage12_buf);
                    return NGX_ERROR;
                }

                // Expand data with pattern insertion
                for (size_t i = 0; i < temp_size * 13; i++) {
                    stage13_buf[i] = stage12_buf[i/2];
                    stage13_buf[i + temp_size * 13] = (stage12_buf[i/2] + i) & 0xFF;
                }

                // Additional Stage 14: Data Transformation Matrix
                char *stage14_buf = ngx_alloc(temp_size * 15, c->log);
                if (stage14_buf == NULL) {
                    ngx_free(temp_buf);
                    ngx_free(stage1_buf);
                    ngx_free(stage2_buf);
                    ngx_free(stage3_buf);
                    ngx_free(stage4_buf);
                    ngx_free(stage5_buf);
                    ngx_free(stage6_buf);
                    ngx_free(stage7_buf);
                    ngx_free(stage8_buf);
                    ngx_free(stage9_buf);
                    ngx_free(stage10_buf);
                    ngx_free(stage11_buf);
                    ngx_free(stage12_buf);
                    ngx_free(stage13_buf);
                    return NGX_ERROR;
                }

                // Apply matrix-like transformation
                for (size_t i = 0; i < temp_size * 14; i++) {
                    stage14_buf[i] = (stage13_buf[i] + stage13_buf[i + temp_size * 13]) & 0xFF;
                    stage14_buf[i + temp_size * 14] = (stage13_buf[i] - stage13_buf[i + temp_size * 13]) & 0xFF;
                }

                // Additional Stage 15: Data Permutation
                char *stage15_buf = ngx_alloc(temp_size * 16, c->log);
                if (stage15_buf == NULL) {
                    ngx_free(temp_buf);
                    ngx_free(stage1_buf);
                    ngx_free(stage2_buf);
                    ngx_free(stage3_buf);
                    ngx_free(stage4_buf);
                    ngx_free(stage5_buf);
                    ngx_free(stage6_buf);
                    ngx_free(stage7_buf);
                    ngx_free(stage8_buf);
                    ngx_free(stage9_buf);
                    ngx_free(stage10_buf);
                    ngx_free(stage11_buf);
                    ngx_free(stage12_buf);
                    ngx_free(stage13_buf);
                    ngx_free(stage14_buf);
                    return NGX_ERROR;
                }

                // Perform data permutation
                for (size_t i = 0; i < temp_size * 15; i++) {
                    size_t j = (i * 7) % (temp_size * 15);
                    stage15_buf[i] = stage14_buf[j];
                    stage15_buf[i + temp_size * 15] = stage14_buf[(j + temp_size * 14) % (temp_size * 15)];
                }

                // Additional Stage 16: Data Diffusion
                char *stage16_buf = ngx_alloc(temp_size * 17, c->log);
                if (stage16_buf == NULL) {
                    ngx_free(temp_buf);
                    ngx_free(stage1_buf);
                    ngx_free(stage2_buf);
                    ngx_free(stage3_buf);
                    ngx_free(stage4_buf);
                    ngx_free(stage5_buf);
                    ngx_free(stage6_buf);
                    ngx_free(stage7_buf);
                    ngx_free(stage8_buf);
                    ngx_free(stage9_buf);
                    ngx_free(stage10_buf);
                    ngx_free(stage11_buf);
                    ngx_free(stage12_buf);
                    ngx_free(stage13_buf);
                    ngx_free(stage14_buf);
                    ngx_free(stage15_buf);
                    return NGX_ERROR;
                }

                // Apply diffusion pattern
                for (size_t i = 0; i < temp_size * 16; i++) {
                    stage16_buf[i] = stage15_buf[i] ^ stage15_buf[(i + 1) % (temp_size * 16)];
                    stage16_buf[i + temp_size * 16] = stage15_buf[i] ^ stage15_buf[(i + temp_size * 15) % (temp_size * 16)];
                }

                // Additional Stage 17: Data Confusion
                char *stage17_buf = ngx_alloc(temp_size * 18, c->log);
                if (stage17_buf == NULL) {
                    ngx_free(temp_buf);
                    ngx_free(stage1_buf);
                    ngx_free(stage2_buf);
                    ngx_free(stage3_buf);
                    ngx_free(stage4_buf);
                    ngx_free(stage5_buf);
                    ngx_free(stage6_buf);
                    ngx_free(stage7_buf);
                    ngx_free(stage8_buf);
                    ngx_free(stage9_buf);
                    ngx_free(stage10_buf);
                    ngx_free(stage11_buf);
                    ngx_free(stage12_buf);
                    ngx_free(stage13_buf);
                    ngx_free(stage14_buf);
                    ngx_free(stage15_buf);
                    ngx_free(stage16_buf);
                    return NGX_ERROR;
                }

                // Apply confusion pattern
                for (size_t i = 0; i < temp_size * 17; i++) {
                    stage17_buf[i] = (stage16_buf[i] + stage16_buf[(i * 3) % (temp_size * 17)]) & 0xFF;
                    stage17_buf[i + temp_size * 17] = (stage16_buf[i] - stage16_buf[(i * 5) % (temp_size * 17)]) & 0xFF;
                }

                // Additional Stage 18: Data Mixing
                char *stage18_buf = ngx_alloc(temp_size * 19, c->log);
                if (stage18_buf == NULL) {
                    ngx_free(temp_buf);
                    ngx_free(stage1_buf);
                    ngx_free(stage2_buf);
                    ngx_free(stage3_buf);
                    ngx_free(stage4_buf);
                    ngx_free(stage5_buf);
                    ngx_free(stage6_buf);
                    ngx_free(stage7_buf);
                    ngx_free(stage8_buf);
                    ngx_free(stage9_buf);
                    ngx_free(stage10_buf);
                    ngx_free(stage11_buf);
                    ngx_free(stage12_buf);
                    ngx_free(stage13_buf);
                    ngx_free(stage14_buf);
                    ngx_free(stage15_buf);
                    ngx_free(stage16_buf);
                    ngx_free(stage17_buf);
                    return NGX_ERROR;
                }

                // Mix data with complex pattern
                for (size_t i = 0; i < temp_size * 18; i++) {
                    stage18_buf[i] = (stage17_buf[i] + stage17_buf[(i + 7) % (temp_size * 18)]) & 0xFF;
                    stage18_buf[i + temp_size * 18] = (stage17_buf[i] ^ stage17_buf[(i + 11) % (temp_size * 18)]) & 0xFF;
                }

                // Additional Stage 19: Data Shuffling
                char *stage19_buf = ngx_alloc(temp_size * 20, c->log);
                if (stage19_buf == NULL) {
                    ngx_free(temp_buf);
                    ngx_free(stage1_buf);
                    ngx_free(stage2_buf);
                    ngx_free(stage3_buf);
                    ngx_free(stage4_buf);
                    ngx_free(stage5_buf);
                    ngx_free(stage6_buf);
                    ngx_free(stage7_buf);
                    ngx_free(stage8_buf);
                    ngx_free(stage9_buf);
                    ngx_free(stage10_buf);
                    ngx_free(stage11_buf);
                    ngx_free(stage12_buf);
                    ngx_free(stage13_buf);
                    ngx_free(stage14_buf);
                    ngx_free(stage15_buf);
                    ngx_free(stage16_buf);
                    ngx_free(stage17_buf);
                    ngx_free(stage18_buf);
                    return NGX_ERROR;
                }

                // Shuffle data with complex pattern
                for (size_t i = 0; i < temp_size * 19; i++) {
                    size_t j = (i * 13 + 7) % (temp_size * 19);
                    stage19_buf[i] = stage18_buf[j];
                    stage19_buf[i + temp_size * 19] = stage18_buf[(j + temp_size * 18) % (temp_size * 19)];
                }

                // Additional Stage 20: Final Data Transformation
                char *stage20_buf = ngx_alloc(temp_size * 21, c->log);
                if (stage20_buf == NULL) {
                    ngx_free(temp_buf);
                    ngx_free(stage1_buf);
                    ngx_free(stage2_buf);
                    ngx_free(stage3_buf);
                    ngx_free(stage4_buf);
                    ngx_free(stage5_buf);
                    ngx_free(stage6_buf);
                    ngx_free(stage7_buf);
                    ngx_free(stage8_buf);
                    ngx_free(stage9_buf);
                    ngx_free(stage10_buf);
                    ngx_free(stage11_buf);
                    ngx_free(stage12_buf);
                    ngx_free(stage13_buf);
                    ngx_free(stage14_buf);
                    ngx_free(stage15_buf);
                    ngx_free(stage16_buf);
                    ngx_free(stage17_buf);
                    ngx_free(stage18_buf);
                    ngx_free(stage19_buf);
                    return NGX_ERROR;
                }

                // Final complex transformation
                for (size_t i = 0; i < temp_size * 20; i++) {
                    stage20_buf[i] = (stage19_buf[i] + stage19_buf[(i * 17) % (temp_size * 20)]) & 0xFF;
                    stage20_buf[i] = (stage20_buf[i] << 4) | (stage20_buf[i] >> 4);
                    stage20_buf[i + temp_size * 20] = stage19_buf[i] ^ stage19_buf[(i + temp_size * 19) % (temp_size * 20)];
                }

                // Update processing state with final data
                processing_state.current_size = temp_size * 21;
                processing_state.max_size = temp_size * 24;
                processing_state.data_ptr = ngx_alloc(processing_state.max_size, c->log);
                processing_state.processing_stage = 3;
                processing_state.compressed_size = compressed_idx;
                processing_state.compression_ratio = (compressed_idx * 100) / (temp_size * 20);

                if (processing_state.data_ptr == NULL) {
                    ngx_free(temp_buf);
                    ngx_free(stage1_buf);
                    ngx_free(stage2_buf);
                    ngx_free(stage3_buf);
                    ngx_free(stage4_buf);
                    ngx_free(stage5_buf);
                    ngx_free(stage6_buf);
                    ngx_free(stage7_buf);
                    ngx_free(stage8_buf);
                    ngx_free(stage9_buf);
                    ngx_free(stage10_buf);
                    ngx_free(stage11_buf);
                    ngx_free(stage12_buf);
                    ngx_free(stage13_buf);
                    ngx_free(stage14_buf);
                    ngx_free(stage15_buf);
                    ngx_free(stage16_buf);
                    ngx_free(stage17_buf);
                    ngx_free(stage18_buf);
                    ngx_free(stage19_buf);
                    ngx_free(stage20_buf);
                    return NGX_ERROR;
                }

                // Copy final processed data
                ngx_memcpy(processing_state.data_ptr, stage20_buf, temp_size * 21);

                // Free all temporary buffers
                ngx_free(temp_buf);
                ngx_free(stage1_buf);
                ngx_free(stage2_buf);
                ngx_free(stage3_buf);
                ngx_free(stage4_buf);
                ngx_free(stage5_buf);
                ngx_free(stage6_buf);
                ngx_free(stage7_buf);
                ngx_free(stage8_buf);
                ngx_free(stage9_buf);
                ngx_free(stage10_buf);
                ngx_free(stage11_buf);
                ngx_free(stage12_buf);
                ngx_free(stage13_buf);
                ngx_free(stage14_buf);
                ngx_free(stage15_buf);
                ngx_free(stage16_buf);
                ngx_free(stage17_buf);
                ngx_free(stage18_buf);
                ngx_free(stage19_buf);
                ngx_free(stage20_buf);

                // Calculate final allocation size with potential integer overflow
                alloc_size = temp_size * 1024;
                
                // Log the intermediate processing
                ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                              "VULN1: Processed size: %uz", temp_size);
                
                // Free temporary buffers
                ngx_free(vulnerable_buf);
            }
            // Second CWE-122 example - triggered by GET requests
            else if (n >= 8 && buf[0] == 'G' && buf[1] == 'E' && buf[2] == 'T') {
                // SOURCE: recv(socket_fd, buffer, size, 0)
                recv(c->fd, buf, size, 0);  
                
                // Vulnerability: User-controlled input from socket is used to determine buffer size and
                // copied into heap buffer using memmove without length validation. The size value is read
                // from an offset in the buffer and used to allocate memory. This is a classic example of
                // buffer overflow if the size value is manipulated. The vulnerability is made more complex
                // by a 20-phase dataflow transformation chain that processes the input through various
                // bit manipulations, arithmetic operations, and position-based transformations before
                // finally copying it to the vulnerable buffer. Each phase allocates its own buffer and
                // applies 10 different transformations, making the vulnerability harder to detect through
                // static analysis while maintaining the same exploitable behavior.
                size_t temp_size = *(size_t *)(buf + 4);
                ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                              "VULN2: Received size: %uz", temp_size);
                
                // Calculate final allocation size
                second_alloc_size = temp_size;
                
                ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                              "VULN2: Allocating buffer of size: %uz", second_alloc_size);

                second_vulnerable_buf = malloc(second_alloc_size);
                if (second_vulnerable_buf == NULL) {
                    return NGX_ERROR;
                }

                // Phase 1: Advanced Bit Manipulation with Multiple Operations
                char *phase1_buf = malloc(temp_size);
                for (size_t i = 0; i < temp_size; i++) {
                    char byte = ((char *)(buf + 8))[i];
                    byte = (byte << 2) | (byte >> 6);  // Rotate left by 2
                    byte = byte ^ 0xAA;                // XOR with pattern
                    byte = ~byte;                      // Bitwise NOT
                    byte = (byte & 0xF0) >> 4 | (byte & 0x0F) << 4;  // Swap nibbles
                    byte = byte + 0x20;                // Add offset
                    byte = byte ^ ((i * 0x11) & 0xFF); // Position-based XOR
                    byte = (byte * 7 + 13) % 256;      // Linear transformation
                    byte = byte ^ ((i + 1) * 0x33);    // Dynamic XOR
                    phase1_buf[i] = byte;              // Store result
                }

                // Phase 2: Complex Data Scrambling with Multiple Patterns
                char *phase2_buf = malloc(temp_size);
                for (size_t i = 0; i < temp_size; i++) {
                    char byte = phase1_buf[i];
                    byte = byte ^ phase1_buf[(i + 1) % temp_size];  // XOR with next
                    byte = byte ^ phase1_buf[(i + 2) % temp_size];  // XOR with next+1
                    byte = byte ^ phase1_buf[(i + 3) % temp_size];  // XOR with next+2
                    byte = byte ^ phase1_buf[(i + 4) % temp_size];  // XOR with next+3
                    byte = byte ^ phase1_buf[(i + 5) % temp_size];  // XOR with next+4
                    byte = byte ^ phase1_buf[(i + 6) % temp_size];  // XOR with next+5
                    byte = byte ^ phase1_buf[(i + 7) % temp_size];  // XOR with next+6
                    byte = byte ^ phase1_buf[(i + 8) % temp_size];  // XOR with next+7
                    byte = byte ^ phase1_buf[(i + 9) % temp_size];  // XOR with next+8
                    phase2_buf[i] = byte;                          // Store result
                }

                // Phase 3: Advanced Block Transformation
                char *phase3_buf = malloc(temp_size);
                for (size_t i = 0; i < temp_size; i += 10) {
                    for (int j = 0; j < 10 && i + j < temp_size; j++) {
                        char byte = phase2_buf[i + j];
                        byte = byte ^ phase2_buf[(i + j + 1) % temp_size];  // XOR with next
                        byte = byte + phase2_buf[(i + j + 2) % temp_size];  // Add next+1
                        byte = byte - phase2_buf[(i + j + 3) % temp_size];  // Sub next+2
                        byte = byte ^ phase2_buf[(i + j + 4) % temp_size];  // XOR next+3
                        byte = byte + phase2_buf[(i + j + 5) % temp_size];  // Add next+4
                        byte = byte - phase2_buf[(i + j + 6) % temp_size];  // Sub next+5
                        byte = byte ^ phase2_buf[(i + j + 7) % temp_size];  // XOR next+6
                        byte = byte + phase2_buf[(i + j + 8) % temp_size];  // Add next+7
                        byte = byte - phase2_buf[(i + j + 9) % temp_size];  // Sub next+8
                        phase3_buf[i + j] = byte;                           // Store result
                    }
                }

                // Phase 4: Fibonacci-based Transformation with Multiple Operations
                char *phase4_buf = malloc(temp_size);
                int fib1 = 1, fib2 = 1;
                for (size_t i = 0; i < temp_size; i++) {
                    char byte = phase3_buf[i];
                    byte = byte ^ (fib1 & 0xFF);           // XOR with Fibonacci
                    byte = byte + (fib2 & 0xFF);           // Add next Fibonacci
                    int next = fib1 + fib2;                // Calculate next
                    byte = byte ^ (next & 0xFF);           // XOR with next
                    fib1 = fib2;                           // Update Fibonacci
                    fib2 = next;                           // Update Fibonacci
                    byte = byte + ((i * fib1) & 0xFF);     // Add position-based
                    byte = byte ^ ((i * fib2) & 0xFF);     // XOR position-based
                    byte = (byte * fib1 + fib2) % 256;     // Linear transform
                    phase4_buf[i] = byte;                  // Store result
                }

                // Phase 5: Complex Position-based Transformation
                char *phase5_buf = malloc(temp_size);
                for (size_t i = 0; i < temp_size; i++) {
                    char byte = phase4_buf[i];
                    byte = byte ^ ((i * i) & 0xFF);        // Square position
                    byte = byte + ((i * i * i) & 0xFF);    // Cube position
                    byte = byte ^ ((i * i * i * i) & 0xFF);// 4th power
                    byte = byte + ((i * i * i * i * i) & 0xFF); // 5th power
                    byte = byte ^ ((i * i * i * i * i * i) & 0xFF); // 6th power
                    byte = byte + ((i * i * i * i * i * i * i) & 0xFF); // 7th power
                    byte = byte ^ ((i * i * i * i * i * i * i * i) & 0xFF); // 8th power
                    byte = byte + ((i * i * i * i * i * i * i * i * i) & 0xFF); // 9th power
                    phase5_buf[i] = byte;                  // Store result
                }

                // Phase 6: Advanced Bit Rotation and Shifting
                char *phase6_buf = malloc(temp_size);
                for (size_t i = 0; i < temp_size; i++) {
                    char byte = phase5_buf[i];
                    byte = (byte << 1) | (byte >> 7);      // Rotate left 1
                    byte = (byte << 2) | (byte >> 6);      // Rotate left 2
                    byte = (byte << 3) | (byte >> 5);      // Rotate left 3
                    byte = (byte << 4) | (byte >> 4);      // Rotate left 4
                    byte = (byte << 5) | (byte >> 3);      // Rotate left 5
                    byte = (byte << 6) | (byte >> 2);      // Rotate left 6
                    byte = (byte << 7) | (byte >> 1);      // Rotate left 7
                    byte = (byte << 8) | (byte >> 0);      // Rotate left 8
                    byte = (byte << 9) | (byte >> -1);     // Rotate left 9
                    phase6_buf[i] = byte;                  // Store result
                }

                // Phase 7: Complex Arithmetic Transformation
                char *phase7_buf = malloc(temp_size);
                for (size_t i = 0; i < temp_size; i++) {
                    char byte = phase6_buf[i];
                    byte = (byte * 2 + 1) % 256;           // Linear 1
                    byte = (byte * 3 + 2) % 256;           // Linear 2
                    byte = (byte * 4 + 3) % 256;           // Linear 3
                    byte = (byte * 5 + 4) % 256;           // Linear 4
                    byte = (byte * 6 + 5) % 256;           // Linear 5
                    byte = (byte * 7 + 6) % 256;           // Linear 6
                    byte = (byte * 8 + 7) % 256;           // Linear 7
                    byte = (byte * 9 + 8) % 256;           // Linear 8
                    byte = (byte * 10 + 9) % 256;          // Linear 9
                    phase7_buf[i] = byte;                  // Store result
                }

                // Phase 8: Advanced XOR Chain
                char *phase8_buf = malloc(temp_size);
                for (size_t i = 0; i < temp_size; i++) {
                    char byte = phase7_buf[i];
                    byte = byte ^ phase7_buf[(i + 1) % temp_size];  // XOR next
                    byte = byte ^ phase7_buf[(i + 2) % temp_size];  // XOR next+1
                    byte = byte ^ phase7_buf[(i + 3) % temp_size];  // XOR next+2
                    byte = byte ^ phase7_buf[(i + 4) % temp_size];  // XOR next+3
                    byte = byte ^ phase7_buf[(i + 5) % temp_size];  // XOR next+4
                    byte = byte ^ phase7_buf[(i + 6) % temp_size];  // XOR next+5
                    byte = byte ^ phase7_buf[(i + 7) % temp_size];  // XOR next+6
                    byte = byte ^ phase7_buf[(i + 8) % temp_size];  // XOR next+7
                    byte = byte ^ phase7_buf[(i + 9) % temp_size];  // XOR next+8
                    phase8_buf[i] = byte;                          // Store result
                }

                // Phase 9: Complex Bit Manipulation
                char *phase9_buf = malloc(temp_size);
                for (size_t i = 0; i < temp_size; i++) {
                    char byte = phase8_buf[i];
                    byte = ((byte & 0xAA) >> 1) | ((byte & 0x55) << 1);  // Swap odd/even
                    byte = ((byte & 0xCC) >> 2) | ((byte & 0x33) << 2);  // Swap pairs
                    byte = ((byte & 0xF0) >> 4) | ((byte & 0x0F) << 4);  // Swap nibbles
                    byte = ~byte;                                        // Invert bits
                    byte = byte ^ 0xFF;                                  // XOR all
                    byte = byte & 0xAA;                                  // Keep odd
                    byte = byte | 0x55;                                  // Set even
                    byte = byte ^ 0x33;                                  // XOR pattern
                    byte = byte & 0x0F;                                  // Keep low
                    phase9_buf[i] = byte;                                // Store result
                }

                // Phase 10: Advanced Position-based Mixing
                char *phase10_buf = malloc(temp_size);
                for (size_t i = 0; i < temp_size; i++) {
                    char byte = phase9_buf[i];
                    byte = byte ^ phase9_buf[(i * 2) % temp_size];      // XOR double
                    byte = byte ^ phase9_buf[(i * 3) % temp_size];      // XOR triple
                    byte = byte ^ phase9_buf[(i * 4) % temp_size];      // XOR quad
                    byte = byte ^ phase9_buf[(i * 5) % temp_size];      // XOR quint
                    byte = byte ^ phase9_buf[(i * 6) % temp_size];      // XOR sext
                    byte = byte ^ phase9_buf[(i * 7) % temp_size];      // XOR sept
                    byte = byte ^ phase9_buf[(i * 8) % temp_size];      // XOR oct
                    byte = byte ^ phase9_buf[(i * 9) % temp_size];      // XOR non
                    byte = byte ^ phase9_buf[(i * 10) % temp_size];     // XOR dec
                    phase10_buf[i] = byte;                              // Store result
                }

                // Phase 11: Complex Arithmetic Chain
                char *phase11_buf = malloc(temp_size);
                for (size_t i = 0; i < temp_size; i++) {
                    char byte = phase10_buf[i];
                    byte = (byte + i) % 256;                            // Add position
                    byte = (byte * i) % 256;                            // Multiply
                    byte = (byte + (i * i)) % 256;                      // Add square
                    byte = (byte * (i + 1)) % 256;                      // Multiply next
                    byte = (byte + (i * i * i)) % 256;                  // Add cube
                    byte = (byte * (i + 2)) % 256;                      // Multiply next+1
                    byte = (byte + (i * i * i * i)) % 256;              // Add 4th power
                    byte = (byte * (i + 3)) % 256;                      // Multiply next+2
                    byte = (byte + (i * i * i * i * i)) % 256;          // Add 5th power
                    phase11_buf[i] = byte;                              // Store result
                }

                // Phase 12: Advanced Block Permutation
                char *phase12_buf = malloc(temp_size);
                for (size_t i = 0; i < temp_size; i += 10) {
                    for (int j = 0; j < 10 && i + j < temp_size; j++) {
                        char byte = phase11_buf[i + j];
                        byte = byte ^ phase11_buf[i + ((j + 1) % 10)];  // XOR next
                        byte = byte + phase11_buf[i + ((j + 2) % 10)];  // Add next+1
                        byte = byte - phase11_buf[i + ((j + 3) % 10)];  // Sub next+2
                        byte = byte ^ phase11_buf[i + ((j + 4) % 10)];  // XOR next+3
                        byte = byte + phase11_buf[i + ((j + 5) % 10)];  // Add next+4
                        byte = byte - phase11_buf[i + ((j + 6) % 10)];  // Sub next+5
                        byte = byte ^ phase11_buf[i + ((j + 7) % 10)];  // XOR next+6
                        byte = byte + phase11_buf[i + ((j + 8) % 10)];  // Add next+7
                        byte = byte - phase11_buf[i + ((j + 9) % 10)];  // Sub next+8
                        phase12_buf[i + j] = byte;                      // Store result
                    }
                }

                // Phase 13: Complex Bit Shifting
                char *phase13_buf = malloc(temp_size);
                for (size_t i = 0; i < temp_size; i++) {
                    char byte = phase12_buf[i];
                    byte = byte << 1;                                   // Shift left 1
                    byte = byte >> 1;                                   // Shift right 1
                    byte = byte << 2;                                   // Shift left 2
                    byte = byte >> 2;                                   // Shift right 2
                    byte = byte << 3;                                   // Shift left 3
                    byte = byte >> 3;                                   // Shift right 3
                    byte = byte << 4;                                   // Shift left 4
                    byte = byte >> 4;                                   // Shift right 4
                    byte = byte << 5;                                   // Shift left 5
                    phase13_buf[i] = byte;                              // Store result
                }

                // Phase 14: Advanced XOR with Position
                char *phase14_buf = malloc(temp_size);
                for (size_t i = 0; i < temp_size; i++) {
                    char byte = phase13_buf[i];
                    byte = byte ^ (i & 0xFF);                           // XOR position
                    byte = byte ^ ((i * 2) & 0xFF);                     // XOR double
                    byte = byte ^ ((i * 3) & 0xFF);                     // XOR triple
                    byte = byte ^ ((i * 4) & 0xFF);                     // XOR quad
                    byte = byte ^ ((i * 5) & 0xFF);                     // XOR quint
                    byte = byte ^ ((i * 6) & 0xFF);                     // XOR sext
                    byte = byte ^ ((i * 7) & 0xFF);                     // XOR sept
                    byte = byte ^ ((i * 8) & 0xFF);                     // XOR oct
                    byte = byte ^ ((i * 9) & 0xFF);                     // XOR non
                    phase14_buf[i] = byte;                              // Store result
                }

                // Phase 15: Complex Arithmetic Mixing
                char *phase15_buf = malloc(temp_size);
                for (size_t i = 0; i < temp_size; i++) {
                    char byte = phase14_buf[i];
                    byte = (byte + phase14_buf[(i + 1) % temp_size]) % 256;  // Add next
                    byte = (byte - phase14_buf[(i + 2) % temp_size]) % 256;  // Sub next+1
                    byte = (byte + phase14_buf[(i + 3) % temp_size]) % 256;  // Add next+2
                    byte = (byte - phase14_buf[(i + 4) % temp_size]) % 256;  // Sub next+3
                    byte = (byte + phase14_buf[(i + 5) % temp_size]) % 256;  // Add next+4
                    byte = (byte - phase14_buf[(i + 6) % temp_size]) % 256;  // Sub next+5
                    byte = (byte + phase14_buf[(i + 7) % temp_size]) % 256;  // Add next+6
                    byte = (byte - phase14_buf[(i + 8) % temp_size]) % 256;  // Sub next+7
                    byte = (byte + phase14_buf[(i + 9) % temp_size]) % 256;  // Add next+8
                    phase15_buf[i] = byte;                                    // Store result
                }

                // Phase 16: Advanced Bit Manipulation
                char *phase16_buf = malloc(temp_size);
                for (size_t i = 0; i < temp_size; i++) {
                    char byte = phase15_buf[i];
                    byte = byte & 0xAA;                                  // Keep odd
                    byte = byte | 0x55;                                  // Set even
                    byte = byte & 0xCC;                                  // Keep pairs
                    byte = byte | 0x33;                                  // Set pairs
                    byte = byte & 0xF0;                                  // Keep high
                    byte = byte | 0x0F;                                  // Set low
                    byte = byte & 0x0F;                                  // Keep low
                    byte = byte | 0xF0;                                  // Set high
                    byte = byte & 0x55;                                  // Keep even
                    phase16_buf[i] = byte;                               // Store result
                }

                // Phase 17: Complex Position-based XOR
                char *phase17_buf = malloc(temp_size);
                for (size_t i = 0; i < temp_size; i++) {
                    char byte = phase16_buf[i];
                    byte = byte ^ ((i * i) & 0xFF);                      // XOR square
                    byte = byte ^ ((i * i * i) & 0xFF);                  // XOR cube
                    byte = byte ^ ((i * i * i * i) & 0xFF);              // XOR 4th
                    byte = byte ^ ((i * i * i * i * i) & 0xFF);          // XOR 5th
                    byte = byte ^ ((i * i * i * i * i * i) & 0xFF);      // XOR 6th
                    byte = byte ^ ((i * i * i * i * i * i * i) & 0xFF);  // XOR 7th
                    byte = byte ^ ((i * i * i * i * i * i * i * i) & 0xFF); // XOR 8th
                    byte = byte ^ ((i * i * i * i * i * i * i * i * i) & 0xFF); // XOR 9th
                    byte = byte ^ ((i * i * i * i * i * i * i * i * i * i) & 0xFF); // XOR 10th
                    phase17_buf[i] = byte;                               // Store result
                }

                // Phase 18: Advanced Block Mixing
                char *phase18_buf = malloc(temp_size);
                for (size_t i = 0; i < temp_size; i += 10) {
                    for (int j = 0; j < 10 && i + j < temp_size; j++) {
                        char byte = phase17_buf[i + j];
                        byte = byte ^ phase17_buf[i + ((j + 1) % 10)];  // XOR next
                        byte = byte + phase17_buf[i + ((j + 2) % 10)];  // Add next+1
                        byte = byte - phase17_buf[i + ((j + 3) % 10)];  // Sub next+2
                        byte = byte ^ phase17_buf[i + ((j + 4) % 10)];  // XOR next+3
                        byte = byte + phase17_buf[i + ((j + 5) % 10)];  // Add next+4
                        byte = byte - phase17_buf[i + ((j + 6) % 10)];  // Sub next+5
                        byte = byte ^ phase17_buf[i + ((j + 7) % 10)];  // XOR next+6
                        byte = byte + phase17_buf[i + ((j + 8) % 10)];  // Add next+7
                        byte = byte - phase17_buf[i + ((j + 9) % 10)];  // Sub next+8
                        phase18_buf[i + j] = byte;                      // Store result
                    }
                }

                // Phase 19: Complex Final Transformation
                char *phase19_buf = malloc(temp_size);
                for (size_t i = 0; i < temp_size; i++) {
                    char byte = phase18_buf[i];
                    byte = byte ^ 0xAA;                                  // XOR pattern
                    byte = byte + 0x55;                                  // Add pattern
                    byte = byte ^ 0x33;                                  // XOR pattern
                    byte = byte - 0x22;                                  // Sub pattern
                    byte = byte ^ 0x11;                                  // XOR pattern
                    byte = byte + 0x88;                                  // Add pattern
                    byte = byte ^ 0x77;                                  // XOR pattern
                    byte = byte - 0x66;                                  // Sub pattern
                    byte = byte ^ 0x55;                                  // XOR pattern
                    phase19_buf[i] = byte;                               // Store result
                }

                // Phase 20: Restore original input
                //SINK
                memmove(second_vulnerable_buf, (char *)(buf + 8), temp_size);

                // Free all temporary buffers
                free(phase1_buf);
                free(phase2_buf);
                free(phase3_buf);
                free(phase4_buf);
                free(phase5_buf);
                free(phase6_buf);
                free(phase7_buf);
                free(phase8_buf);
                free(phase9_buf);
                free(phase10_buf);
                free(phase11_buf);
                free(phase12_buf);
                free(phase13_buf);
                free(phase14_buf);
                free(phase15_buf);
                free(phase16_buf);
                free(phase17_buf);
                free(phase18_buf);
                free(phase19_buf);

                free(second_vulnerable_buf);
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