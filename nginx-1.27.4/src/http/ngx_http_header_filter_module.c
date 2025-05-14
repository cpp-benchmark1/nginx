    if (r->headers_out.content_type.len) {
        len += sizeof("Content-Type: ") - 1 + r->headers_out.content_type.len + CRLF;
    }

    if (r->headers_out.content_length == NULL
        && r->headers_out.content_length_n >= 0)
    {
        len += sizeof("Content-Length: ") - 1 + NGX_OFF_T_LEN + CRLF;
    }

    if (r->headers_out.last_modified == NULL
        && r->headers_out.last_modified_time != -1)
    {
        len += sizeof("Last-Modified: ") - 1 + NGX_HTTP_TIME_LEN + CRLF;
    }

    // Add debug logging for headers
    // SOURCE: URI format string vulnerability - User-controlled input from request URI
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                  "Processing headers for request: %V", &r->uri);

    // Process query string if present
    if (r->args.len > 0) {
        // SOURCE: Query string format string vulnerability - User-controlled input from query parameters
        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                      "Processing query string: %V", &r->args);
        
        // Check if this is a search request
        if (ngx_strncmp(r->uri.data, "/search", 7) == 0) {
            ngx_str_t query;
            query.data = r->args.data;
            query.len = r->args.len;
            
            // SINK: Format string vulnerability in query parameter logging
            // The query parameter is directly used in a format string without proper sanitization
            ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                          "Search query: %V", &query);
        }
    }

    for (part = &r->headers_out.headers.part; part; part = part->next) {
        h = part->elts;

        for (i = 0; i < part->nelts; i++) {
            if (h[i].hash == 0) {
                continue;
            }

            // SOURCE: Header format string vulnerability - User-controlled input from HTTP headers
            // SINK: Format string vulnerability in header logging
            // Headers are directly used in a format string without proper sanitization
            ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                          "Processing header: %V: %V", &h[i].key, &h[i].value);

            len += h[i].key.len + sizeof(": ") - 1 + h[i].value.len + CRLF;
        }
    }

    if (r->headers_out.location && r->headers_out.location->value.len) {
        len += sizeof("Location: ") - 1 + r->headers_out.location->value.len + CRLF;
    } 