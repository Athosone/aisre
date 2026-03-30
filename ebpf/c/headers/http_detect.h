#ifndef __HTTP_DETECT_H__
#define __HTTP_DETECT_H__

// Check if buffer starts with an HTTP method or response signature.
// Returns 1 if HTTP detected, 0 otherwise.
static __always_inline int is_http(const __u8 *buf, __u32 len) {
    if (len < 4)
        return 0;

    // HTTP response: "HTTP/"
    if (buf[0] == 'H' && buf[1] == 'T' && buf[2] == 'T' && buf[3] == 'P')
        return 1;

    // GET
    if (buf[0] == 'G' && buf[1] == 'E' && buf[2] == 'T' && buf[3] == ' ')
        return 1;

    // PUT
    if (buf[0] == 'P' && buf[1] == 'U' && buf[2] == 'T' && buf[3] == ' ')
        return 1;

    if (len < 5)
        return 0;

    // POST
    if (buf[0] == 'P' && buf[1] == 'O' && buf[2] == 'S' && buf[3] == 'T' && buf[4] == ' ')
        return 1;

    // HEAD
    if (buf[0] == 'H' && buf[1] == 'E' && buf[2] == 'A' && buf[3] == 'D' && buf[4] == ' ')
        return 1;

    if (len < 6)
        return 0;

    // PATCH
    if (buf[0] == 'P' && buf[1] == 'A' && buf[2] == 'T' && buf[3] == 'C' && buf[4] == 'H' && buf[5] == ' ')
        return 1;

    if (len < 7)
        return 0;

    // DELETE
    if (buf[0] == 'D' && buf[1] == 'E' && buf[2] == 'L' && buf[3] == 'E' && buf[4] == 'T' && buf[5] == 'E' && buf[6] == ' ')
        return 1;

    if (len < 8)
        return 0;

    // OPTIONS
    if (buf[0] == 'O' && buf[1] == 'P' && buf[2] == 'T' && buf[3] == 'I' &&
        buf[4] == 'O' && buf[5] == 'N' && buf[6] == 'S' && buf[7] == ' ')
        return 1;

    // CONNECT
    if (buf[0] == 'C' && buf[1] == 'O' && buf[2] == 'N' && buf[3] == 'N' &&
        buf[4] == 'E' && buf[5] == 'C' && buf[6] == 'T' && buf[7] == ' ')
        return 1;

    return 0;
}

#endif /* __HTTP_DETECT_H__ */
