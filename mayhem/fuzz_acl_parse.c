/* ACL text parsers: "a.b.c.d/len", "any", and list names, plus the formatter. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "acl.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 2) return -1;
    uint8_t sel = data[0], blen = data[1];
    data += 2; size -= 2;

    char *str = malloc(size + 1);
    memcpy(str, data, size);
    str[size] = '\0';

    if (sel & 1) {
        acl_parse_name(str);
    } else {
        uint32_t ip = 0, mask = 0;
        if (acl_parse_ip(str, &ip, &mask)) {
            size_t n = 1 + blen % 40;
            char *out = malloc(n);
            acl_format_ip(ip, mask, out, n);
            if (strlen(out) >= n) abort();
            free(out);
        }
    }
    free(str);
    return 0;
}
