/* Model-checks the pcap ring buffer (pcap_ringbuf.c, unmodified) against a shadow FIFO. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "pcap_ringbuf.h"

#define SHADOW_MAX 4096

static uint8_t shadow[SHADOW_MAX];
static size_t shadow_len;

static void shadow_pop(size_t n)
{
    memmove(shadow, shadow + n, shadow_len - n);
    shadow_len -= n;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 3) return -1;
    size_t cap = 1 + ((data[0] | (data[1] << 8)) % 2048);
    data += 2; size -= 2;

    ringbuf_init();
    if (!ringbuf_alloc(cap)) abort();
    shadow_len = 0;

    while (size > 0) {
        uint8_t op = data[0] & 7, arg = data[0] >> 3;
        data++; size--;
        switch (op) {
        case 0: {   /* write */
            size_t n = arg < size ? arg : size;
            size_t room = cap - shadow_len;
            bool ok = ringbuf_write(data, n);
            if (ok != (n <= room)) abort();
            if (ok) { memcpy(shadow + shadow_len, data, n); shadow_len += n; }
            data += n; size -= n;
            break;
        }
        case 1: {   /* read */
            size_t max = arg * 7;
            uint8_t *buf = malloc(max ? max : 1);
            size_t r = ringbuf_read(buf, max, 0);
            size_t want = max < shadow_len ? max : shadow_len;
            if (r > want) abort();
            if (r && memcmp(buf, shadow, r) != 0) abort();
            shadow_pop(r);
            free(buf);
            break;
        }
        case 2: {   /* peek */
            size_t max = arg * 7;
            uint8_t *buf = malloc(max ? max : 1);
            size_t r = ringbuf_peek(buf, max);
            size_t want = max < shadow_len ? max : shadow_len;
            if (r != want || (r && memcmp(buf, shadow, r) != 0)) abort();
            free(buf);
            break;
        }
        case 3: {   /* skip */
            size_t n = arg * 11;
            ringbuf_skip(n);
            shadow_pop(n < shadow_len ? n : shadow_len);
            break;
        }
        case 4:
            ringbuf_reset();
            shadow_len = 0;
            break;
        default:
            if (ringbuf_available_bytes() != shadow_len) abort();
            if (ringbuf_free_space() != cap - shadow_len) abort();
            if (ringbuf_total_size() != cap) abort();
            break;
        }
    }
    ringbuf_free();
    return 0;
}
