/* Wraps the unmodified pcap_capture.c so the harness can set its private state
 * (a connected capture client) without starting the firmware's TCP server task. */
#include <arpa/inet.h>
#include "../components/pcap_capture/pcap_capture.c"

void mayhem_pcap_setup(int mode, int connected)
{
    ringbuf_init();
    if (connected) {
        ringbuf_alloc(4096);
    }
    capture_mode = (pcap_capture_mode_t)mode;
    client_connected = connected != 0;
    captured_packets = 0;
}

void mayhem_pcap_teardown(void)
{
    ringbuf_free();
    capture_mode = PCAP_MODE_OFF;
    client_connected = false;
}
