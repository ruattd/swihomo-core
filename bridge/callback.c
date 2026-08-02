#include <stddef.h>
#include <stdint.h>

extern void swihomo_write_packet(const uint8_t *packet, size_t length, int family) __attribute__((weak_import));
extern void swihomo_write_log(const char *level, const char *message) __attribute__((weak_import));

void swihomo_emit_packet(const uint8_t *packet, size_t length, int family) {
    if (swihomo_write_packet != NULL) {
        swihomo_write_packet(packet, length, family);
    }
}

void swihomo_emit_log(const char *level, const char *message) {
    if (swihomo_write_log != NULL) {
        swihomo_write_log(level, message);
    }
}
