#include <stddef.h>
#include <stdint.h>

extern void swihomo_write_packets(const uint8_t *buffer, const size_t *lengths, const int *families, size_t count) __attribute__((weak_import));
extern void swihomo_write_log(const char *level, const char *message) __attribute__((weak_import));

void swihomo_emit_packets(const uint8_t *buffer, const size_t *lengths, const int *families, size_t count) {
    if (swihomo_write_packets != NULL) {
        swihomo_write_packets(buffer, lengths, families, count);
    }
}

void swihomo_emit_log(const char *level, const char *message) {
    if (swihomo_write_log != NULL) {
        swihomo_write_log(level, message);
    }
}
