/*
 * canparse.c — a deliberately vulnerable ISO-TP / UDS-style frame parser.
 *
 * This file is a TEACHING FIXTURE for Skepsis. It reproduces, in miniature,
 * the bug classes Skepsis hunts for: unbounded protocol fields,
 * integer-underflow indices, uncontrolled format strings, and check-after-use
 * ordering flaws.
 *
 * DO NOT ship anything resembling this. Every function below is unsafe.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define CAN_MTU 8

typedef struct {
    uint8_t data[CAN_MTU];
    uint8_t dlc;
} can_frame_t;

/* BUG (CWE-787): `len` comes straight off the wire and bounds nothing.
 * A single-frame ISO-TP PCI can claim up to 15 bytes into an 8-byte MTU. */
int isotp_reassemble(const uint8_t *pdu, size_t pdu_len, uint8_t *out) {
    uint8_t len = pdu[0] & 0x0F;      /* protocol-controlled length nibble */
    memcpy(out, pdu + 1, len);        /* <-- unbounded copy */
    return len;
}

/* BUG (CWE-191): unsigned underflow makes `remaining` gigantic when the
 * frame is shorter than the header it claims. */
size_t uds_payload_size(const can_frame_t *f) {
    size_t header = 3;
    size_t remaining = f->dlc - header;   /* underflows when dlc < 3 */
    return remaining;
}

/* BUG (CWE-125): index underflow when idx == 0. */
uint8_t last_signal(const uint8_t *buf, size_t idx) {
    return buf[idx - 1];
}

/* BUG (CWE-134): attacker-controlled diagnostic string used as a format. */
void log_dtc(const char *dtc_text) {
    printf(dtc_text);   /* format string */
}

/* BUG (CWE-696): the copy happens before the length is validated. */
int copy_then_check(const uint8_t *src, uint8_t claimed_len, uint8_t *dst, uint8_t cap) {
    memcpy(dst, src, claimed_len);
    if (claimed_len > cap) {
        return -1;      /* too late — the overflow already happened */
    }
    return 0;
}

int main(void) {
    uint8_t out[CAN_MTU];
    uint8_t pdu[2] = {0x0F, 0xAB};   /* claims 15 bytes, provides 1 */
    isotp_reassemble(pdu, sizeof(pdu), out);
    return 0;
}
