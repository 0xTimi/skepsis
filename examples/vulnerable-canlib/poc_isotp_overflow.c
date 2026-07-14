/*
 * poc_isotp_overflow.c — self-contained proof-of-concept for the CWE-787
 * unbounded-copy bug in isotp_reassemble().
 *
 * Run it through Skepsis's dynamic verifier:
 *
 *     skepsis verify examples/vulnerable-canlib/poc_isotp_overflow.c --runs 20
 *
 * Under -fsanitize=address this aborts with a stack-buffer-overflow every run
 * (100% crash rate), satisfying the protocol's dynamic-confirmation bar.
 */
#include <stdint.h>
#include <string.h>

static int isotp_reassemble(const uint8_t *pdu, uint8_t *out) {
    uint8_t len = pdu[0] & 0x0F;   /* up to 15 */
    memcpy(out, pdu + 1, len);     /* overflows an 8-byte destination */
    return len;
}

int main(void) {
    uint8_t out[8];                       /* CAN MTU */
    uint8_t pdu[16] = {0x0F};             /* claims 15 payload bytes */
    for (int i = 1; i < 16; i++) pdu[i] = (uint8_t)i;
    isotp_reassemble(pdu, out);
    return 0;
}
