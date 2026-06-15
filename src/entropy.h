#ifndef MOLE_ENTROPY_H
#define MOLE_ENTROPY_H

#include <stddef.h>

/* Entropy math reused from the `entropy` password toolkit.
 *
 * `entropy` measures password strength as length * log2(charset_pool).
 * For a secrets scanner the more discriminating signal is the *observed*
 * Shannon entropy of a token's byte distribution: real credentials (random
 * base64 / hex blobs) crowd the upper end of the bits-per-character scale,
 * whereas English words and identifiers sit well below it. We keep both
 * notions here:
 *
 *   shannon_entropy_bits()  - observed bits per character (0 .. 8)
 *   charset_pool()          - theoretical pool size, as in `entropy`
 *   naive_entropy_bits()    - len * log2(pool), the `entropy` "naive" metric
 */

/* Observed Shannon entropy of the first `len` bytes of `s`, in bits per
 * character (0 for empty input). This is the headline metric the scanner
 * thresholds on. */
double shannon_entropy_bits(const char *s, size_t len);

/* Theoretical character-pool size for `s`, summing the classes present
 * (lowercase 26, uppercase 26, digits 10, plus a flat bump for any symbols),
 * mirroring charset_size() in the entropy tool. */
int charset_pool(const char *s, size_t len);

/* Naive entropy: len * log2(charset_pool), the entropy tool's theoretical
 * upper bound. Useful as a secondary score for the triage UI. */
double naive_entropy_bits(const char *s, size_t len);

#endif /* MOLE_ENTROPY_H */
