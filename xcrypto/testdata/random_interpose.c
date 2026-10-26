// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <Security/SecRandom.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int testRandom(SecRandomRef random, size_t count, uint8_t *bytes) {
    const char *mode = getenv("GO_DARWIN_TEST_RANDOM_MODE");
    if (mode != NULL && strcmp(mode, "lifetime") == 0) {
        if (count < 2 * sizeof(int))
            return -1;
        int fds[2];
        memcpy(fds, bytes, sizeof(fds));
        unsigned char signal = 1;
        if (write(fds[0], &signal, 1) != 1)
            return -1;
        ssize_t n;
        do {
            n = read(fds[1], &signal, 1);
        } while (n < 0 && errno == EINTR);
        if (n != 1 || signal != 1)
            return -1;
        memset(bytes, 0x5a, count);
        return 0;
    }
    if (mode != NULL && strcmp(mode, "partial") == 0 && count != 0)
        bytes[0] = 0x5a;
    return -1;
}

__attribute__((used))
static const struct {
    const void *replacement;
    const void *original;
} interpose __attribute__((section("__DATA,__interpose"))) = {
    (const void *)testRandom,
    (const void *)SecRandomCopyBytes
};
