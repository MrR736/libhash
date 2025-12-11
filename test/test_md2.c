#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "md2.h"

/* RFC 1319 test vectors */
struct tv { const char *m; size_t len; const char *hex; };

int main(void) {
    struct tv tests[] = {
        { "", 0, "8350e5a3e24c153df2275c9f80692773" },
        { "a", 1, "32ec01ec4a6dac72c0ab96fb34c0b5d1" },
        { "abc", 3, "da853b0d3f88d99b30283a69e6ded6bb" },
        { "message digest", 14, "ab4f496bfb2a530b219ff33031fe06b0" },
        { "abcdefghijklmnopqrstuvwxyz", 26, "4e8ddff3650292ab5a4108c3aa47940b" },
        { "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 62,
          "da33def2a42df13975352846c30338cd" },
        { "12345678901234567890123456789012345678901234567890123456789012345678901234567890", 80,
          "d5976f79d83d3a0dc9806c3c66f3efd8" }
    };
    int ntests = sizeof(tests)/sizeof(tests[0]);
    int pass = 0;
    for (int i = 0; i < ntests; ++i) {
        MD2_HASH h;
        Md2Calculate(tests[i].m, tests[i].len, &h);
        char gothex[MD2_HASH_SIZE*2 + 1];
        for (int j = 0; j < MD2_HASH_SIZE; ++j) sprintf(gothex + j*2, "%02x", h.bytes[j]);
        gothex[MD2_HASH_SIZE*2] = '\0';
        int ok = (strcmp(gothex, tests[i].hex) == 0);
        printf("Test %d %s\nMessage : \"%s\"\nExpected: %s\nGot     : %s\n\n",
               i, ok ? "PASSED" : "FAILED", tests[i].m, tests[i].hex, gothex);
        if (ok) ++pass;
    }
    printf("Result: %d/%d passed\n", pass, ntests);
    return (pass == ntests) ? 0 : 1;
}
