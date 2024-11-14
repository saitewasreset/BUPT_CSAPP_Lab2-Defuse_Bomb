#include "support.h"
#include <stdio.h>

int strings_not_equal(const char *a, const char *b) {
    const char *cur_a = a;
    const char *cur_b = b;

    if (string_length(a) == string_length(b)) {
        if (*cur_a == '\0') {
            return 0;
        }

        while (*cur_a == *cur_b) {
            cur_a++;
            cur_b++;

            if (*cur_a == '\0') {
                return 0;
            }
        }
    }

    return 1;
}

int string_length(const char *str) {
    int length = 0;

    while (*str != '\0') {
        length++;
        str++;
    }
    return length;
}

void read_six_numbers(char *s, int *arr) {
    int read_count;

    read_count = sscanf(s, "%d %d %d %d %d %d", &arr[0], &arr[1], &arr[2],
                        &arr[3], &arr[4], &arr[5]);
    if (read_count < 6) {
        explode_bomb();
    }
    return;
}

int func4(int a, int b, int c) {
    int mid = (b + c) / 2;
    if (mid > a) {
        return func4(a, b, (mid - 1)) * 2;
    } else if (mid < a) {
        return func4(a, (mid + 1), c) * 2 + 1;
    } else {
        return 0;
    }
}

int fun7(uint64_t arg1, int arg2) {
    if (arg1 == 0) {
        return -1;
    }

    if (arg2 < *(int *)arg1) {
        return 2 * fun7(*(uint64_t *)(arg1 + 8), arg2);
    } else if (arg2 > *(int *)arg1) {
        return 2 * fun7(*(uint64_t *)(arg1 + 16), arg2) + 1;
    } else {
        return 0;
    }
}