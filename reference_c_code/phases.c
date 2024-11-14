#include "phases.h"
#include "support.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int _num_input_strings = 0;

void phase_1(char *input) {
    int ret =
        strings_not_equal(input, "In 2004, BUPT became one of the 56 "
                                 "universities which have graduate school.");
    if (ret != 0) {
        explode_bomb();
    }
}

void phase_2(char *input) {
    int arr[6];

    read_six_numbers(input, arr);

    if ((arr[0] != 0) || (arr[1] != 1)) {
        explode_bomb();
    }

    for (int i = 0; i < 4; i++) {
        if (arr[i + 2] != arr[i + 1] + arr[i]) {
            explode_bomb();
        }
    }
}

void phase_3(char *input) {
    int a;
    int b;

    int count = sscanf(input, "%d %d", &a, &b);
    if (count < 2) {
        explode_bomb();
    }

    int f = 0;

    switch (a) {
    case 0:
        f = 492;
        break;
    case 1:
        f = 825;
        break;
    case 2:
        f = 757;
        break;
    case 3:
        f = 82;
        break;
    case 4:
        f = 284;
        break;
    case 5:
        f = 337;
        break;
    case 6:
        f = 56;
        break;
    case 7:
        f = 670;
        break;
    default:
        explode_bomb();
    }

    if (f != b) {
        explode_bomb();
    }
}

void phase_4(char *input) {
    int read_count;
    int ret;

    int a;
    int b;

    read_count = sscanf(input, "%d %d", &a, &b);

    if ((read_count != 2) || (a > 14)) {
        explode_bomb();
    }

    ret = func4(a, 0, 14);

    if ((ret != 1) || (b != 1)) {
        explode_bomb();
    }

    return;
}

void phase_5(char *input) {
    char mapped[7];
    char map[16] = {'m', 'a', 'd', 'u', 'i', 'e', 'r', 's',
                    'n', 'f', 'o', 't', 'v', 'b', 'y', 'l'};

    if (string_length(input) != 6) {
        explode_bomb();
    }

    for (int i = 0; i < 6; i++) {
        mapped[i] = map[input[i] % 16];
    }

    mapped[6] = '\0';

    if (strings_not_equal(mapped, "flyers")) {
        explode_bomb();
    }

    return;
}

void phase_6(char *s) {
    int arr[6];

    uint64_t base_addr_list[6] = {0x6042f0, 0x604300, 0x604310,
                                  0x604320, 0x604330, 0x604340};
    uint64_t temp[6];

    read_six_numbers(s, arr);

    for (int i = 0; i < 6; i++) {
        if (arr[i] > 6 || arr[i] < 1) {
            explode_bomb();
        }

        for (int j = i + 1; j < 6; j++) {
            if (arr[j] == arr[i]) {
                explode_bomb();
            }
        }
    }

    for (int i = 0; i < 6; i++) {
        temp[i] = base_addr_list[arr[i] - 1];
    }

    for (int i = 0; i < 5; i++) {
        *((uint64_t *)temp[i] + 1) = temp[i + 1];
    }

    int *addr = (int *)temp[0];

    for (int i = 0; i < 5; i++) {
        if (**(int **)((uint64_t)addr + 8) < *addr) {
            explode_bomb();
        }

        addr = *(int **)((uint64_t)addr + 8);
    }
}

void secret_phase(void) {
    char *line = read_line();
    long num = strtol(line, '\0', 10);

    if (num > 1001 || num < 0) {
        explode_bomb();
    }

    if (fun7(0x604110, (int)num) != 0) {
        explode_bomb();
    }

    puts("Wow! You\'ve defused the secret stage!");
    phase_defused();
    return;
}

void phase_defused(void) {
    int a;
    int b;
    char buffer[88];

    send_msg(1);
    if (_num_input_strings == 6) {
        if (sscanf((const char *)0x6048b0, "%d %d %s", &a, &b, buffer) == 3) {
            if (!strings_not_equal(buffer, (const char *)0x4029d0)) {
                puts("Curses, you\'ve found the secret phase!");
                puts("But finding it and solving it are quite different...");
                secret_phase();
            }
        }
        puts("Congratulations! You\'ve defused the bomb!");
        puts(
            "Your instructor has been notified and will verify your solution.");
    }

    return;
}