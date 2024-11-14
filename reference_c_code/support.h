#include <stdint.h>

extern int _num_input_strings;

void initialize_bomb();
char *read_line();
void explode_bomb();
int string_length(const char *str);
int strings_not_equal(const char *a, const char *b);
void read_six_numbers(char *s, int *arr);
int func4(int a, int b, int c);
int fun7(uint64_t arg1, int arg2);
void send_msg(int msg);