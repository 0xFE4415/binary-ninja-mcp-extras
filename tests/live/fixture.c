#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define PLANT __attribute__((noipa))

volatile int sink32;
volatile int64_t sink64;
volatile uint64_t sink_unsigned64;
volatile int8_t sink8;

/* One callee reached from two call sites; a diamond with two real routes. */
PLANT int dup_leaf(int value)
{
    puts("dup_leaf");
    return value + 1;
}

PLANT int dup_mid(int value)
{
    int result = dup_leaf(value);
    if (sink32)
        result += dup_leaf(result);
    return result;
}

PLANT int dup_root(int value)
{
    return dup_mid(value) + 1;
}

PLANT int diamond_bottom(int value)
{
    puts("diamond_bottom");
    return value * 3;
}

PLANT int diamond_left(int value)
{
    return diamond_bottom(value) + 1;
}

PLANT int diamond_right(int value)
{
    return diamond_bottom(value) + 2;
}

PLANT int diamond_top(int value)
{
    return sink32 ? diamond_left(value) : diamond_right(value);
}

/* -1 compared at widths 1, 2, 4 and 8, and loads at negative displacements. */
PLANT int compare_minus_one(int8_t narrow, int16_t half, int32_t word, int64_t wide)
{
    if (narrow == -1) {
        sink32 = 1;
        return 1;
    }
    if (half == -1) {
        sink32 = 2;
        return 2;
    }
    if (word == -1) {
        sink32 = 3;
        return 3;
    }
    if (wide == -1) {
        sink32 = 4;
        return 4;
    }
    return 0;
}

PLANT int negative_displacements(const int32_t *words, const int8_t *bytes)
{
    if (words[-2] == 0x1234) {
        sink32 = 1;
        return 1;
    }
    if (bytes[-8] == 0x41) {
        sink32 = 2;
        return 2;
    }
    if (words[-3] == -1) {
        sink32 = 3;
        return 3;
    }
    return 0;
}

/* All-ones 64-bit constant, a distinct magic, real zero, xor-only zero. */
PLANT void store_big_constants(void)
{
    sink_unsigned64 = 0xffffffffffffffffULL;
    sink64 = 0x7edcba9876543210LL;
}

PLANT void store_real_zero(void)
{
    sink32 = 0;
}

__asm__(".text\n"
        ".globl zero_xor_only\n"
        ".type zero_xor_only,@function\n"
        "zero_xor_only:\n"
        "    xor %eax, %eax\n"
        "    ret\n"
        ".size zero_xor_only, .-zero_xor_only\n");

/* Register parameters and stack-passed parameters that MLIL never defines. */
PLANT int many_arguments(int a, int b, int c, int d, int e, int f, int g, int h)
{
    return a + b + c + d + e + f + g * h;
}

/* One variable defined at three addresses; the core lists them out of address order. */
__asm__(".text\n"
        ".globl many_definitions\n"
        ".type many_definitions,@function\n"
        "many_definitions:\n"
        "    cmpl $1, sink32(%rip)\n"
        "    jne 3f\n"
        "    lea 7(%rsi), %eax\n"
        "9:  movb %al, sink8(%rip)\n"
        "    ret\n"
        "3:  lea 3(%rdi), %eax\n"
        "    cmpl $2, sink32(%rip)\n"
        "    jne 9b\n"
        "    lea 5(%rdx), %eax\n"
        "    jmp 9b\n"
        ".size many_definitions, .-many_definitions\n");

int many_definitions(int first, int second, int third);

/* overlap_high jumps into the middle of overlap_low, so one block is in both. */
__asm__(".text\n"
        ".globl overlap_low\n"
        ".type overlap_low,@function\n"
        "overlap_low:\n"
        "    cmpl $0, sink32(%rip)\n"
        "    jne overlap_shared\n"
        "    movl $0x11111111, %eax\n"
        "    ret\n"
        "overlap_shared:\n"
        "    movl $0x5a5a1234, %eax\n"
        "    ret\n"
        ".size overlap_low, .-overlap_low\n"
        ".globl overlap_high\n"
        ".type overlap_high,@function\n"
        "overlap_high:\n"
        "    cmpl $1, sink32(%rip)\n"
        "    je overlap_shared\n"
        "    movl $0x22222222, %eax\n"
        "    ret\n"
        ".size overlap_high, .-overlap_high\n");

/* main only tail-calls the real body. */
PLANT int real_main(int argc, char **argv)
{
    int total = argc;
    if (argc > 1)
        total += atoi(argv[1]);
    if (argc > 99) {
        total += dup_root(total) + diamond_top(total);
        total += compare_minus_one((int8_t)total, (int16_t)total, total, total);
        total += negative_displacements((const int32_t *)argv, (const int8_t *)argv);
        total += many_arguments(total, total, total, total, total, total, total, total) + many_definitions(total, total, total);
        store_big_constants();
        store_real_zero();
    }
    return total;
}

int main(int argc, char **argv)
{
    return real_main(argc, argv);
}
