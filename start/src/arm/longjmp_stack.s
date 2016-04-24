.syntax unified
.global longjmp_stack
.type longjmp_stack,%function
longjmp_stack:

    // src
    mov r4, r2
    // dst
    ldr r5, =stack_base
    ldr r5, [r5]
    // src+len
    ldr r6, =stack_size
    ldr r6, [r6]
    add r6, r4

    // restore stack backup
.Lcopy_loop:
    ldr     r7, [r4], #4
    str     r7, [r5], #4
    cmp     r4, r6
    bne     .Lcopy_loop

    // call longjmp
    b longjmp
