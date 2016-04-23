.syntax unified
.global setjmp_stack
.type setjmp_stack,%function
setjmp_stack:
    push    { r0-r11, lr }

    // src
    ldr r4, =stack_base
    ldr r4, [r4]
    // dst
    ldr r5, =stack_copy
    ldr r5, [r5]
    // src+len
    ldr r6, =stack_size
    ldr r6, [r6]
    add r6, r4

    // backup stack contents
.Lcopy_loop:
    ldr     r7, [r4], #4
    str     r7, [r5], #4
    cmp     r4, r6
    bne     .Lcopy_loop

    pop    { r0-r11, lr }

    // call setjmp
    b setjmp
