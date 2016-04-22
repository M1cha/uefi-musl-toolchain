/*
 * Copyright 2016, The EFIDroid Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

#ifndef _SYSCALLS_H
#define _SYSCALLS_H

#define asmlinkage

#ifdef __CHECKER__
# define __user		__attribute__((noderef, address_space(1)))
# define __kernel	__attribute__((address_space(0)))
#else
# define __user
# define __kernel
#endif

/**
 * BUILD_BUG_ON - break compile if a condition is true.
 * @condition: the condition which the compiler should know is false.
 *
 * If you have some code which relies on certain constants being equal, or
 * other compile-time-evaluated condition, you should use BUILD_BUG_ON to
 * detect if someone changes it.
 *
 * The implementation uses gcc's reluctance to create a negative array, but
 * gcc (as of 4.4) only emits that error for obvious cases (eg. not arguments
 * to inline functions).  So as a fallback we use the optimizer; if it can't
 * prove the condition is false, it will cause a link error on the undefined
 * "__build_bug_on_failed".  This error message can be harder to track down
 * though, hence the two different methods.
 */
#ifndef __OPTIMIZE__
#define BUILD_BUG_ON(condition) ((void)sizeof(char[1 - 2*!!(condition)]))
#else
extern int __build_bug_on_failed;
#define BUILD_BUG_ON(condition)					\
	do {							\
		((void)sizeof(char[1 - 2*!!(condition)]));	\
		if (condition) __build_bug_on_failed = 1;	\
	} while(0)
#endif

#define __SC_DECL1(t1, a1)	t1 a1
#define __SC_DECL2(t2, a2, ...) t2 a2, __SC_DECL1(__VA_ARGS__)
#define __SC_DECL3(t3, a3, ...) t3 a3, __SC_DECL2(__VA_ARGS__)
#define __SC_DECL4(t4, a4, ...) t4 a4, __SC_DECL3(__VA_ARGS__)
#define __SC_DECL5(t5, a5, ...) t5 a5, __SC_DECL4(__VA_ARGS__)
#define __SC_DECL6(t6, a6, ...) t6 a6, __SC_DECL5(__VA_ARGS__)

#define __SC_LONG1(t1, a1) 	long a1
#define __SC_LONG2(t2, a2, ...) long a2, __SC_LONG1(__VA_ARGS__)
#define __SC_LONG3(t3, a3, ...) long a3, __SC_LONG2(__VA_ARGS__)
#define __SC_LONG4(t4, a4, ...) long a4, __SC_LONG3(__VA_ARGS__)
#define __SC_LONG5(t5, a5, ...) long a5, __SC_LONG4(__VA_ARGS__)
#define __SC_LONG6(t6, a6, ...) long a6, __SC_LONG5(__VA_ARGS__)

#define __SC_CAST1(t1, a1)	(t1) a1
#define __SC_CAST2(t2, a2, ...) (t2) a2, __SC_CAST1(__VA_ARGS__)
#define __SC_CAST3(t3, a3, ...) (t3) a3, __SC_CAST2(__VA_ARGS__)
#define __SC_CAST4(t4, a4, ...) (t4) a4, __SC_CAST3(__VA_ARGS__)
#define __SC_CAST5(t5, a5, ...) (t5) a5, __SC_CAST4(__VA_ARGS__)
#define __SC_CAST6(t6, a6, ...) (t6) a6, __SC_CAST5(__VA_ARGS__)

#define __SC_TEST(type)		BUILD_BUG_ON(sizeof(type) > sizeof(long))
#define __SC_TEST1(t1, a1)	__SC_TEST(t1)
#define __SC_TEST2(t2, a2, ...)	__SC_TEST(t2); __SC_TEST1(__VA_ARGS__)
#define __SC_TEST3(t3, a3, ...)	__SC_TEST(t3); __SC_TEST2(__VA_ARGS__)
#define __SC_TEST4(t4, a4, ...)	__SC_TEST(t4); __SC_TEST3(__VA_ARGS__)
#define __SC_TEST5(t5, a5, ...)	__SC_TEST(t5); __SC_TEST4(__VA_ARGS__)
#define __SC_TEST6(t6, a6, ...)	__SC_TEST(t6); __SC_TEST5(__VA_ARGS__)

#define SYSCALL_DEFINE0(name)	   asmlinkage long sys_##name()
#define SYSCALL_DEFINE1(name, ...) SYSCALL_DEFINEx(1, _##name, __VA_ARGS__)
#define SYSCALL_DEFINE2(name, ...) SYSCALL_DEFINEx(2, _##name, __VA_ARGS__)
#define SYSCALL_DEFINE3(name, ...) SYSCALL_DEFINEx(3, _##name, __VA_ARGS__)
#define SYSCALL_DEFINE4(name, ...) SYSCALL_DEFINEx(4, _##name, __VA_ARGS__)
#define SYSCALL_DEFINE5(name, ...) SYSCALL_DEFINEx(5, _##name, __VA_ARGS__)
#define SYSCALL_DEFINE6(name, ...) SYSCALL_DEFINEx(6, _##name, __VA_ARGS__)

#define SYSCALL_ALIAS(alias, name)					\
	asm ("\t.globl " #alias "\n\t.set " #alias ", " #name)

#define SYSCALL_DEFINEx(x, sname, ...)				\
	__SYSCALL_DEFINEx(x, sname, __VA_ARGS__)

#define __SYSCALL_DEFINEx(x, name, ...)					\
	asmlinkage long sys##name(__SC_DECL##x(__VA_ARGS__));		\
	static inline long SYSC##name(__SC_DECL##x(__VA_ARGS__));	\
	asmlinkage long SyS##name(__SC_LONG##x(__VA_ARGS__))		\
	{								\
		__SC_TEST##x(__VA_ARGS__);				\
		return (long) SYSC##name(__SC_CAST##x(__VA_ARGS__));	\
	}								\
	SYSCALL_ALIAS(sys##name, SyS##name);				\
	static inline long SYSC##name(__SC_DECL##x(__VA_ARGS__))

#endif // _SYSCALLS_H
