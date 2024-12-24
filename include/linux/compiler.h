/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_COMPILER_H
#define __LINUX_COMPILER_H

#include <linux/compiler_types.h>

#ifndef __ASSEMBLY__

#ifdef __KERNEL__

/*
 * Note: DISABLE_BRANCH_PROFILING can be used by special lowlevel code
 * to disable branch tracing on a per file basis.
 */
void ftrace_likely_update(struct ftrace_likely_data *f, int val,
			  int expect, int is_constant);
#if defined(CONFIG_TRACE_BRANCH_PROFILING) \
    && !defined(DISABLE_BRANCH_PROFILING) && !defined(__CHECKER__)
#define likely_notrace(x)	__builtin_expect(!!(x), 1)
#define unlikely_notrace(x)	__builtin_expect(!!(x), 0)

#define __branch_check__(x, expect, is_constant) ({			\
			long ______r;					\
			static struct ftrace_likely_data		\
				__aligned(4)				\
				__section("_ftrace_annotated_branch")	\
				______f = {				\
				.data.func = __func__,			\
				.data.file = __FILE__,			\
				.data.line = __LINE__,			\
			};						\
			______r = __builtin_expect(!!(x), expect);	\
			ftrace_likely_update(&______f, ______r,		\
					     expect, is_constant);	\
			______r;					\
		})

/*
 * Using __builtin_constant_p(x) to ignore cases where the return
 * value is always the same.  This idea is taken from a similar patch
 * written by Daniel Walker.
 */
# ifndef likely
#  define likely(x)	(__branch_check__(x, 1, __builtin_constant_p(x)))
# endif
# ifndef unlikely
#  define unlikely(x)	(__branch_check__(x, 0, __builtin_constant_p(x)))
# endif

#ifdef CONFIG_PROFILE_ALL_BRANCHES
/*
 * "Define 'is'", Bill Clinton
 * "Define 'if'", Steven Rostedt
 */
#define if(cond, ...) if ( __trace_if_var( !!(cond , ## __VA_ARGS__) ) )

#define __trace_if_var(cond) (__builtin_constant_p(cond) ? (cond) : __trace_if_value(cond))

#define __trace_if_value(cond) ({			\
	static struct ftrace_branch_data		\
		__aligned(4)				\
		__section("_ftrace_branch")		\
		__if_trace = {				\
			.func = __func__,		\
			.file = __FILE__,		\
			.line = __LINE__,		\
		};					\
	(cond) ?					\
		(__if_trace.miss_hit[1]++,1) :		\
		(__if_trace.miss_hit[0]++,0);		\
})

#endif /* CONFIG_PROFILE_ALL_BRANCHES */

#else
# define likely(x)	__builtin_expect(!!(x), 1)
# define unlikely(x)	__builtin_expect(!!(x), 0)
# define likely_notrace(x)	likely(x)
# define unlikely_notrace(x)	unlikely(x)
#endif

/* Optimization barrier */
#ifndef barrier
/* The "volatile" is due to gcc bugs */
# define barrier() __asm__ __volatile__("": : :"memory")
#endif

#ifndef barrier_data
/*
 * This version is i.e. to prevent dead stores elimination on @ptr
 * where gcc and llvm may behave differently when otherwise using
 * normal barrier(): while gcc behavior gets along with a normal
 * barrier(), llvm needs an explicit input variable to be assumed
 * clobbered. The issue is as follows: while the inline asm might
 * access any memory it wants, the compiler could have fit all of
 * @ptr into memory registers instead, and since @ptr never escaped
 * from that, it proved that the inline asm wasn't touching any of
 * it. This version works well with both compilers, i.e. we're telling
 * the compiler that the inline asm absolutely may see the contents
 * of @ptr. See also: https://llvm.org/bugs/show_bug.cgi?id=15495
 */
# define barrier_data(ptr) __asm__ __volatile__("": :"r"(ptr) :"memory")
#endif

/* workaround for GCC PR82365 if needed */
#ifndef barrier_before_unreachable
# define barrier_before_unreachable() do { } while (0)
#endif

/* Unreachable code */
#ifdef CONFIG_OBJTOOL
/*
 * These macros help objtool understand GCC code flow for unreachable code.
 * The __COUNTER__ based labels are a hack to make each instance of the macros
 * unique, to convince GCC not to merge duplicate inline asm statements.
 */
#define __stringify_label(n) #n

#define __annotate_reachable(c) ({					\
	asm volatile(__stringify_label(c) ":\n\t"			\
			".pushsection .discard.reachable\n\t"		\
			".long " __stringify_label(c) "b - .\n\t"	\
			".popsection\n\t");				\
})
#define annotate_reachable() __annotate_reachable(__COUNTER__)

#define __annotate_unreachable(c) ({					\
	asm volatile(__stringify_label(c) ":\n\t"			\
		     ".pushsection .discard.unreachable\n\t"		\
		     ".long " __stringify_label(c) "b - .\n\t"		\
		     ".popsection\n\t" : : "i" (c));			\
})
#define annotate_unreachable() __annotate_unreachable(__COUNTER__)

/* Annotate a C jump table to allow objtool to follow the code flow */
#define __annotate_jump_table __section(".rodata..c_jump_table,\"a\",@progbits #")

#else /* !CONFIG_OBJTOOL */
#define annotate_reachable()
#define annotate_unreachable()
#define __annotate_jump_table
#endif /* CONFIG_OBJTOOL */

#ifndef unreachable
# define unreachable() do {		\
	annotate_unreachable();		\
	__builtin_unreachable();	\
} while (0)
#endif

/*
 * KENTRY - kernel entry point
 * This can be used to annotate symbols (functions or data) that are used
 * without their linker symbol being referenced explicitly. For example,
 * interrupt vector handlers, or functions in the kernel image that are found
 * programatically.
 *
 * Not required for symbols exported with EXPORT_SYMBOL, or initcalls. Those
 * are handled in their own way (with KEEP() in linker scripts).
 *
 * KENTRY can be avoided if the symbols in question are marked as KEEP() in the
 * linker script. For example an architecture could KEEP() its entire
 * boot/exception vector code rather than annotate each function and data.
 */
#ifndef KENTRY
# define KENTRY(sym)						\
	extern typeof(sym) sym;					\
	static const unsigned long __kentry_##sym		\
	__used							\
	__attribute__((__section__("___kentry+" #sym)))		\
	= (unsigned long)&sym;
#endif

#ifndef RELOC_HIDE
# define RELOC_HIDE(ptr, off)					\
  ({ unsigned long __ptr;					\
     __ptr = (unsigned long) (ptr);				\
    (typeof(ptr)) (__ptr + (off)); })
#endif

#define absolute_pointer(val)	RELOC_HIDE((void *)(val), 0)

#ifndef OPTIMIZER_HIDE_VAR
/* Make the optimizer believe the variable can be manipulated arbitrarily. */
#define OPTIMIZER_HIDE_VAR(var)						\
	__asm__ ("" : "=r" (var) : "0" (var))
#endif

#define __UNIQUE_ID(prefix) __PASTE(__PASTE(__UNIQUE_ID_, prefix), __COUNTER__)

/**
 * data_race - mark an expression as containing intentional data races
 *
 * This data_race() macro is useful for situations in which data races
 * should be forgiven.  One example is diagnostic code that accesses
 * shared variables but is not a part of the core synchronization design.
 * For example, if accesses to a given variable are protected by a lock,
 * except for diagnostic code, then the accesses under the lock should
 * be plain C-language accesses and those in the diagnostic code should
 * use data_race().  This way, KCSAN will complain if buggy lockless
 * accesses to that variable are introduced, even if the buggy accesses
 * are protected by READ_ONCE() or WRITE_ONCE().
 *
 * This macro *does not* affect normal code generation, but is a hint
 * to tooling that data races here are to be ignored.  If the access must
 * be atomic *and* KCSAN should ignore the access, use both data_race()
 * and READ_ONCE(), for example, data_race(READ_ONCE(x)).
 */
#define data_race(expr)							\
({									\
	__kcsan_disable_current();					\
	__auto_type __v = (expr);					\
	__kcsan_enable_current();					\
	__v;								\
})

#endif /* __KERNEL__ */

/**
 * offset_to_ptr - convert a relative memory offset to an absolute pointer
 * @off:	the address of the 32-bit offset value
 */
static inline void *offset_to_ptr(const int *off)
{
	return (void *)((unsigned long)off + *off);
}

#endif /* __ASSEMBLY__ */

#ifdef CONFIG_64BIT
#define ARCH_SEL(a,b) a
#else
#define ARCH_SEL(a,b) b
#endif

/*
 * Force the compiler to emit 'sym' as a symbol, so that we can reference
 * it from inline assembler. Necessary in case 'sym' could be inlined
 * otherwise, or eliminated entirely due to lack of references that are
 * visible to the compiler.
 */
#define ___ADDRESSABLE(sym, __attrs)						\
	static void * __used __attrs						\
	__UNIQUE_ID(__PASTE(__addressable_,sym)) = (void *)(uintptr_t)&sym;

#define __ADDRESSABLE(sym) \
	___ADDRESSABLE(sym, __section(".discard.addressable"))

#define __ADDRESSABLE_ASM(sym)						\
	.pushsection .discard.addressable,"aw";				\
	.align ARCH_SEL(8,4);						\
	ARCH_SEL(.quad, .long) __stringify(sym);			\
	.popsection;

#define __ADDRESSABLE_ASM_STR(sym) __stringify(__ADDRESSABLE_ASM(sym))

#ifdef __CHECKER__
#define __BUILD_BUG_ON_ZERO_MSG(e, msg) (0)
#else /* __CHECKER__ */
#define __BUILD_BUG_ON_ZERO_MSG(e, msg) ((int)sizeof(struct {_Static_assert(!(e), msg);}))
#endif /* __CHECKER__ */

/* &a[0] degrades to a pointer: a different type from an array */
#define __must_be_array(a)	__BUILD_BUG_ON_ZERO_MSG(__same_type((a), &(a)[0]), "must be array")

/* Require C Strings (i.e. NUL-terminated) lack the "nonstring" attribute. */
#define __must_be_cstr(p) \
	__BUILD_BUG_ON_ZERO_MSG(__annotated(p, nonstring), "must be cstr (NUL-terminated)")

/*
 * Whether 'type' is a signed type or an unsigned type. Supports scalar types,
 * bool and also pointer types.
 */
#define is_signed_type(type) (((type)(-1)) < (__force type)1)
#define is_unsigned_type(type) (!is_signed_type(type))

/*
 * Useful shorthand for "is this condition known at compile-time?"
 *
 * Note that the condition may involve non-constant values,
 * but the compiler may know enough about the details of the
 * values to determine that the condition is statically true.
 */
#define statically_true(x) (__builtin_constant_p(x) && (x))

/*
 * Whether x is the integer constant expression 0 or something else.
 *
 * Details:
 *   - The C11 standard defines in §6.3.2.3.3
 *       (void *)<integer constant expression with the value 0>
 *     as a null pointer constant (c.f. the NULL macro).
 *   - If x evaluates to the integer constant expression 0,
 *       (void *)(x)
 *     is a null pointer constant. Else, it is a void * expression.
 *   - In a ternary expression:
 *       condition ? operand1 : operand2
 *     if one of the two operands is of type void * and the other one
 *     some other pointer type, the C11 standard defines in §6.5.15.6
 *     the resulting type as below:
 *       if one operand is a null pointer constant, the result has the
 *       type of the other operand; otherwise [...] the result type is
 *       a pointer to an appropriately qualified version of void.
 *   - As such, in
 *       0 ? (void *)(x) : (char *)0
 *     if x is the integer constant expression 0, operand1 is a null
 *     pointer constant and the resulting type is that of operand2:
 *     char *. If x is anything else, the type is void *.
 *   - The (long) cast silences a compiler warning for when x is not 0.
 *   - Finally, the _Generic() dispatches the resulting type into a
 *     Boolean.
 */
#define __is_const_zero(x) \
	_Generic(0 ? (void *)(long)(x) : (char *)0, char *: 1, void *: 0)

/*
 * Returns a constant expression while determining if its argument is a
 * constant expression, most importantly without evaluating the argument.
 *
 * The argument must be a scalar. Pointers raise a constraint violation.
 *
 * If you want to know whether x is a compile time constant, use
 * __builtin_constant_p() instead.
 */
#define is_const(x) __is_const_zero(0 * (x))

/*
 * Return an integer constant expression while evaluating if the
 * argument is a true (non zero) integer constant expression.
 *
 * To be used in conjunction with macros, such as BUILD_BUG_ON_ZERO(),
 * which require their input to be a constant expression and for which
 * statically_true() would otherwise fail.
 *
 * This is a trade-off: is_const_true() requires all its operands to
 * be compile time constants. Else, it would always returns false even
 * on the most trivial cases like:
 *
 *   true || non_const_expr
 *
 * On the opposite, statically_true() is able to fold more complex
 * tautologies and will return true on expressions such as:
 *
 *   !(non_const_expr * 8 % 4)
 *
 * For the general case, statically_true() is better.
 */
#define is_const_true(x) __is_const_zero((x) == 0)

/*
 * This is needed in functions which generate the stack canary, see
 * arch/x86/kernel/smpboot.c::start_secondary() for an example.
 */
#define prevent_tail_call_optimization()	mb()

#include <asm/rwonce.h>

#endif /* __LINUX_COMPILER_H */
