#ifndef FRANKENSTEIN_LGCC_H
#define FRANKENSTEIN_LGCC_H

/*
 * __udivmodsi4.c
 *
 */

extern void __div0(void);

/*
 * 32-bit. (internal funtion)
 */
unsigned int __udivmodsi4(unsigned int num, unsigned int den, unsigned int * rem_p)
{
    unsigned int quot = 0, qbit = 1;

    if (den == 0)
    {
        return 0;
    }

    /*
     * left-justify denominator and count shift
     */
    while ((signed int) den >= 0)
    {
        den <<= 1;
        qbit <<= 1;
    }

    while (qbit)
    {
        if (den <= num)
        {
            num -= den;
            quot += qbit;
        }
        den >>= 1;
        qbit >>= 1;
    }

    if (rem_p)
        *rem_p = num;

    return quot;
}

/*
 * __aeabi_idiv for 32-bit signed integer divide.
 */

extern unsigned int __udivmodsi4(unsigned int num, unsigned int den, unsigned int * rem_p);

/*
 * 32-bit signed integer divide.
 */
signed int __aeabi_idiv(signed int num, signed int den)
{
    signed int minus = 0;
    signed int v;

    if (num < 0)
    {
        num = -num;
        minus = 1;
    }
    if (den < 0)
    {
        den = -den;
        minus ^= 1;
    }

    v = __udivmodsi4(num, den, 0);
    if (minus)
        v = -v;

    return v;
}

/*
 * __aeabi_uidiv.c for 32-bit unsigned integer divide.
 */

extern unsigned int __udivmodsi4(unsigned int num, unsigned int den, unsigned int * rem_p);

/*
 * 32-bit unsigned integer divide.
 */
unsigned int __aeabi_uidiv(unsigned int num, unsigned int den)
{
    return __udivmodsi4(num, den, 0);
}

#endif
