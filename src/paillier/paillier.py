"""
Minimal pure-Python implementation of the
`Paillier cryptosystem <https://en.wikipedia.org/wiki/Paillier_cryptosystem>`__.
"""
from __future__ import annotations
from typing import Union, Tuple
import doctest
import math
import secrets
from egcd import egcd

def _prime(number: int) -> bool:
    """
    Pure-Python implementation of the Miller-Rabin primality test.

    >>> _prime(2)
    True
    >>> _prime(4)
    False
    >>> _prime(9999777777776655544433333333222111111111)
    True
    >>> _prime(9999777777776655544433333333222111111115)
    False
    >>> _prime(0) or _prime(1)
    False

    Any attempt to invoke this function with an argument that does not have the
    expected types raises an exception.

    >>> _prime('abc')
    Traceback (most recent call last):
      ...
    TypeError: input must be an integer
    >>> _prime(-123)
    Traceback (most recent call last):
      ...
    ValueError: input must be a nonnegative integer
    """
    if not isinstance(number, int):
        raise TypeError('input must be an integer')

    if number < 0:
        raise ValueError('input must be a nonnegative integer')

    if number in (0, 1):
        return False

    for prime in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31]:
        if number == prime:
            return True
        if number % prime == 0:
            return False

    exponent = 0
    odd = number - 1
    while odd % 2 == 0:
        odd >>= 1
        exponent += 1

    for i in range(8):
        a = 2 + secrets.randbelow(number - 2)
        if pow(a, odd, number) == 1:
            continue
        composite = True
        for i in range(exponent):
            if pow(a, (2 ** i) * odd, number) == number - 1:
                composite = False
                break
        if composite:
            return False

    return True

def _primes(bit_length: int) -> Tuple[int, int]:
    """
    Return a pair of distinct primes (each having the specified
    number of bits in its representation).

    >>> (p, q) = _primes(32)
    >>> p.bit_length() == q.bit_length() == 32
    True
    >>> math.gcd(p, q)
    1
    """
    (lower, upper) = (2 ** (bit_length - 1), (2 ** bit_length) - 1)
    difference = upper - lower
    (p, q) = (0, 0)
    while p <= lower or not _prime(p):
        p = (secrets.randbelow(difference // 2) * 2) + lower + 1
    while p == q or q <= lower or not _prime(q):
        q = (secrets.randbelow(difference // 2) * 2) + lower + 1

    return (p, q)

class secret(Tuple[int, int]):
    """
    Wrapper class for an integer that represents a secret key.

    >>> (secret_key, _) = keypair(256)
    >>> isinstance(secret_key, secret)
    True
    """

class public(Tuple[int, int]):
    """
    Wrapper class for an integer that represents a public key.

    >>> (_, public_key) = keypair(256)
    >>> isinstance(public_key, public)
    True
    """

class plain(int):
    """
    Wrapper class for an integer that represents a plaintext.

    >>> isinstance(plain(123), plain)
    True
    """

class cipher(int):
    """
    Wrapper class for an integer that represents a ciphertext.

    >>> (secret_key, public_key) = keypair(256)
    >>> ciphertext = encrypt(public_key, plain(123))
    >>> isinstance(ciphertext, cipher)
    True
    """

def _generator(modulus: int) -> int:
    """
    Return a generator modulo the supplied modulus.
    """
    g = 0
    while g == 0 or math.gcd(g, modulus) != 1:
        g = secrets.randbelow(modulus)

    return g

def keypair(bit_length: int) -> (secret, public):
    """
    Return a key pair.
    """
    (p, q) = _primes(bit_length)
    n = p * q
    lam = ((p - 1) * (q - 1)) // math.gcd(p - 1, q - 1)
    g = None
    while g is None:
        g = _generator(n ** 2)
        (d, mu, _) = egcd((pow(g, lam, n ** 2) - 1) // n, n)
        if d != 1: # pragma: no cover # Highly unlikely to occur.
            g = None
    return (secret((lam, mu % n)), public((n, g)))

def encrypt(public_key: public, plaintext: Union[plain, int]) -> cipher:
    """
    Encrypt the supplied plaintext using the supplied public key.

    >>> (secret_key, public_key) = keypair(2048)
    >>> c = encrypt(public_key, 123)
    >>> isinstance(c, cipher)
    True

    Any attempt to invoke this function using arguments that do not have
    the expected types raises an exception.

    >>> encrypt(secret_key, 123)
    Traceback (most recent call last):
      ...
    TypeError: can only encrypt using a public key
    """
    if not isinstance(public_key, public):
        raise TypeError('can only encrypt using a public key')

    (n, g) = public_key
    r = _generator(n)
    return cipher(pow(g, plaintext % n, n ** 2) * pow(r, n, n ** 2))

def decrypt(secret_key: secret, public_key: public, ciphertext: cipher) -> plain:
    """
    Decrypt the supplied plaintext using the supplied public key.

    >>> (secret_key, public_key) = keypair(2048)
    >>> c = encrypt(public_key, 123)
    >>> decrypt(secret_key, public_key, c)
    123

    Any attempt to invoke this function using arguments that do not have
    the expected types raises an exception.

    >>> decrypt(public_key, secret_key, c)
    Traceback (most recent call last):
      ...
    TypeError: can only decrypt using a secret key and its corresponding public key
    >>> decrypt(secret_key, public_key, 123)
    Traceback (most recent call last):
      ...
    TypeError: can only decrypt a ciphertext
    """
    if (not isinstance(secret_key, secret)) or (not isinstance(public_key, public)):
        raise TypeError(
            'can only decrypt using a secret key and its corresponding public key'
        )

    if not isinstance(ciphertext, cipher):
        raise TypeError('can only decrypt a ciphertext')

    (n, _) = public_key
    (lam, mu) = secret_key
    return plain((((pow(ciphertext, lam, n ** 2) - 1) // n) * mu) % n)

def add(public_key: public, c: cipher, d: cipher) -> cipher:
    """
    Perform addition of two encrypted values to produce the encrypted
    result.

    >>> (secret_key, public_key) = keypair(2048)
    >>> c = encrypt(public_key, 22)
    >>> d = encrypt(public_key, 33)
    >>> r = add(public_key, c, d)
    >>> int(decrypt(secret_key, public_key, r))
    55

    Any attempt to invoke this function using arguments that do not have
    the expected types raises an exception.

    >>> add(secret_key, c, d)
    Traceback (most recent call last):
      ...
    TypeError: can only perform operation using a public key
    >>> add(public_key, c, 123)
    Traceback (most recent call last):
      ...
    TypeError: can only add two ciphertexts
    """
    if not isinstance(public_key, public):
        raise TypeError('can only perform operation using a public key')

    if (not isinstance(c, cipher)) or (not isinstance(d, cipher)):
        raise TypeError('can only add two ciphertexts')

    return cipher((c * d) % (public_key[0] ** 2))

def mul(public_key: public, c: cipher, s: int) -> cipher:
    """
    Perform multiplication of an encrypted value by a scalar to produce
    the encrypted result.

    >>> (secret_key, public_key) = keypair(2048)
    >>> c = encrypt(public_key, 22)
    >>> r = mul(public_key, c, 3)
    >>> int(decrypt(secret_key, public_key, r))
    66

    Any attempt to invoke this function using arguments that do not have
    the expected types raises an exception.

    >>> mul(secret_key, c, 3)
    Traceback (most recent call last):
      ...
    TypeError: can only perform operation using a public key
    >>> mul(public_key, 123, 3)
    Traceback (most recent call last):
      ...
    TypeError: can only multiply a ciphertext
    >>> mul(public_key, c, 'abc')
    Traceback (most recent call last):
      ...
    TypeError: can only multiply by an integer scalar
    """
    if not isinstance(public_key, public):
        raise TypeError('can only perform operation using a public key')

    if not isinstance(c, cipher):
        raise TypeError('can only multiply a ciphertext')

    if not isinstance(s, int):
        raise TypeError('can only multiply by an integer scalar')

    return cipher((c ** s) % (public_key[0] ** 2))

if __name__ == '__main__':
    doctest.testmod() # pragma: no cover
