/**
 * Big Integer Utilities for Paillier Cryptosystem
 * Implements various mathematical operations needed for cryptography
 */

class BigIntUtils {
    /**
     * Generate a random BigInt with specified bit length
     */
    static randomBigInt(bitLength) {
        const bytes = Math.ceil(bitLength / 8);
        const randomBytes = new Uint8Array(bytes);
        crypto.getRandomValues(randomBytes);

        let result = 0n;
        for (let i = 0; i < bytes; i++) {
            result = (result << 8n) | BigInt(randomBytes[i]);
        }

        // Ensure we have the right bit length
        const mask = (1n << BigInt(bitLength)) - 1n;
        return result & mask;
    }

    /**
     * Generate a random BigInt in range [min, max)
     */
    static randomRange(min, max) {
        const range = max - min;
        const bitLength = range.toString(2).length;

        let result;
        do {
            result = this.randomBigInt(bitLength);
        } while (result >= range);

        return result + min;
    }

    /**
     * Modular exponentiation: (base^exp) % mod
     * Uses binary exponentiation for efficiency
     */
    static modPow(base, exp, mod) {
        if (mod === 1n) return 0n;

        let result = 1n;
        base = base % mod;

        while (exp > 0n) {
            if (exp % 2n === 1n) {
                result = (result * base) % mod;
            }
            exp = exp >> 1n;
            base = (base * base) % mod;
        }

        return result;
    }

    /**
     * Extended Euclidean Algorithm
     * Returns [gcd, x, y] where gcd = ax + by
     */
    static extendedGcd(a, b) {
        if (a === 0n) {
            return [b, 0n, 1n];
        }

        const [gcd, x1, y1] = this.extendedGcd(b % a, a);
        const x = y1 - (b / a) * x1;
        const y = x1;

        return [gcd, x, y];
    }

    /**
     * Modular multiplicative inverse
     * Returns x such that (a * x) ≡ 1 (mod m)
     */
    static modInverse(a, m) {
        const [gcd, x, _] = this.extendedGcd(a, m);

        if (gcd !== 1n) {
            throw new Error('Modular inverse does not exist');
        }

        return (x % m + m) % m;
    }

    /**
     * Greatest Common Divisor using Euclidean algorithm
     */
    static gcd(a, b) {
        while (b !== 0n) {
            [a, b] = [b, a % b];
        }
        return a;
    }

    /**
     * Least Common Multiple
     */
    static lcm(a, b) {
        return (a * b) / this.gcd(a, b);
    }

    /**
     * Miller-Rabin primality test
     * Returns true if n is probably prime
     */
    static isProbablePrime(n, k = 10) {
        if (n === 2n || n === 3n) return true;
        if (n < 2n || n % 2n === 0n) return false;

        // Write n-1 as d * 2^r
        let d = n - 1n;
        let r = 0n;
        while (d % 2n === 0n) {
            d /= 2n;
            r++;
        }

        // Perform k rounds of testing
        for (let i = 0; i < k; i++) {
            const a = this.randomRange(2n, n - 1n);
            let x = this.modPow(a, d, n);

            if (x === 1n || x === n - 1n) continue;

            let composite = true;
            for (let j = 0n; j < r - 1n; j++) {
                x = this.modPow(x, 2n, n);
                if (x === n - 1n) {
                    composite = false;
                    break;
                }
            }

            if (composite) return false;
        }

        return true;
    }

    /**
     * Generate a random prime with specified bit length
     */
    static generatePrime(bitLength) {
        let candidate;
        do {
            candidate = this.randomBigInt(bitLength);
            // Ensure it's odd and has the MSB set
            candidate |= 1n;
            candidate |= (1n << BigInt(bitLength - 1));
        } while (!this.isProbablePrime(candidate));

        return candidate;
    }

    /**
     * Generate two distinct primes of specified bit length
     */
    static generateTwoPrimes(bitLength) {
        const p = this.generatePrime(bitLength);
        let q;
        do {
            q = this.generatePrime(bitLength);
        } while (p === q);

        return [p, q];
    }

    /**
     * Check if two numbers are coprime (gcd = 1)
     */
    static areCoprime(a, b) {
        return this.gcd(a, b) === 1n;
    }

    /**
     * Calculate the L function: L(x) = (x - 1) / n
     * Used in Paillier decryption
     */
    static L(x, n) {
        return (x - 1n) / n;
    }

    /**
     * Convert BigInt to hex string for display
     */
    static toHex(n) {
        return '0x' + n.toString(16);
    }

    /**
     * Convert hex string to BigInt
     */
    static fromHex(hex) {
        return BigInt(hex);
    }

    /**
     * Get bit length of a BigInt
     */
    static bitLength(n) {
        return n.toString(2).length;
    }

    /**
     * Check if a number is a perfect square
     */
    static isPerfectSquare(n) {
        if (n < 0n) return false;
        if (n === 0n || n === 1n) return true;

        let x = n;
        let y = (x + 1n) / 2n;

        while (y < x) {
            x = y;
            y = (x + n / x) / 2n;
        }

        return x * x === n;
    }

    /**
     * Square root of a BigInt (floor)
     */
    static sqrt(n) {
        if (n === 0n) return 0n;

        let x = n;
        let y = (x + 1n) / 2n;

        while (y < x) {
            x = y;
            y = (x + n / x) / 2n;
        }

        return x;
    }
}

// Export for use in other modules
window.BigIntUtils = BigIntUtils;
