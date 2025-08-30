/**
 * Paillier Cryptosystem Implementation
 * Provides homomorphic encryption suitable for voting systems
 */

class PaillierCryptosystem {
    constructor() {
        this.publicKey = null;
        this.privateKey = null;
        this.keySize = 1024; // bits
    }

    /**
     * Generate a new key pair for Paillier encryption
     */
    generateKeys() {
        console.log('Generating Paillier key pair...');

        // Generate two large primes p and q
        const [p, q] = BigIntUtils.generateTwoPrimes(this.keySize / 2);

        // Compute n = p * q
        const n = p * q;

        // Compute λ = lcm(p-1, q-1) (Carmichael's lambda function)
        const lambda = BigIntUtils.lcm(p - 1n, q - 1n);

        // Choose g = n + 1 (this is a common choice that works well)
        const g = n + 1n;

        // Compute μ = (L(g^λ mod n^2))^-1 mod n
        const nSquared = n * n;
        const gLambda = BigIntUtils.modPow(g, lambda, nSquared);
        const L_g_lambda = BigIntUtils.L(gLambda, n);
        const mu = BigIntUtils.modInverse(L_g_lambda, n);

        // Store keys
        this.publicKey = { n, g, nSquared };
        this.privateKey = { lambda, mu, n };

        console.log('Key generation complete!');
        console.log(`Key size: ${BigIntUtils.bitLength(n)} bits`);
        console.log(`p: ${BigIntUtils.bitLength(p)} bits`);
        console.log(`q: ${BigIntUtils.bitLength(q)} bits`);

        return {
            public: this.publicKey,
            private: this.privateKey
        };
    }

    /**
     * Encrypt a plaintext message
     * @param {bigint} plaintext - The message to encrypt (must be < n)
     * @param {object} publicKey - The public key {n, g, nSquared}
     * @returns {bigint} The encrypted ciphertext
     */
    encrypt(plaintext, publicKey = null) {
        const pubKey = publicKey || this.publicKey;
        if (!pubKey) {
            throw new Error('No public key available for encryption');
        }

        const { n, g, nSquared } = pubKey;

        // Ensure plaintext is in valid range
        if (plaintext < 0n || plaintext >= n) {
            throw new Error('Plaintext must be in range [0, n)');
        }

        // Generate random r where 1 < r < n and gcd(r, n) = 1
        let r;
        do {
            r = BigIntUtils.randomRange(1n, n);
        } while (!BigIntUtils.areCoprime(r, n));

        // Compute ciphertext: c = g^m * r^n mod n^2
        const gPowM = BigIntUtils.modPow(g, plaintext, nSquared);
        const rPowN = BigIntUtils.modPow(r, n, nSquared);
        const ciphertext = (gPowM * rPowN) % nSquared;

        return {
            ciphertext,
            randomness: r // Store for potential ZKP use
        };
    }

    /**
     * Decrypt a ciphertext message
     * @param {bigint} ciphertext - The encrypted message
     * @param {object} privateKey - The private key {lambda, mu, n}
     * @returns {bigint} The decrypted plaintext
     */
    decrypt(ciphertext, privateKey = null) {
        const privKey = privateKey || this.privateKey;
        if (!privKey) {
            throw new Error('No private key available for decryption');
        }

        const { lambda, mu, n } = privKey;
        const nSquared = n * n;

        // Compute c^λ mod n^2
        const cLambda = BigIntUtils.modPow(ciphertext, lambda, nSquared);

        // Apply L function: L(c^λ mod n^2)
        const L_c_lambda = BigIntUtils.L(cLambda, n);

        // Compute plaintext: m = L(c^λ mod n^2) * μ mod n
        const plaintext = (L_c_lambda * mu) % n;

        return plaintext;
    }

    /**
     * Homomorphic addition of two ciphertexts
     * Enc(m1) * Enc(m2) = Enc(m1 + m2)
     */
    addCiphertexts(c1, c2, publicKey = null) {
        const pubKey = publicKey || this.publicKey;
        if (!pubKey) {
            throw new Error('No public key available');
        }

        const { nSquared } = pubKey;
        return (c1 * c2) % nSquared;
    }

    /**
     * Homomorphic scalar multiplication
     * Enc(m)^k = Enc(k * m)
     */
    scalarMultiply(ciphertext, scalar, publicKey = null) {
        const pubKey = publicKey || this.publicKey;
        if (!pubKey) {
            throw new Error('No public key available');
        }

        const { nSquared } = pubKey;
        return BigIntUtils.modPow(ciphertext, scalar, nSquared);
    }

    /**
     * Compute homomorphic sum of multiple ciphertexts
     */
    sumCiphertexts(ciphertexts, publicKey = null) {
        if (ciphertexts.length === 0) {
            throw new Error('Cannot sum empty array of ciphertexts');
        }

        const pubKey = publicKey || this.publicKey;
        if (!pubKey) {
            throw new Error('No public key available');
        }

        const { nSquared } = pubKey;

        let result = ciphertexts[0];
        for (let i = 1; i < ciphertexts.length; i++) {
            result = (result * ciphertexts[i]) % nSquared;
        }

        return result;
    }

    /**
     * Verify that a ciphertext is valid (i.e., in the correct range)
     */
    isValidCiphertext(ciphertext, publicKey = null) {
        const pubKey = publicKey || this.publicKey;
        if (!pubKey) return false;

        const { nSquared } = pubKey;
        return ciphertext > 0n && ciphertext < nSquared;
    }

    /**
     * Get the current public key in a serializable format
     */
    getPublicKeyInfo() {
        if (!this.publicKey) return null;

        return {
            n: this.publicKey.n.toString(),
            g: this.publicKey.g.toString(),
            nSquared: this.publicKey.nSquared.toString(),
            bitLength: BigIntUtils.bitLength(this.publicKey.n)
        };
    }

    /**
     * Get the current private key in a serializable format
     */
    getPrivateKeyInfo() {
        if (!this.privateKey) return null;

        return {
            lambda: this.privateKey.lambda.toString(),
            mu: this.privateKey.mu.toString(),
            n: this.privateKey.n.toString(),
            bitLength: BigIntUtils.bitLength(this.privateKey.n)
        };
    }

    /**
     * Clear all keys from memory
     */
    clearKeys() {
        this.publicKey = null;
        this.privateKey = null;
        console.log('Keys cleared from memory');
    }

    /**
     * Test the cryptosystem with sample data
     */
    selfTest() {
        console.log('Running Paillier self-test...');

        // Generate keys
        this.generateKeys();

        // Test basic encryption/decryption
        const testValues = [0n, 1n, 42n, 100n];

        for (const value of testValues) {
            const encrypted = this.encrypt(value);
            const decrypted = this.decrypt(encrypted.ciphertext);

            if (decrypted !== value) {
                throw new Error(`Self-test failed: ${value} != ${decrypted}`);
            }

            console.log(`✓ Encrypt/decrypt test passed for value: ${value}`);
        }

        // Test homomorphic addition
        const a = 5n;
        const b = 7n;
        const encA = this.encrypt(a);
        const encB = this.encrypt(b);
        const encSum = this.addCiphertexts(encA.ciphertext, encB.ciphertext);
        const decryptedSum = this.decrypt(encSum);

        if (decryptedSum !== (a + b)) {
            throw new Error(`Homomorphic addition failed: ${decryptedSum} != ${a + b}`);
        }

        console.log(`✓ Homomorphic addition test passed: ${a} + ${b} = ${decryptedSum}`);

        // Test scalar multiplication
        const scalar = 3n;
        const encScalar = this.scalarMultiply(encA.ciphertext, scalar);
        const decryptedScalar = this.decrypt(encScalar);

        if (decryptedScalar !== (a * scalar)) {
            throw new Error(`Scalar multiplication failed: ${decryptedScalar} != ${a * scalar}`);
        }

        console.log(`✓ Scalar multiplication test passed: ${a} * ${scalar} = ${decryptedScalar}`);

        console.log('All Paillier self-tests passed!');
        return true;
    }
}

// Export for use in other modules
window.PaillierCryptosystem = PaillierCryptosystem;
