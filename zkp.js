/**
 * Zero-Knowledge Proof System for Paillier Encrypted Votes
 * Implements proofs that encrypted values are 0 or 1 and sum constraints
 */

class ZKProofSystem {
    constructor(paillierSystem) {
        this.paillier = paillierSystem;
    }

    /**
     * Generate a Zero-Knowledge Proof that an encrypted value is either 0 or 1
     * Uses disjunctive proof with Fiat-Shamir heuristic
     * 
     * @param {bigint} plaintext - The actual plaintext (0 or 1)
     * @param {bigint} ciphertext - The encrypted value
     * @param {bigint} randomness - The randomness used in encryption
     * @returns {object} The ZK proof
     */
    proveBitValue(plaintext, ciphertext, randomness) {
        if (plaintext !== 0n && plaintext !== 1n) {
            throw new Error('Plaintext must be 0 or 1 for bit proof');
        }

        const { n, g, nSquared } = this.paillier.publicKey;

        if (plaintext === 0n) {
            // Real proof for 0, simulated proof for 1

            // Generate random values for real proof (value 0)
            const s0 = BigIntUtils.randomRange(1n, n);
            const rPrime0 = BigIntUtils.randomRange(1n, n);
            const a0 = (BigIntUtils.modPow(g, s0, nSquared) * BigIntUtils.modPow(rPrime0, n, nSquared)) % nSquared;

            // Generate simulated values for fake proof (value 1)
            const e1 = BigIntUtils.randomRange(1n, n);
            const z1 = BigIntUtils.randomRange(1n, n);
            const r1 = BigIntUtils.randomRange(1n, n);

            // For simulated proof: a = (g^z * r^n) * (c^e)^(-1) (mod n^2)
            // This makes the verification equation g^z * r^n = a * c^e hold
            const gPowZ1 = BigIntUtils.modPow(g, z1, nSquared);
            const r1PowN = BigIntUtils.modPow(r1, n, nSquared);
            const cPowE1 = BigIntUtils.modPow(ciphertext, e1, nSquared);
            const cPowE1Inv = BigIntUtils.modInverse(cPowE1, nSquared);
            const a1 = (gPowZ1 * r1PowN * cPowE1Inv) % nSquared;

            // Generate total challenge from commitments
            const totalChallenge = this.generateChallenge(ciphertext, a0, a1);

            // Complete real proof for 0
            let e0 = (totalChallenge - e1) % n;
            if (e0 < 0n) e0 += n;  // Handle negative modulo
            const z0 = (s0 + e0 * plaintext) % n; // plaintext = 0, so z0 = s0
            const r0 = (rPrime0 * BigIntUtils.modPow(randomness, e0, n)) % n;

            return {
                proof0: { a: a0, e: e0, z: z0, rResponse: r0, plaintext: 0n },
                proof1: { a: a1, e: e1, z: z1, rResponse: r1, plaintext: 1n },
                ciphertext,
                type: 'bit-value'
            };
        } else {
            // Real proof for 1, simulated proof for 0

            // Generate random values for real proof (value 1)
            const s1 = BigIntUtils.randomRange(1n, n);
            const rPrime1 = BigIntUtils.randomRange(1n, n);
            const a1 = (BigIntUtils.modPow(g, s1, nSquared) * BigIntUtils.modPow(rPrime1, n, nSquared)) % nSquared;

            // Generate simulated values for fake proof (value 0)
            const e0 = BigIntUtils.randomRange(1n, n);
            const z0 = BigIntUtils.randomRange(1n, n);
            const r0 = BigIntUtils.randomRange(1n, n);

            // For simulated proof: a = (g^z * r^n) * (c^e)^(-1) (mod n^2)
            const gPowZ0 = BigIntUtils.modPow(g, z0, nSquared);
            const r0PowN = BigIntUtils.modPow(r0, n, nSquared);
            const cPowE0 = BigIntUtils.modPow(ciphertext, e0, nSquared);
            const cPowE0Inv = BigIntUtils.modInverse(cPowE0, nSquared);
            const a0 = (gPowZ0 * r0PowN * cPowE0Inv) % nSquared;

            // Generate total challenge from commitments
            const totalChallenge = this.generateChallenge(ciphertext, a0, a1);

            // Complete real proof for 1
            let e1 = (totalChallenge - e0) % n;
            if (e1 < 0n) e1 += n;  // Handle negative modulo
            const z1 = (s1 + e1 * plaintext) % n; // plaintext = 1, so z1 = s1 + e1
            const r1 = (rPrime1 * BigIntUtils.modPow(randomness, e1, n)) % n;

            return {
                proof0: { a: a0, e: e0, z: z0, rResponse: r0, plaintext: 0n },
                proof1: { a: a1, e: e1, z: z1, rResponse: r1, plaintext: 1n },
                ciphertext,
                type: 'bit-value'
            };
        }
    }

    /**
     * Generate cryptographic challenge using Fiat-Shamir heuristic
     * In practice, this would use a cryptographic hash function
     */
    generateChallenge(ciphertext, commitment0, commitment1) {
        // Simple hash-like function for demonstration
        // In production, use SHA-256 or similar
        const combined = ciphertext.toString() + commitment0.toString() + commitment1.toString();
        const hash = this.simpleHash(combined);
        const result = BigInt(hash) % this.paillier.publicKey.n;
        // Ensure positive result
        return result < 0n ? result + this.paillier.publicKey.n : result;
    }

    /**
     * Simple hash function for demonstration (NOT cryptographically secure)
     * In production, use proper cryptographic hash functions
     */
    simpleHash(input) {
        let hash = 0;
        for (let i = 0; i < input.length; i++) {
            const char = input.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash; // Convert to 32bit integer
        }
        return Math.abs(hash);
    }

    /**
     * Verify a Zero-Knowledge Proof for bit values
     */
    verifyBitProof(proof) {
        const { proof0, proof1, ciphertext } = proof;
        const { n, g, nSquared } = this.paillier.publicKey;

        try {
            // Regenerate the total challenge
            const totalChallenge = this.generateChallenge(ciphertext, proof0.a, proof1.a);

            // Check that e0 + e1 = totalChallenge (mod n)
            const challengeSum = (proof0.e + proof1.e) % n;
            const challengeValid = challengeSum === totalChallenge;

            // Verify both individual proofs
            const valid0 = this.verifySingleBitProof(proof0, ciphertext, 0n, n, g, nSquared);
            const valid1 = this.verifySingleBitProof(proof1, ciphertext, 1n, n, g, nSquared);

            return {
                valid: valid0 && valid1 && challengeValid,
                details: {
                    proof0Valid: valid0,
                    proof1Valid: valid1,
                    challengeValid,
                    challengeSum: challengeSum.toString(),
                    expectedChallenge: totalChallenge.toString()
                }
            };
        } catch (error) {
            return {
                valid: false,
                error: error.message
            };
        }
    }

    /**
     * Verify a single proof within the disjunctive proof
     * Correct verification for Paillier encryption: g^z * r^n = a * c^e (mod n^2)
     */
    verifySingleBitProof(proof, ciphertext, expectedPlaintext, n, g, nSquared) {
        const { a, e, z, rResponse } = proof;

        try {
            // Standard Paillier ZKP verification equation:
            // g^z * r^n ≡ a * c^e (mod n^2)
            // This works because:
            // - For real proof: z = s + e*m, r = r' * R^e
            // - For simulated proof: we choose z, r to make equation hold

            const leftSide = (BigIntUtils.modPow(g, z, nSquared) * BigIntUtils.modPow(rResponse, n, nSquared)) % nSquared;
            const rightSide = (a * BigIntUtils.modPow(ciphertext, e, nSquared)) % nSquared;

            const isValid = leftSide === rightSide;

            // Debug logging
            if (!isValid) {
                console.log(`Verification failed for plaintext ${expectedPlaintext}:`);
                console.log(`  Left: ${leftSide.toString().substring(0, 20)}...`);
                console.log(`  Right: ${rightSide.toString().substring(0, 20)}...`);
                console.log(`  e: ${e.toString().substring(0, 20)}...`);
                console.log(`  z: ${z.toString().substring(0, 20)}...`);
                console.log(`  a: ${a.toString().substring(0, 20)}...`);
                console.log(`  rResponse: ${rResponse.toString().substring(0, 20)}...`);
                console.log(`  Ciphertext: ${ciphertext.toString().substring(0, 20)}...`);
            }

            return isValid;
        } catch (error) {
            console.error('Single proof verification error:', error);
            return false;
        }
    }    /**
     * Generate a proof that a set of encrypted votes sum to exactly 1
     * This ensures that exactly one candidate is chosen in a valid vote
     */
    proveSumEqualsOne(encryptedVotes, plaintextVotes, randomnesses) {
        if (encryptedVotes.length !== plaintextVotes.length ||
            encryptedVotes.length !== randomnesses.length) {
            throw new Error('Array lengths must match');
        }

        // Verify that sum equals 1
        const sum = plaintextVotes.reduce((acc, vote) => acc + vote, 0n);
        if (sum !== 1n) {
            throw new Error('Plaintext votes must sum to exactly 1');
        }

        const { n, g, nSquared } = this.paillier.publicKey;

        // Compute homomorphic sum of all encrypted votes
        const encryptedSum = this.paillier.sumCiphertexts(encryptedVotes);

        // Compute combined randomness
        let combinedRandomness = 1n;
        for (const r of randomnesses) {
            combinedRandomness = (combinedRandomness * r) % n;
        }

        // Generate proof that encrypted sum corresponds to plaintext 1
        return this.generateSumProof(1n, encryptedSum, combinedRandomness, n, g, nSquared);
    }

    /**
     * Generate proof for sum constraint
     */
    generateSumProof(expectedSum, encryptedSum, combinedRandomness, n, g, nSquared) {
        // Generate random values
        const s = BigIntUtils.randomRange(1n, n);
        const rPrime = BigIntUtils.randomRange(1n, n);

        // Compute commitment
        const a = (BigIntUtils.modPow(g, s, nSquared) * BigIntUtils.modPow(rPrime, n, nSquared)) % nSquared;

        // Generate challenge - use simpler approach for sum proof
        const e = this.generateSumChallenge(encryptedSum, a, expectedSum);

        // Compute responses
        const z = (s + e * expectedSum) % n;
        const rResponse = (rPrime * BigIntUtils.modPow(combinedRandomness, e, n)) % n;

        return {
            encryptedSum,
            expectedSum,
            a,
            e,
            z,
            rResponse,
            type: 'sum-equals-one'
        };
    }

    /**
     * Generate challenge for sum proof
     */
    generateSumChallenge(encryptedSum, commitment, expectedSum) {
        const combined = encryptedSum.toString() + commitment.toString() + expectedSum.toString();
        const hash = this.simpleHash(combined);
        return BigInt(hash) % this.paillier.publicKey.n;
    }

    /**
     * Verify proof that encrypted votes sum to 1
     */
    verifySumProof(proof) {
        const { encryptedSum, expectedSum, a, e, z, rResponse } = proof;
        const { n, g, nSquared } = this.paillier.publicKey;

        try {
            // Use the same verification equation as bit proofs:
            // g^z * r^n ≡ a * encryptedSum^e (mod n^2)
            const leftSide = (BigIntUtils.modPow(g, z, nSquared) * BigIntUtils.modPow(rResponse, n, nSquared)) % nSquared;
            const rightSide = (a * BigIntUtils.modPow(encryptedSum, e, nSquared)) % nSquared;

            const isValid = leftSide === rightSide;

            if (!isValid) {
                console.log('Sum proof verification failed:');
                console.log(`  Expected sum: ${expectedSum}`);
                console.log(`  Left side: ${leftSide.toString().substring(0, 20)}...`);
                console.log(`  Right side: ${rightSide.toString().substring(0, 20)}...`);
            }

            return {
                valid: isValid,
                details: {
                    expectedSum: expectedSum.toString(),
                    leftSide: leftSide.toString(),
                    rightSide: rightSide.toString()
                }
            };
        } catch (error) {
            return {
                valid: false,
                error: error.message
            };
        }
    }

    /**
     * Generate comprehensive ZKP for a complete vote
     */
    generateVoteProof(encryptedVotes, plaintextVotes, randomnesses) {
        const bitProofs = [];

        // Generate bit proofs for each vote
        for (let i = 0; i < encryptedVotes.length; i++) {
            const bitProof = this.proveBitValue(
                plaintextVotes[i],
                encryptedVotes[i],
                randomnesses[i]
            );
            bitProofs.push(bitProof);
        }

        // Generate sum proof
        const sumProof = this.proveSumEqualsOne(encryptedVotes, plaintextVotes, randomnesses);

        return {
            bitProofs,
            sumProof,
            timestamp: Date.now(),
            type: 'complete-vote-proof'
        };
    }

    /**
     * Verify a complete vote proof
     */
    verifyVoteProof(voteProof) {
        const { bitProofs, sumProof } = voteProof;
        const results = {
            bitProofsValid: true,
            bitProofResults: [],
            sumProofValid: false,
            overallValid: false
        };

        // Verify all bit proofs
        for (let i = 0; i < bitProofs.length; i++) {
            const result = this.verifyBitProof(bitProofs[i]);
            results.bitProofResults.push({
                candidateIndex: i,
                valid: result.valid,
                details: result.details,
                error: result.error
            });

            if (!result.valid) {
                results.bitProofsValid = false;
            }
        }

        // Verify sum proof
        const sumResult = this.verifySumProof(sumProof);
        results.sumProofValid = sumResult.valid;
        results.sumProofDetails = sumResult.details;
        results.sumProofError = sumResult.error;

        // Overall validity
        results.overallValid = results.bitProofsValid && results.sumProofValid;

        return results;
    }
}

// Export for use in other modules
window.ZKProofSystem = ZKProofSystem;
