# Paillier Encryption Voting System with Zero-Knowledge Proofs

A secure, client-side voting system implementation using Paillier homomorphic encryption and Zero-Knowledge Proofs (ZKP) for educational and testing purposes.

## 🔐 Features

### Core Cryptographic Components
- **Paillier Homomorphic Encryption**: Allows computation on encrypted data
- **Zero-Knowledge Proofs**: Validates vote integrity without revealing content
- **Client-Side Security**: All operations performed in browser, no external dependencies

### System Capabilities
1. **Key Generation**: Generate cryptographically secure public/private key pairs
2. **Individual Vote Encryption**: Each vote encrypted separately for O(n) efficiency
3. **Zero-Knowledge Proofs**: Proves each vote is 0 or 1, and total sum is valid
4. **Homomorphic Tallying**: Compute results without decrypting individual votes
5. **Privacy Preservation**: Private key only used for final tallying

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend UI   │    │  Paillier Crypto│    │   ZK Proofs     │
│   (HTML/CSS)    │◄──►│   System        │◄──►│   System        │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                        │                        │
         ▼                        ▼                        ▼
┌─────────────────────────────────────────────────────────────────┐
│                    BigInt Utilities                            │
│         (Prime Generation, Modular Arithmetic, etc.)           │
└─────────────────────────────────────────────────────────────────┘
```

## 📁 File Structure

```
voting/
├── index.html          # Main user interface
├── bigint-utils.js     # Mathematical utilities for large numbers
├── paillier.js         # Paillier cryptosystem implementation
├── zkp.js              # Zero-Knowledge Proof system
├── voting-system.js    # Main application logic
└── README.md           # This documentation
```

## 🚀 Getting Started

1. **Open the Application**
   ```bash
   # Navigate to the voting directory
   cd voting
   
   # Open in a web browser
   # Double-click index.html or serve via local web server
   ```

2. **Generate Keys**
   - Click "Generate New Key Pair" to create cryptographic keys
   - Keys are displayed in the interface (truncated for security)

3. **Cast Test Votes**
   - Select one or more candidates (multiple selections for testing ZKP)
   - Click "Encrypt Votes & Generate ZKPs"

4. **Verify Proofs**
   - Click "Verify All ZKPs" to validate Zero-Knowledge Proofs
   - System verifies each vote is 0 or 1 and total sum is valid

5. **Tally Results**
   - Click "Decrypt & Tally Results" to compute final results
   - ⚠️ This uses the private key and should only be done by authorities

## 🔬 Cryptographic Details

### Paillier Encryption
- **Key Size**: 1024 bits (configurable)
- **Security**: Based on composite residuosity assumption
- **Homomorphic Property**: E(m₁) × E(m₂) = E(m₁ + m₂)

### Zero-Knowledge Proofs
- **Bit Proofs**: Proves encrypted value is 0 or 1 using disjunctive proofs
- **Sum Proofs**: Proves total encrypted votes sum to valid amount
- **Fiat-Shamir Heuristic**: Non-interactive proof generation

### Security Properties
- **Privacy**: Individual votes remain encrypted
- **Verifiability**: Anyone can verify vote validity without decryption
- **Correctness**: Homomorphic tallying ensures accurate results
- **Integrity**: ZKPs prevent invalid votes

## 🧪 Testing Scenarios

### Valid Vote Testing
1. Select exactly one candidate → Should pass all proofs
2. Multiple candidates → Tests ZKP system with invalid sum

### Invalid Vote Detection
1. No candidates selected → System prevents encryption
2. Modified ciphertexts → ZKP verification will fail

### Homomorphic Properties
1. Individual decryption matches selections
2. Homomorphic sum equals individual vote total

## ⚙️ Technical Implementation

### Mathematical Operations
```javascript
// Key Generation
n = p × q  (where p, q are large primes)
λ = lcm(p-1, q-1)
g = n + 1
μ = (L(g^λ mod n²))^(-1) mod n

// Encryption
c = g^m × r^n mod n²

// Decryption
m = L(c^λ mod n²) × μ mod n
```

### Zero-Knowledge Proof Structure
```javascript
// Bit Proof (0 or 1)
{
  proof0: { a, e, z, rResponse },  // Real or simulated
  proof1: { a, e, z, rResponse }   // Real or simulated
}

// Sum Proof
{
  encryptedSum: homomorphic_sum(ciphertexts),
  proof: { a, e, z, rResponse }
}
```

## 🔒 Security Considerations

### Production Deployment
- [ ] Use cryptographically secure random number generation
- [ ] Implement proper hash functions (SHA-256) for Fiat-Shamir
- [ ] Add timing attack protections
- [ ] Implement secure key storage and distribution
- [ ] Add audit logging and monitoring

### Current Limitations
- Simplified hash function (for demonstration)
- No network security (client-side only)
- Limited key sizes (for performance)
- Basic UI (focused on cryptographic functionality)

## 📊 Performance Characteristics

### Time Complexity
- **Key Generation**: O(k × log³(n)) where k is prime testing rounds
- **Encryption**: O(log³(n)) per vote
- **ZKP Generation**: O(log³(n)) per proof
- **Verification**: O(log³(n)) per proof
- **Decryption**: O(log³(n)) per ciphertext

### Space Complexity
- **Keys**: O(log(n))
- **Ciphertexts**: O(log(n)) per vote
- **Proofs**: O(log(n)) per proof

## 🎯 Use Cases

### Educational
- Cryptography course demonstrations
- Voting system security research
- Homomorphic encryption tutorials

### Research & Development
- ZKP system prototyping
- Voting protocol testing
- Privacy-preserving computation studies

### Production Considerations
- Electronic voting systems
- Private auction mechanisms
- Confidential surveys and polls

## 📚 References

1. **Paillier Cryptosystem**: Paillier, Pascal (1999). "Public-Key Cryptosystems Based on Composite Degree Residuosity Classes"
2. **Zero-Knowledge Proofs**: Goldwasser, Micali, Rackoff (1985). "The Knowledge Complexity of Interactive Proof-Systems"
3. **Fiat-Shamir Heuristic**: Fiat, Shamir (1986). "How to Prove Yourself: Practical Solutions to Identification and Signature Problems"

## 🤝 Contributing

This is an educational implementation. For production use, consider:
- Professional cryptographic library integration
- Security audit and penetration testing
- Performance optimization for scale
- Compliance with voting regulations

## ⚠️ Disclaimer

This implementation is for **educational and testing purposes only**. Do not use in production voting systems without proper security review, audit, and compliance verification.

---

**Built with**: Pure JavaScript, HTML5, CSS3
**Dependencies**: None (all crypto implemented locally)
**Browser Support**: Modern browsers with BigInt support
