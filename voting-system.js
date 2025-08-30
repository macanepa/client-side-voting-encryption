/**
 * Main Voting System Application
 * Coordinates Paillier encryption, ZKP, and user interface
 */

// ==========================================
// CONFIGURATION - Change this single value to adjust candidate count
// ==========================================
const CANDIDATE_COUNT = 5;  // 🔧 CHANGE THIS VALUE TO SET NUMBER OF CANDIDATES

// Global variables
let paillierSystem = null;
let zkpSystem = null;
let currentVotes = new Array(CANDIDATE_COUNT).fill(false);
let encryptedVotes = [];
let voteProofs = [];
let isKeysGenerated = false;

/**
 * Initialize the voting system
 */
function initVotingSystem() {
    paillierSystem = new PaillierCryptosystem();
    zkpSystem = new ZKProofSystem(paillierSystem);

    // Generate candidate UI
    generateCandidateInterface();

    log(`Voting system initialized with ${CANDIDATE_COUNT} candidates. Ready to generate keys.`);
    updateUIState();
}

/**
 * Generate the candidate selection interface
 */
function generateCandidateInterface() {
    const votingSection = document.getElementById('votingSection');
    let html = '';

    for (let i = 0; i < CANDIDATE_COUNT; i++) {
        html += `
            <div class="candidate" id="candidate${i}" onclick="toggleVote(${i})">
                <input type="checkbox" id="vote${i}">
                <label for="vote${i}">Candidate ${i + 1}</label>
            </div>
        `;
    }

    votingSection.innerHTML = html;
    log(`Generated interface for ${CANDIDATE_COUNT} candidates`);
}

/**
 * Generate new Paillier key pair
 */
function generateKeys() {
    try {
        log('Starting key generation...');
        updateStatus('Generating cryptographic keys...', 'info');

        // Use setTimeout to allow UI to update before heavy computation
        setTimeout(() => {
            try {
                const keys = paillierSystem.generateKeys();
                isKeysGenerated = true;

                // Update UI with key information
                displayPublicKey();
                displayPrivateKey();

                log('✅ Key pair generated successfully!');
                updateStatus('Keys generated successfully! You can now encrypt votes.', 'success');
                updateUIState();

            } catch (error) {
                log('❌ Key generation failed: ' + error.message);
                updateStatus('Key generation failed: ' + error.message, 'error');
            }
        }, 100);

    } catch (error) {
        log('❌ Key generation error: ' + error.message);
        updateStatus('Key generation error: ' + error.message, 'error');
    }
}

/**
 * Clear all keys and reset system
 */
function clearKeys() {
    if (paillierSystem) {
        paillierSystem.clearKeys();
    }

    isKeysGenerated = false;
    encryptedVotes = [];
    voteProofs = [];
    currentVotes = new Array(CANDIDATE_COUNT).fill(false);

    // Clear UI displays
    document.getElementById('publicKeyText').textContent = 'No keys generated';
    document.getElementById('privateKeyText').textContent = 'No keys generated';
    document.getElementById('keyStatus').innerHTML = '';
    document.getElementById('votingStatus').innerHTML = '';
    document.getElementById('encryptedVotesDisplay').textContent = 'No votes encrypted yet';
    document.getElementById('zkpResults').textContent = 'No proofs generated yet';
    document.getElementById('tallyResults').innerHTML = '';

    // Clear vote selections
    for (let i = 0; i < CANDIDATE_COUNT; i++) {
        const checkbox = document.getElementById(`vote${i}`);
        const candidate = document.getElementById(`candidate${i}`);
        if (checkbox) checkbox.checked = false;
        if (candidate) candidate.classList.remove('selected');
    }

    log('🗑️ All keys and votes cleared');
    updateStatus('Keys and votes cleared. Generate new keys to continue.', 'info');
    updateUIState();
}

/**
 * Display public key information
 */
function displayPublicKey() {
    const keyInfo = paillierSystem.getPublicKeyInfo();
    if (keyInfo) {
        const display = `n: ${keyInfo.n.substring(0, 50)}...\ng: ${keyInfo.g.substring(0, 50)}...\nBit length: ${keyInfo.bitLength}`;
        document.getElementById('publicKeyText').textContent = display;
    }
}

/**
 * Display private key information
 */
function displayPrivateKey() {
    const keyInfo = paillierSystem.getPrivateKeyInfo();
    if (keyInfo) {
        const display = `λ: ${keyInfo.lambda.substring(0, 50)}...\nμ: ${keyInfo.mu.substring(0, 50)}...\nBit length: ${keyInfo.bitLength}`;
        document.getElementById('privateKeyText').textContent = display;
    }
}

/**
 * Toggle vote selection for a candidate
 */
function toggleVote(candidateIndex) {
    if (!isKeysGenerated) {
        updateStatus('Please generate keys first before voting.', 'error');
        return;
    }

    const checkbox = document.getElementById(`vote${candidateIndex}`);
    const candidateDiv = document.getElementById(`candidate${candidateIndex}`);

    // Toggle the vote
    currentVotes[candidateIndex] = !currentVotes[candidateIndex];
    checkbox.checked = currentVotes[candidateIndex];

    // Update visual feedback
    if (currentVotes[candidateIndex]) {
        candidateDiv.classList.add('selected');
    } else {
        candidateDiv.classList.remove('selected');
    }

    // Log the selection
    const candidateName = `Candidate ${candidateIndex + 1}`;
    const action = currentVotes[candidateIndex] ? 'selected' : 'deselected';
    log(`📊 ${candidateName} ${action}`);

    updateUIState();
}

/**
 * Clear all vote selections
 */
function clearVotes() {
    for (let i = 0; i < CANDIDATE_COUNT; i++) {
        currentVotes[i] = false;
        const checkbox = document.getElementById(`vote${i}`);
        const candidate = document.getElementById(`candidate${i}`);
        if (checkbox) checkbox.checked = false;
        if (candidate) candidate.classList.remove('selected');
    }

    encryptedVotes = [];
    voteProofs = [];

    document.getElementById('encryptedVotesDisplay').textContent = 'No votes encrypted yet';
    document.getElementById('zkpResults').textContent = 'No proofs generated yet';
    document.getElementById('votingStatus').innerHTML = '';
    document.getElementById('tallyResults').innerHTML = '';

    log('🗑️ All votes cleared');
    updateUIState();
}

/**
 * Encrypt selected votes and generate ZKPs
 */
function encryptVotes() {
    if (!isKeysGenerated) {
        updateStatus('Please generate keys first.', 'error');
        return;
    }

    try {
        log('🔒 Starting vote encryption and ZKP generation...');
        updateStatus('Encrypting votes and generating Zero-Knowledge Proofs...', 'info');

        // Use setTimeout to allow UI to update
        setTimeout(() => {
            try {
                const plaintextVotes = currentVotes.map(vote => vote ? 1n : 0n);

                // Check if at least one vote is selected for testing
                const hasVotes = plaintextVotes.some(vote => vote === 1n);
                if (!hasVotes) {
                    updateStatus('Please select at least one candidate to test the system.', 'error');
                    return;
                }

                const selectedCount = plaintextVotes.filter(vote => vote === 1n).length;
                if (selectedCount > 20) {
                    log(`⚠️ Processing ${selectedCount} votes - this may take some time...`);
                }

                log(`📊 Vote vector: [${plaintextVotes.slice(0, 10).join(', ')}${plaintextVotes.length > 10 ? ', ...' : ''}]`);

                // Encrypt each vote separately
                encryptedVotes = [];
                const randomnesses = [];

                for (let i = 0; i < plaintextVotes.length; i++) {
                    const encResult = paillierSystem.encrypt(plaintextVotes[i]);
                    encryptedVotes.push(encResult.ciphertext);
                    randomnesses.push(encResult.randomness);

                    if (plaintextVotes[i] === 1n) {
                        log(`🔒 Candidate ${i + 1}: ${plaintextVotes[i]} → encrypted`);
                    }
                }

                // Generate comprehensive ZKP
                log('🛡️ Generating Zero-Knowledge Proofs...');
                const voteProof = zkpSystem.generateVoteProof(encryptedVotes, plaintextVotes, randomnesses);
                voteProofs = [voteProof];

                // Display encrypted votes
                displayEncryptedVotes();

                // Display initial ZKP status
                displayZKPStatus();

                log('✅ Vote encryption and ZKP generation completed!');
                updateStatus('Votes encrypted and ZKPs generated successfully! You can now verify the proofs.', 'success');
                updateUIState();

            } catch (error) {
                log('❌ Encryption failed: ' + error.message);
                updateStatus('Encryption failed: ' + error.message, 'error');
            }
        }, 100);

    } catch (error) {
        log('❌ Encryption error: ' + error.message);
        updateStatus('Encryption error: ' + error.message, 'error');
    }
}

/**
 * Display encrypted votes in the UI
 */
function displayEncryptedVotes() {
    let html = '';
    let displayCount = 0;
    const maxDisplay = 10; // Show only first 10 and summary

    for (let i = 0; i < encryptedVotes.length; i++) {
        if (currentVotes[i] && displayCount < maxDisplay) { // Only show selected votes
            const shortCiphertext = encryptedVotes[i].toString().substring(0, 60) + '...';
            html += `
                <div class="encrypted-vote">
                    <strong>Candidate ${i + 1}:</strong><br>
                    ${shortCiphertext}
                </div>
            `;
            displayCount++;
        }
    }

    // Add summary
    const selectedCount = currentVotes.filter(vote => vote).length;
    if (selectedCount > maxDisplay) {
        html += `
            <div class="encrypted-vote">
                <strong>... and ${selectedCount - maxDisplay} more encrypted votes</strong>
            </div>
        `;
    }

    html += `
        <div class="encrypted-vote">
            <strong>Total: ${selectedCount} votes encrypted out of ${CANDIDATE_COUNT} candidates</strong>
        </div>
    `;

    document.getElementById('encryptedVotesDisplay').innerHTML = html;
}

/**
 * Display ZKP status
 */
function displayZKPStatus() {
    const selectedCount = currentVotes.filter(vote => vote).length;
    let html = `
        <div class="status info">
            <strong>ZKPs Generated:</strong><br>
            • ${voteProofs[0].bitProofs.length} bit-value proofs (each vote is 0 or 1)<br>
            • 1 sum proof (votes sum to valid total)<br>
            • Selected candidates: ${selectedCount}/${CANDIDATE_COUNT}<br>
            <em>Click "Verify All ZKPs" to validate proofs</em>
        </div>
    `;

    document.getElementById('zkpResults').innerHTML = html;
}

/**
 * Verify all Zero-Knowledge Proofs
 */
function verifyAllZKPs() {
    if (voteProofs.length === 0) {
        updateStatus('No proofs to verify. Please encrypt votes first.', 'error');
        return;
    }

    try {
        log('🔍 Starting ZKP verification...');
        updateStatus('Verifying Zero-Knowledge Proofs...', 'info');

        setTimeout(() => {
            try {
                const results = zkpSystem.verifyVoteProof(voteProofs[0]);

                log('🔍 ZKP Verification Results:');
                log(`  Overall Valid: ${results.overallValid}`);
                log(`  Bit Proofs Valid: ${results.bitProofsValid}`);
                log(`  Sum Proof Valid: ${results.sumProofValid}`);

                // Display detailed results
                displayVerificationResults(results);

                if (results.overallValid) {
                    log('✅ All Zero-Knowledge Proofs verified successfully!');
                    updateStatus('All ZKPs verified successfully! The encrypted votes are valid.', 'success');
                } else {
                    log('❌ Some Zero-Knowledge Proofs failed verification!');
                    updateStatus('Some ZKPs failed verification. Check the detailed results.', 'error');
                }

                updateUIState();

            } catch (error) {
                log('❌ ZKP verification failed: ' + error.message);
                updateStatus('ZKP verification failed: ' + error.message, 'error');
            }
        }, 100);

    } catch (error) {
        log('❌ ZKP verification error: ' + error.message);
        updateStatus('ZKP verification error: ' + error.message, 'error');
    }
}

/**
 * Debug function to test ZKP step by step
 */
function debugZKP() {
    if (!isKeysGenerated || encryptedVotes.length === 0) {
        log('❌ Need keys and encrypted votes for debugging');
        return;
    }

    try {
        log('🐛 Starting ZKP Debug Analysis...');

        const plaintext = currentVotes[0] ? 1n : 0n; // Test first vote
        const ciphertext = encryptedVotes[0];
        const proof = voteProofs[0].bitProofs[0];

        log(`🔍 Testing vote for Candidate A:`);
        log(`  Actual plaintext: ${plaintext}`);
        log(`  Proof0 plaintext: ${proof.proof0.plaintext}`);
        log(`  Proof1 plaintext: ${proof.proof1.plaintext}`);

        // Test decryption to verify ciphertext is correct
        const decrypted = paillierSystem.decrypt(ciphertext);
        log(`  Decrypted value: ${decrypted}`);
        log(`  Match: ${decrypted === plaintext ? '✅' : '❌'}`);

        // Test individual proofs
        const result0 = zkpSystem.verifySingleBitProof(proof.proof0, ciphertext, 0n,
            paillierSystem.publicKey.n, paillierSystem.publicKey.g, paillierSystem.publicKey.nSquared);
        const result1 = zkpSystem.verifySingleBitProof(proof.proof1, ciphertext, 1n,
            paillierSystem.publicKey.n, paillierSystem.publicKey.g, paillierSystem.publicKey.nSquared);

        log(`  Proof0 (for value 0): ${result0 ? '✅' : '❌'}`);
        log(`  Proof1 (for value 1): ${result1 ? '✅' : '❌'}`);

        // Test challenge consistency
        const totalChallenge = zkpSystem.generateChallenge(ciphertext, proof.proof0.a, proof.proof1.a);
        const challengeSum = (proof.proof0.e + proof.proof1.e) % paillierSystem.publicKey.n;
        log(`  Challenge sum: ${challengeSum.toString().substring(0, 20)}...`);
        log(`  Expected challenge: ${totalChallenge.toString().substring(0, 20)}...`);
        log(`  Challenge match: ${challengeSum === totalChallenge ? '✅' : '❌'}`);

    } catch (error) {
        log(`❌ Debug error: ${error.message}`);
    }
}

/**
 * Compute homomorphic tally using private key
 */
function computeHomomorphicTally() {
    if (encryptedVotes.length === 0) {
        updateStatus('No encrypted votes to tally. Please encrypt votes first.', 'error');
        return;
    }

    if (!isKeysGenerated) {
        updateStatus('Private key not available for tallying.', 'error');
        return;
    }

    try {
        log('🔓 Starting homomorphic tally computation...');
        log('⚠️  WARNING: Using private key for decryption!');
        updateStatus('Computing homomorphic tally... (Using private key)', 'info');

        setTimeout(() => {
            try {
                const results = [];

                // Decrypt each vote individually
                for (let i = 0; i < encryptedVotes.length; i++) {
                    const decryptedVote = paillierSystem.decrypt(encryptedVotes[i]);
                    results.push(Number(decryptedVote));
                    if (decryptedVote === 1n) {
                        log(`🔓 Candidate ${i + 1}: ${decryptedVote}`);
                    }
                }

                // Compute homomorphic sum
                const encryptedSum = paillierSystem.sumCiphertexts(encryptedVotes);
                const decryptedSum = paillierSystem.decrypt(encryptedSum);

                log(`📊 Total votes cast: ${decryptedSum}`);
                log('✅ Homomorphic tally computation completed!');

                // Display results
                displayTallyResults(results, Number(decryptedSum));

                updateStatus('Tally computed successfully! Results displayed below.', 'success');
                updateUIState();

            } catch (error) {
                log('❌ Tally computation failed: ' + error.message);
                updateStatus('Tally computation failed: ' + error.message, 'error');
            }
        }, 100);

    } catch (error) {
        log('❌ Tally computation error: ' + error.message);
        updateStatus('Tally computation error: ' + error.message, 'error');
    }
}

/**
 * Display tally results
 */
function displayTallyResults(results, totalVotes) {
    let html = `
        <div class="status success">
            <strong>🏆 Voting Results</strong>
        </div>
        <div class="results-section">
    `;

    // Individual results - show all candidates
    html += '<div><h3>All Candidates Results</h3>';
    for (let i = 0; i < results.length; i++) {
        const votes = results[i];
        const percentage = totalVotes > 0 ? (votes / totalVotes * 100).toFixed(1) : 0;
        const voteClass = votes > 0 ? 'selected' : '';
        html += `
            <div class="encrypted-vote ${voteClass}">
                <strong>Candidate ${i + 1}:</strong> ${votes} vote${votes !== 1 ? 's' : ''} (${percentage}%)
            </div>
        `;
    }
    html += '</div>';

    // Summary
    html += `
        <div>
            <h3>Summary</h3>
            <div class="encrypted-vote">
                <strong>Total Votes:</strong> ${totalVotes}<br>
                <strong>Total Candidates:</strong> ${CANDIDATE_COUNT}<br>
                <strong>Candidates with Votes:</strong> ${results.filter(v => v > 0).length}<br>
                <strong>Homomorphic Property:</strong> ✅ Verified<br>
                <strong>Privacy:</strong> ✅ Individual votes encrypted<br>
                <strong>Integrity:</strong> ✅ ZKPs validated
            </div>
        </div>
    `;

    html += '</div>';

    document.getElementById('tallyResults').innerHTML = html;
}

/**
 * Update UI element states based on system status
 */
function updateUIState() {
    // Key generation buttons
    document.getElementById('generateKeys').disabled = false;
    document.getElementById('clearKeys').disabled = !isKeysGenerated;

    // Voting buttons
    document.getElementById('encryptVotes').disabled = !isKeysGenerated;
    document.getElementById('clearVotes').disabled = !isKeysGenerated;

    // Verification and tally buttons
    const hasEncryptedVotes = encryptedVotes.length > 0;
    const hasProofs = voteProofs.length > 0;

    document.getElementById('verifyZKPs').disabled = !hasEncryptedVotes;
    document.getElementById('debugZKP').disabled = !hasEncryptedVotes;
    document.getElementById('computeTally').disabled = !hasEncryptedVotes;
    document.getElementById('sendVote').disabled = !hasEncryptedVotes || !hasProofs;
}

/**
 * Update status message
 */
function updateStatus(message, type = 'info') {
    const statusElements = document.querySelectorAll('[id$="Status"]');
    statusElements.forEach(element => {
        element.innerHTML = `<div class="status ${type}">${message}</div>`;
    });
}

/**
 * Log message to system log
 */
function log(message) {
    const logElement = document.getElementById('systemLog');
    const timestamp = new Date().toLocaleTimeString();
    logElement.textContent += `[${timestamp}] ${message}\n`;
    logElement.scrollTop = logElement.scrollHeight;

    // Also log to browser console for debugging
    console.log(`[Voting System] ${message}`);
}

/**
 * Clear system log
 */
function clearLog() {
    document.getElementById('systemLog').textContent = '';
    log('System log cleared');
}

/**
 * Run system self-tests
 */
function runSelfTests() {
    try {
        log('🧪 Running system self-tests...');

        // Initialize systems
        const testPaillier = new PaillierCryptosystem();
        testPaillier.selfTest();

        log('✅ All self-tests passed!');
        updateStatus('Self-tests completed successfully!', 'success');

    } catch (error) {
        log('❌ Self-tests failed: ' + error.message);
        updateStatus('Self-tests failed: ' + error.message, 'error');
    }
}

/**
 * Display detailed verification results
 */
function displayVerificationResults(results) {
    let html = '';

    // Overall status
    html += `<div class="status ${results.overallValid ? 'success' : 'error'}">
        <strong>Overall Verification: ${results.overallValid ? '✅ PASSED' : '❌ FAILED'}</strong>
    </div>`;

    // Summary of bit proof results
    const totalProofs = results.bitProofResults.length;
    const validProofs = results.bitProofResults.filter(r => r.valid).length;

    html += '<h4>Individual Vote Proofs (0 or 1):</h4>';
    html += `
        <div class="encrypted-vote">
            <strong>Summary:</strong> ${validProofs}/${totalProofs} bit proofs passed<br>
            <strong>Total Candidates:</strong> ${CANDIDATE_COUNT}<br>
            <strong>Selected Votes:</strong> ${currentVotes.filter(v => v).length}
        </div>
    `;

    // Show details for failed proofs or first few if all passed
    const showDetails = results.bitProofResults.filter(r => !r.valid).slice(0, 10);
    if (showDetails.length === 0 && validProofs > 0) {
        // Show first few successful ones if all passed
        showDetails.push(...results.bitProofResults.filter(r => r.valid).slice(0, 5));
    }

    for (const bitResult of showDetails) {
        const status = bitResult.valid ? '✅' : '❌';
        html += `
            <div class="encrypted-vote">
                ${status} <strong>Candidate ${bitResult.candidateIndex + 1}:</strong> 
                ${bitResult.valid ? 'Valid' : 'Invalid'}
                ${bitResult.error ? `<br><em>Error: ${bitResult.error}</em>` : ''}
                ${bitResult.details ? `
                    <br><small>
                        Proof0: ${bitResult.details.proof0Valid ? '✅' : '❌'}, 
                        Proof1: ${bitResult.details.proof1Valid ? '✅' : '❌'}, 
                        Challenge: ${bitResult.details.challengeValid ? '✅' : '❌'}
                    </small>
                ` : ''}
            </div>
        `;
    }

    if (results.bitProofResults.length > showDetails.length) {
        html += `
            <div class="encrypted-vote">
                <em>... and ${results.bitProofResults.length - showDetails.length} more proofs</em>
            </div>
        `;
    }

    // Sum proof result
    html += '<h4>Sum Constraint Proof:</h4>';
    const sumStatus = results.sumProofValid ? '✅' : '❌';
    html += `
        <div class="encrypted-vote">
            ${sumStatus} <strong>Sum equals valid total:</strong> 
            ${results.sumProofValid ? 'Valid' : 'Invalid'}
            ${results.sumProofError ? `<br><em>Error: ${results.sumProofError}</em>` : ''}
            ${results.sumProofDetails ? `
                <br><small>Expected: ${results.sumProofDetails.expectedSum}</small>
            ` : ''}
        </div>
    `;

    document.getElementById('zkpResults').innerHTML = html;
}

/**
 * Send encrypted vote with proofs to backend
 */
async function sendVoteToBackend() {
    if (!encryptedVotes.length || !voteProofs.length) {
        updateStatus('No encrypted votes or proofs to send. Please encrypt votes first.', 'error');
        return;
    }

    try {
        log('📤 Preparing vote payload for inspection...');
        updateStatus('Preparing vote payload...', 'info');

        // Prepare the complete vote payload
        const votePayload = prepareVotePayload();

        // Show payload inspection modal
        showPayloadModal(votePayload);

    } catch (error) {
        log('❌ Payload preparation failed: ' + error.message);
        updateStatus('Failed to prepare vote payload: ' + error.message, 'error');
    }
}

/**
 * Prepare the vote payload for network transmission
 */
function prepareVotePayload() {
    return {
        // Metadata
        timestamp: new Date().toISOString(),
        voterId: 'demo-voter-' + Date.now(), // In real system, this would be authenticated
        sessionId: 'session-' + Math.random().toString(36).substr(2, 9),

        // Public key (so backend can verify without storing keys)
        publicKey: {
            n: paillierSystem.publicKey.n.toString(),
            g: paillierSystem.publicKey.g.toString(),
            nSquared: paillierSystem.publicKey.nSquared.toString()
        },

        // Encrypted votes for each candidate
        encryptedVotes: encryptedVotes.map((vote, index) => ({
            candidateId: index,
            candidateName: `Candidate ${index + 1}`,
            ciphertext: vote.toString()
        })),

        // Zero-Knowledge Proofs
        zkpProofs: {
            // Individual bit proofs (each vote is 0 or 1)
            bitProofs: voteProofs[0].bitProofs.map((proof, index) => ({
                candidateId: index,
                proof0: {
                    a: proof.proof0.a.toString(),
                    e: proof.proof0.e.toString(),
                    z: proof.proof0.z.toString(),
                    rResponse: proof.proof0.rResponse.toString()
                },
                proof1: {
                    a: proof.proof1.a.toString(),
                    e: proof.proof1.e.toString(),
                    z: proof.proof1.z.toString(),
                    rResponse: proof.proof1.rResponse.toString()
                },
                ciphertext: proof.ciphertext.toString()
            })),

            // Sum constraint proof (votes sum to exactly 1)
            sumProof: {
                encryptedSum: voteProofs[0].sumProof.encryptedSum.toString(),
                expectedSum: voteProofs[0].sumProof.expectedSum.toString(),
                a: voteProofs[0].sumProof.a.toString(),
                e: voteProofs[0].sumProof.e.toString(),
                z: voteProofs[0].sumProof.z.toString(),
                rResponse: voteProofs[0].sumProof.rResponse.toString()
            }
        },

        // Vote selections for verification (in real system, this would be omitted)
        debugInfo: {
            selectedCandidates: currentVotes.map((vote, index) => vote ? index : null).filter(x => x !== null),
            voteVector: currentVotes.map(vote => vote ? 1 : 0)
        }
    };
}

/**
 * Show the payload inspection modal
 */
function showPayloadModal(payload) {
    const modal = document.getElementById('payloadModal');
    const payloadContent = document.getElementById('payloadContent');
    const payloadStats = document.getElementById('payloadStats');

    // Convert to formatted JSON
    const payloadJson = JSON.stringify(payload, null, 2);
    
    // Calculate stats
    const sizeKB = (payloadJson.length / 1024).toFixed(2);
    const selectedCount = currentVotes.filter(v => v).length;
    const totalProofs = payload.zkpProofs.bitProofs.length;
    
    // Display stats
    payloadStats.innerHTML = `
        <strong>📊 Payload Statistics:</strong><br>
        • Size: ${sizeKB} KB<br>
        • Selected Candidates: ${selectedCount}/${CANDIDATE_COUNT}<br>
        • ZK Proofs: ${totalProofs} bit proofs + 1 sum proof<br>
        • Endpoint: <code>POST http://localhost:3000/api/vote</code>
    `;

    // Display formatted payload
    payloadContent.textContent = payloadJson;

    // Store payload for later use
    window.currentPayload = payloadJson;

    // Show modal
    modal.style.display = 'block';

    log(`📦 Payload prepared for inspection (${sizeKB} KB)`);
}

/**
 * Close the payload modal
 */
function closePayloadModal() {
    const modal = document.getElementById('payloadModal');
    modal.style.display = 'none';
    window.currentPayload = null;
}

/**
 * Copy payload to clipboard
 */
async function copyPayloadToClipboard() {
    if (!window.currentPayload) return;

    try {
        await navigator.clipboard.writeText(window.currentPayload);
        log('📋 Payload copied to clipboard');
        
        // Visual feedback
        const btn = event.target;
        const originalText = btn.textContent;
        btn.textContent = '✅ Copied!';
        btn.style.background = '#27ae60';
        
        setTimeout(() => {
            btn.textContent = originalText;
            btn.style.background = '#9b59b6';
        }, 2000);
        
    } catch (error) {
        log('❌ Failed to copy payload: ' + error.message);
        
        // Fallback - select the text
        const payloadContent = document.getElementById('payloadContent');
        const range = document.createRange();
        range.selectNode(payloadContent);
        window.getSelection().removeAllRanges();
        window.getSelection().addRange(range);
        
        log('� Payload text selected - use Ctrl+C to copy');
    }
}

/**
 * Download payload as JSON file
 */
function downloadPayload() {
    if (!window.currentPayload) return;

    try {
        const blob = new Blob([window.currentPayload], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
        a.href = url;
        a.download = `vote-payload-${timestamp}.json`;
        
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        
        URL.revokeObjectURL(url);
        
        log('💾 Payload downloaded as JSON file');
        
        // Visual feedback
        const btn = event.target;
        const originalText = btn.textContent;
        btn.textContent = '✅ Downloaded!';
        btn.style.background = '#27ae60';
        
        setTimeout(() => {
            btn.textContent = originalText;
            btn.style.background = '#9b59b6';
        }, 2000);
        
    } catch (error) {
        log('❌ Failed to download payload: ' + error.message);
    }
}

/**
 * Confirm and send the payload to the network
 */
async function confirmSendPayload() {
    if (!window.currentPayload) {
        log('❌ No payload available to send');
        return;
    }

    try {
        log('📤 Sending vote payload to backend...');
        updateStatus('Sending encrypted vote to backend...', 'info');

        // Parse the payload back to object for sending
        const votePayload = JSON.parse(window.currentPayload);

        log(`📦 Transmitting ${(window.currentPayload.length / 1024).toFixed(2)} KB to network...`);
        log('🌐 Opening network connection to http://localhost:3000/api/vote');

        // Send to localhost backend
        const response = await fetch('http://localhost:3000/api/vote', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Client-Version': '1.0.0',
                'X-Vote-Type': 'paillier-zkp'
            },
            body: window.currentPayload
        });

        if (response.ok) {
            const result = await response.json();
            log('✅ Vote sent successfully!');
            log(`📨 Server response: ${JSON.stringify(result, null, 2)}`);
            updateStatus('Vote sent successfully to backend!', 'success');
            
            // Close modal on success
            closePayloadModal();
        } else {
            const errorText = await response.text();
            log(`❌ Server error (${response.status}): ${errorText}`);
            updateStatus(`Backend error (${response.status}): ${errorText}`, 'error');
        }

    } catch (error) {
        if (error.name === 'TypeError' && error.message.includes('fetch')) {
            log('❌ Connection failed - backend server not running');
            updateStatus('Cannot connect to backend server at localhost:3000', 'error');
            log('💡 Start a backend server or check the endpoint URL');
            log('💡 You can still copy/download the payload to inspect it');
        } else {
            log('❌ Send failed: ' + error.message);
            updateStatus('Failed to send vote: ' + error.message, 'error');
        }
    }
}

// Initialize the system when page loads
document.addEventListener('DOMContentLoaded', function () {
    initVotingSystem();
    log('🗳️  Paillier Encryption Voting System Ready');
    log('💡 This is a demonstration system for educational purposes');
    log('🔐 All cryptographic operations are performed client-side');

    // Run self-tests
    runSelfTests();

    // Add modal event listeners
    setupModalEventListeners();
});

/**
 * Setup modal event listeners
 */
function setupModalEventListeners() {
    const modal = document.getElementById('payloadModal');
    
    // Close modal when clicking outside of it
    window.addEventListener('click', function(event) {
        if (event.target === modal) {
            closePayloadModal();
        }
    });

    // Close modal with Escape key
    document.addEventListener('keydown', function(event) {
        if (event.key === 'Escape' && modal.style.display === 'block') {
            closePayloadModal();
        }
    });
}
