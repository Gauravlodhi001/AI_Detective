class IdorVerifier {
  constructor(log) {
    this.log = log || [];
  }

  // Tokenizes a string into a set of unique words/tokens
  tokenize(text) {
    if (!text) return new Set();
    // Normalize and split by whitespace/punctuation
    const tokens = text
      .toLowerCase()
      .replace(/[^\w\s-]/g, ' ')
      .split(/\s+/)
      .filter(t => t.length > 1);
    return new Set(tokens);
  }

  // Computes Jaccard Similarity between two strings
  calculateJaccardSimilarity(strA, strB) {
    const setA = this.tokenize(strA);
    const setB = this.tokenize(strB);

    if (setA.size === 0 && setB.size === 0) return 1.0;
    if (setA.size === 0 || setB.size === 0) return 0.0;

    let intersectionCount = 0;
    for (const item of setA) {
      if (setB.has(item)) {
        intersectionCount++;
      }
    }

    const unionCount = setA.size + setB.size - intersectionCount;
    return intersectionCount / unionCount;
  }

  // Verifies if User B accessing User A's resource constitutes an IDOR vulnerability
  verifyIdor(ownerRes, attackerRes, guestRes, ownerConfig, attackerConfig) {
    // 1. Verify if Guest (unauthenticated) can access
    const isGuestSuccess = guestRes && (guestRes.status >= 200 && guestRes.status < 300);
    
    // Check if the resource is completely public (e.g. Guest gets 200)
    if (isGuestSuccess) {
      this.log.push(`[IDORVerifier] Guest received status ${guestRes.status}. This resource appears to be PUBLIC.`);
      return {
        isVulnerable: false,
        reason: 'Resource is publicly accessible to unauthenticated guests (intended public resource)'
      };
    }

    // 2. If Attacker (User B) request failed, there is no IDOR
    if (!attackerRes || attackerRes.status === 401 || attackerRes.status === 403 || attackerRes.status === 302) {
      this.log.push(`[IDORVerifier] Attacker session blocked with status: ${attackerRes ? attackerRes.status : 'failed'}`);
      return {
        isVulnerable: false,
        reason: 'Attacker session was correctly blocked'
      };
    }

    // 3. Both User A and User B received 200. Compare response bodies.
    const simAB = this.calculateJaccardSimilarity(ownerRes.body, attackerRes.body);
    this.log.push(`[IDORVerifier] Jaccard similarity between Owner and Attacker response: ${(simAB * 100).toFixed(2)}%`);

    // Let's check for custom JSON error bodies in the attacker response
    // e.g. {"error": "Unauthorized"} returning 200 OK
    try {
      const attackerData = JSON.parse(attackerRes.body);
      if (attackerData && (attackerData.error || attackerData.message === 'Access Denied' || attackerData.status === 'error')) {
        this.log.push(`[IDORVerifier] Attacker response contains a custom JSON error block despite returning 200 OK.`);
        return {
          isVulnerable: false,
          reason: 'Attacker received a 200 OK but body indicates custom access control refusal message'
        };
      }
    } catch (e) {
      // Not JSON, continue with similarity check
    }

    // If similarity is extremely high (e.g., > 97%) and they contain identical static HTML dashboard skeleton without private data,
    // it could be a shared template. But if it's JSON data, high similarity with different ID references is a major indicator of IDOR!
    // Let's check if the owner's unique identifiers or credentials leak in the attacker response
    const ownerEmail = ownerConfig && ownerConfig.credentials ? ownerConfig.credentials.usernameValue : null;

    if (ownerEmail && attackerRes.body.includes(ownerEmail)) {
      this.log.push(`[IDORVerifier] IDOR confirmed! Attacker response body reflects Owner's email: ${ownerEmail}`);
      return {
        isVulnerable: true,
        reason: `Access allowed (200 OK) and response leaks Owner's unique credential details: ${ownerEmail}`
      };
    }

    // If similarity is between 20% and 95% (indicating different records are loaded, e.g. Invoice A vs Invoice B),
    // and both returned 200, this is a clear IDOR bypass!
    if (simAB < 0.95) {
      this.log.push(`[IDORVerifier] IDOR confirmed! Attacker retrieved resource with distinct data content (similarity: ${(simAB * 100).toFixed(2)}%).`);
      return {
        isVulnerable: true,
        reason: `Horizontal privilege escalation confirmed. Attacker retrieved private data belonging to Owner (Jaccard similarity: ${(simAB * 100).toFixed(2)}%).`
      };
    }

    // If similarity is 1.0 (or very close), it means the attacker received the exact same data.
    // We already checked that Guest was blocked. So if Guest is blocked (meaning it is a private route),
    // and both User A and User B see the exact same content, then User B is accessing User A's private data!
    if (simAB >= 0.95) {
      // Let's see if the body is an empty shell or custom denial
      if (attackerRes.body.toLowerCase().includes('denied') || attackerRes.body.toLowerCase().includes('forbidden')) {
        return {
          isVulnerable: false,
          reason: 'High similarity but text contains access denial strings'
        };
      }

      this.log.push(`[IDORVerifier] IDOR confirmed! Attacker accessed Owner's private data, returning identical body content.`);
      return {
        isVulnerable: true,
        reason: 'Private resource accessed successfully by attacker, returning identical data content'
      };
    }

    return {
      isVulnerable: false,
      reason: 'No authorization bypass confirmed'
    };
  }
}

module.exports = { IdorVerifier };
