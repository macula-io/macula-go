// Package identity holds a macula 12 node's keys and the statements it signs
// with them: an identity key (ML-DSA-87 in pq_pure, the LAMPS composite
// ML-DSA-87 + RSA-4096-PSS in pq_hybrid) whose node_id solves the admission
// puzzle, a CONNECT key bound to it, TLS and CONNECT bindings, the status
// statements a StatementIssuer reissues every 15 minutes, signed objects under
// a label, and key files.
package identity
