# Second, independent implementation of the node_id vectors (Python hashlib).
import hashlib
LABEL = b"MACULA-NODE-ID-V1"
def node_id(profile, n):
    key = bytes(i % 256 for i in range(n))
    return hashlib.sha256(LABEL + bytes([0, len(profile)]) + profile.encode() + key).hexdigest()
for name, profile, n in [("V1", "pq_pure", 2592), ("V2", "pq_hybrid", 3118), ("V3", "pq_hybrid", 2592)]:
    print(name, profile, n, node_id(profile, n))
