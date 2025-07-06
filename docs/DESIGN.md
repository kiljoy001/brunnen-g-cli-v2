# Brunnen-G Identity System Documentation v3.1

## Overview

Brunnen-G implements a decentralized public key infrastructure using hardware security modules, blockchain persistence, and certificate-based identity storage. The system enables passwordless authentication without central authorities or network dependencies.

## Core Identity Equation

Each identity is computed as a stable hash:
```
Let:
 H(.) denote the SHA256 hash function
 || denote the concatenation operator
 TPMpk represents the TPM public key
 DILsig represents the Dilithium signature of the Emercoin signed hash of TPMpk
 YUBIpk represents the YubiKey public key in slot 9c (touch-only)

First define the Domain Identity Hash (DIH):
 DIH = H(TPMpk || H(DILsig))

Then, the Stable Identity Hash (IDstable):
 IDstable = H(DIH || H(YUBIpk))

IDstable serves as the leaf in merkle trees, providing an unchanging identifier.
```

### Components

**TPM Public Key**
- Hardware-generated key that never leaves the TPM
- Provides root of trust anchored in silicon
- Randomized handles prevent enumeration

**Emercoin Domain Signature**
- Proves domain ownership through blockchain
- Signs the TPM public key with domain's private key
- Creates binding between hardware and blockchain identity

**Dilithium Signature**
- Post-quantum cryptographic signature
- Signs the Emercoin signature for quantum resistance
- NIST-approved algorithm (FIPS 204)

**YubiKey Component**
- PIV slot 9c configured for touch-only (no PIN)
- Certificate generated on-device with custom extensions
- Physical touch required for all operations
- Public key exportable for remote verification

## Certificate-Based Architecture

### Self-Contained Identity

X.509 certificate structure:
- **Subject**: user@domain.coin
- **Extension OID 63716**: Merkle proof and metadata (JSON)
  - merkle_proof: array of proof nodes
  - merkle_index: leaf position
  - dih: Domain Identity Hash
  - domain_signature: Emercoin signature

### Multi-Slot Device Identity
Slots could be used to hold multiple idenities, typically for devices that the user may have using the yggdrasil public key as an identifier. An extension equation of IDstable = H(DIH || H(YUBIpk) || H(YggPubKey))
- **Slot 9a**: Personal device identity
- **Slot 9c**: Work device identity  
- **Slot 9d**: Kiosk/shared device identity
- **Slot 9e**: Service-specific identity

Each slot binds a user to a specific device, enabling fine-grained access control.

## Registration Process

### Step 1: Identity Generation
1. TPM generates keypair (randomized handle)
2. Domain owner signs TPM public key with Emercoin key
3. Dilithium signs the domain signature
4. YubiKey generates touch-only key in slot 9c

### Step 2: Certificate Creation
1. Compute IDstable for user
2. Add user to domain's merkle tree
3. Generate merkle proof for user
4. YubiKey generates certificate with proof in extension
5. Certificate remains on YubiKey

### Step 3: Domain Publication
1. Compute final merkle root
2. Publish to blockchain:
   ```
   trust:domain.coin = {
     "merkle_root": "0xabc123...",
     "blockheight": 1234567890
   }
   ```

## Authentication Flow

### Touch-Only Authentication
1. Verifier sends challenge nonce
2. User signs challenge with YubiKey (touch required)
3. Verifier validates signature with certificate public key
4. Extract merkle proof from certificate extension
5. Verify proof against blockchain merkle root

This order prevents proof replay attacks by validating possession first.

### Cross-Domain Verification

User alice@domain1.coin authenticates to domain2.coin:
1. domain2.coin generates challenge
2. alice signs with YubiKey from domain1.coin
3. domain2.coin fetches trust:domain1.coin from blockchain
4. Verifies alice's merkle proof against domain1's root

## Domain Certificate Authority

Domains can operate as their own CA:
1. Generate domain TPM keypair
2. Create self-signed CA certificate
3. Sign certificate hash with TPM
4. Publish to blockchain as `ca:domain.coin`

This enables:
- Domain-issued TLS certificates
- Service authentication
- Code signing
- Email encryption

## Data Layer (Prefix: 'risk:')

### Storage Tiers
1. **CBOR on Blockchain** (<15KB)
   - Direct storage with 'risk:' prefix
   - Configuration, metadata, small files
   - Example: `risk:domain.coin:config`

2. **BitTorrent** (>15KB)
   - Large databases, media files
   - Blockchain stores torrent hash
   - P2P distribution for scalability

## API Design

### DDOS Protection

Verify endpoints protected via:
- Rate limiting per IP/identity
- Proof-of-work challenges for anonymous access
- YubiKey signature validation before expensive operations
- Caching of recently verified identities

### Core Endpoints
```
GET  /api/v1/health              - System status
POST /api/v1/auth/challenge      - Get auth challenge
POST /api/v1/auth/verify         - Verify signed challenge
POST /api/v1/register            - Register new identity (authenticated)
```

## Security Properties

**Hardware Binding**
- Private keys physically locked in TPM/YubiKey
- Touch requirement prevents automation
- Survives OS compromise

**Quantum Resistance**
- Dilithium signatures resist quantum attacks
- SHA256 provides 128-bit quantum security
- Forward-secure design

**Physical Presence**
- Every operation requires touch
- No PIN reduces phishing surface
- Rate-limited by human interaction

**Offline Capability**
- Certificate contains all verification data
- Only blockchain root lookup required
- Works with cached merkle roots

## Network Architecture

### Yggdrasil Integration
- TPM-secured mesh networking
- Cryptographic device addressing
- Direct peer-to-peer identity verification
- IPv6 addresses for all nodes

## Database Role

Databases used only for:
- Initial merkle tree computation
- Batch registration processing
- Administrative operations

Not required for:
- Identity verification
- Authentication
- Certificate validation
## Economic Defense

Using the formula of ```2^(n + y)``` where ```n```is the number 
of attempts and ```y``` is the number of domains with .001 emc
is the base price fee (added on top of network fees) that is paid
directly to the domain owner for rate limited actions. 
The same formula is applied to a blockchain hosted spam list
by yggdrasil public key of users. 

## Group Membership

Blockchain registry for group management:
```
registry:domain.coin:groupID = {
  "members": ["alice_IDstable", "bob_IDstable"],
  "merkle_root": "0xdef456...",
  "updated": 1234567890
}
```

# API Write Operations and Economic Model

## Write Authentication

All write operations require YubiKey touch authentication to ensure physical user presence:

1. **Touch Authorization**: User touches YubiKey to sign `H(current_block_height || expiry_window || operation_type)`
2. **Request Submission**: Application includes signature with write request
3. **Verification**: Node validates signature against user's registered YubiKey public key
4. **Expiration**: Signatures expire after 10 blocks (~10 minutes)

## Economic Model

### Fee Structure

Write operations incur fees to prevent spam and fund infrastructure:

```
total_fee = (base_fee + (data_size_kb * storage_rate)) * 2^(attempts_in_window)
```

**Components:**
- `base_fee`: 0.001 EMC minimum per operation
- `storage_rate`: 0.0001 EMC per KB
- `attempts_in_window`: Requests in last 24 hours
- **Platform fee**: 1% to Brunnen-G development

**Fee Distribution:**
- 99% to domain owner
- 1% to platform development fund

### Storage Tiers
- **Metadata** (<1KB): Base fee only
- **Documents** (1KB-1MB): Linear scaling
- **Large Objects** (>1MB): Premium rates apply

# Additional Speculative Features

## User-Level DNS

Each identity controls a DNS namespace:

```sql
CREATE TABLE user_dns (
  identity_address VARCHAR(255),
  record_type ENUM('AAAA', 'CNAME', 'MX', 'SRV', 'HYPER', 'IPFS', 'BTIH'),
  subdomain VARCHAR(255),
  value TEXT,
  priority INTEGER,
  ttl INTEGER DEFAULT 3600,
  UNIQUE(identity_address, subdomain, record_type)
);
```

**Example Records:**
```
alice@domain.coin           AAAA   200:dead:beef::1
blog.alice@domain.coin      AAAA   200:cafe:babe::2
mail.alice@domain.coin      MX     10 alice@mailserver.coin
data.alice@domain.coin      HYPER  hyper://abc123...
files.alice@domain.coin     IPFS   ipfs://QmXyz789...
media.alice@domain.coin     BTIH   magnet:?xt=urn:btih:def456...
```

**Resolution API:** `GET /dns/{identity}/{subdomain}`

### P2P Protocol Integration

Support the same data layer as Agregore Browser:

**HYPER Records** - Hypercore Protocol feeds
- Real-time data streams
- Cryptographically signed append-only logs
- Automatic peer replication

**IPFS Records** - InterPlanetary File System
- Content-addressed static files
- Automatic deduplication
- Global CDN through peers

**BTIH Records** - BitTorrent Info Hash
- Large file distribution
- Proven P2P technology
- Bandwidth sharing across peers

This creates complete compatibility with Agregore while maintaining identity-based addressing.

## Secure Object Storage

PostgreSQL-native storage with identity-based access:

```sql
CREATE SCHEMA user_{identity_hash} AUTHORIZATION brunnen_node;

CREATE TABLE user_{identity_hash}.objects (
  id UUID DEFAULT gen_random_uuid(),
  key VARCHAR(255) UNIQUE,
  value JSONB,
  metadata JSONB,
  encrypted BOOLEAN DEFAULT false,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW(),
  PRIMARY KEY (id)
);

-- Enable JSON indexing
CREATE INDEX idx_value_gin ON user_{identity_hash}.objects USING GIN (value);
```

**Features:**
- JSONB for flexible data structures
- Optional client-side encryption
- SQL-queryable user data
- Automatic schema isolation

## WASM Compute Layer

Execute user functions on their data:

```sql
CREATE TABLE wasm_functions (
  identity_address VARCHAR(255),
  function_name VARCHAR(255),
  wasm_hash VARCHAR(64),
  entry_point VARCHAR(255),
  permissions JSONB,
  UNIQUE(identity_address, function_name)
);
```

**DNS Integration:**
```
compute.alice@domain.coin   TXT   "wasm://QmHashOfWASMBinary"
api.alice@domain.coin       SRV   0 0 8080 200:dead:beef::1
```

**Execution Model:**
- Functions run in sandboxed WASM runtime
- Access only to user's own schema
- Results cached with configurable TTL
- Billed per CPU millisecond

## Identity Sharding

High-security identities split across multiple TPMs:

- K-of-N reconstruction required
- Geographic distribution of shards
- Time-locked recovery procedures
- Hardware attestation for each shard

## Zero-Knowledge Attributes

Prove attributes without revealing identity:

- Age verification without birthdate
- Credential validation without details
- Group membership proofs
- Selective disclosure certificates

## Agregore Browser Integration

Native browser for the decentralized web:

- **Direct Protocol Support**: Browse `hyper://`, `ipfs://`, and `bittorrent://` addresses natively
- **Identity Integration**: YubiKey authentication built into browser
- **P2P First**: Automatically reshare visited content with peers
- **Offline Capable**: Access cached and peer-shared content without internet
- **DNS Bridge**: Resolve `alice@domain.coin` to Hypercore addresses via API

**User Experience:**
```
// Navigate directly to identity-based content
https://api.domain.coin/dns/alice -> returns HYPER record
hyper://[alice's blog feed] -> loads in Agregore
```

Agregore becomes the default browser for Brunnen-G users, accessing P2P content directly via DNS lookups.

## Keycloak Integration

Enterprise SSO bridge:

- **SAML/OIDC Provider**: Brunnen-G identities exposed via standard protocols
- **Hardware Authentication**: YubiKey touch replaces passwords in enterprise
- **Group Sync**: Blockchain groups map to Keycloak roles
- **Audit Trail**: All authentications logged with TPM signatures

Organizations can adopt Brunnen-G while maintaining existing SSO infrastructure.

## PAM Module

System-level authentication:

- **Login Integration**: Replace passwords for SSH, sudo, desktop login
- **Offline Mode**: Cache identity proofs for network-free auth
- **Touch Verification**: YubiKey required for privileged operations
- **Group Support**: Map blockchain groups to Unix groups

## Asterisk VoIP

Identity-based telephony:

- **Dial by Identity**: Call alice@domain.coin directly
- **SIP over Yggdrasil**: Encrypted mesh routing
- **Economic Defense**: Spam calls cost EMC
- **AGI Integration**: brunnen_lookup.agi resolves identities to endpoints

## JavaScript SDK

Web integration library:

```javascript
// Simple authentication
const identity = await BrunnenG.authenticate({
  touch: true,  // Require YubiKey touch
  challenge: await BrunnenG.getChallenge()
});

// DNS lookups
const address = await BrunnenG.resolve('alice@domain.coin');

// Signed API calls
const response = await BrunnenG.api.post('/data', {
  body: { key: 'value' },
  identity: identity
});
```

Makes identity integration trivial for web developers.

## P256-Based Group Membership

Cryptographic group boundaries using elliptic curves:

- **Group Creation**: Domain admin generates P256 group key sealed in TPM
- **Member Addition**: Derive member key from `H(identity || group_seed)`
- **Proof of Membership**: Member's P256 public key signed by group key
- **Revocation**: Remove member's point from group aggregate
- **Network Segmentation**: Automatic Yggdrasil peer filtering by group

**Optional Privacy Enhancement**: Ring signatures for anonymous group membership - prove you're in the group without revealing which member.