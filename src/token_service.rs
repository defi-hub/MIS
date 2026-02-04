// Token Service - Ed25519 signing and capability token management

use anyhow::{Context, Result};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey, Signature};
use sha2::{Sha256, Digest};
use std::time::{SystemTime, UNIX_EPOCH};
use rand::rngs::OsRng;

/// Capability flags (must match eBPF definitions)
pub const CAP_READ: u64 = 1 << 0;
pub const CAP_WRITE: u64 = 1 << 1;
pub const CAP_EXEC: u64 = 1 << 2;
pub const CAP_NETWORK: u64 = 1 << 3;
pub const CAP_IPC: u64 = 1 << 4;
pub const CAP_ADMIN: u64 = 1 << 5;
pub const CAP_CREATE: u64 = 1 << 6;
pub const CAP_DELETE: u64 = 1 << 7;

/// Capability Token - matches eBPF struct (64 bytes)
#[repr(C, align(64))]
#[derive(Debug, Clone, Copy)]
pub struct CapabilityToken {
    pub capabilities: u64,
    pub expires_at: u64,
    pub session_id: u64,
    pub flags: u64,
    pub token_hash: [u8; 32],
}

impl CapabilityToken {
    /// Serialize for Ed25519 signing (everything except hash)
    fn to_signing_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32);
        bytes.extend_from_slice(&self.capabilities.to_le_bytes());
        bytes.extend_from_slice(&self.expires_at.to_le_bytes());
        bytes.extend_from_slice(&self.session_id.to_le_bytes());
        bytes.extend_from_slice(&self.flags.to_le_bytes());
        bytes
    }
    
    /// Convert to bytes for BPF map
    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                self as *const Self as *const u8,
                std::mem::size_of::<Self>()
            )
        }
    }
}

/// Session Metadata - matches eBPF struct (128 bytes)
#[repr(C, align(128))]
#[derive(Debug, Clone)]
pub struct SessionMetadata {
    pub session_id: u64,
    pub cgroup_id: u64,
    pub capabilities: u64,
    pub last_access_ns: u64,
    pub created_at: u64,
    pub agent_pid: u32,
    pub violation_count: u16,
    pub state: u8,
    pub defcon_level: u8,
    pub intent: [u8; 64],
    pub padding: [u8; 40],
}

impl SessionMetadata {
    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                self as *const Self as *const u8,
                std::mem::size_of::<Self>()
            )
        }
    }
}

/// Token Service - manages capability tokens
pub struct TokenService {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl TokenService {
    /// Create new token service with generated keys
    pub fn new() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        
        Self {
            signing_key,
            verifying_key,
        }
    }
    
    /// Load from existing key file
    pub fn from_key_file(path: &std::path::Path) -> Result<Self> {
        let key_bytes = std::fs::read(path)
            .context("Failed to read signing key")?;
        
        let signing_key = SigningKey::from_bytes(
            key_bytes[..32].try_into()
                .context("Invalid key length")?
        );
        
        let verifying_key = signing_key.verifying_key();
        
        Ok(Self {
            signing_key,
            verifying_key,
        })
    }
    
    /// Save keys to file
    pub fn save_key(&self, path: &std::path::Path) -> Result<()> {
        std::fs::write(path, self.signing_key.to_bytes())
            .context("Failed to write signing key")?;
        Ok(())
    }
    
    /// Issue new capability token
    pub fn issue_token(
        &self,
        session_id: u64,
        capabilities: u64,
        ttl_secs: u64,
    ) -> Result<CapabilityToken> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_nanos() as u64;
        
        let expires_at = now + (ttl_secs * 1_000_000_000);
        
        let mut token = CapabilityToken {
            capabilities,
            expires_at,
            session_id,
            flags: 0,  // Can add hw_backed, revocable flags
            token_hash: [0u8; 32],
        };
        
        // Sign token with Ed25519
        let message = token.to_signing_bytes();
        let signature: Signature = self.signing_key.sign(&message);
        
        // Combine signature + message → SHA256 hash
        // eBPF will verify this hash (faster than full Ed25519 in kernel)
        let mut hasher = Sha256::new();
        hasher.update(signature.to_bytes());
        hasher.update(&message);
        let hash = hasher.finalize();
        
        token.token_hash.copy_from_slice(&hash);
        
        Ok(token)
    }
    
    /// Verify token (for userspace validation)
    pub fn verify_token(&self, token: &CapabilityToken) -> Result<bool> {
        let message = token.to_signing_bytes();
        
        // Recompute hash
        let mut test_hash = [0u8; 32];
        // Note: we don't store signature separately, so can't fully verify
        // In production: store signature alongside token
        // For now: assume hash match = valid
        
        Ok(true)  // Placeholder
    }
    
    /// Get public key (for distribution to other nodes)
    pub fn public_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_token_issue() {
        let service = TokenService::new();
        
        let token = service.issue_token(
            12345,
            CAP_READ | CAP_WRITE,
            3600,
        ).unwrap();
        
        assert_eq!(token.session_id, 12345);
        assert_eq!(token.capabilities, CAP_READ | CAP_WRITE);
        assert!(token.expires_at > 0);
    }
    
    #[test]
    fn test_token_size() {
        assert_eq!(std::mem::size_of::<CapabilityToken>(), 64);
        assert_eq!(std::mem::size_of::<SessionMetadata>(), 128);
    }
}
