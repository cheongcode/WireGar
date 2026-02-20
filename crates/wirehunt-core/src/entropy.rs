/// Shannon entropy of a byte slice, in bits (0.0 - 8.0).
/// High entropy (>7.0) suggests encrypted/compressed data.
/// Low entropy (<3.0) suggests structured/repetitive data.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut freq = [0u64; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Classify data based on entropy level.
pub fn classify_entropy(entropy: f64) -> EntropyClass {
    if entropy > 7.5 {
        EntropyClass::Encrypted
    } else if entropy > 6.5 {
        EntropyClass::Compressed
    } else if entropy > 4.5 {
        EntropyClass::Mixed
    } else if entropy > 2.0 {
        EntropyClass::Structured
    } else {
        EntropyClass::Repetitive
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntropyClass {
    Encrypted,
    Compressed,
    Mixed,
    Structured,
    Repetitive,
}

impl std::fmt::Display for EntropyClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Encrypted => write!(f, "encrypted/random"),
            Self::Compressed => write!(f, "compressed"),
            Self::Mixed => write!(f, "mixed"),
            Self::Structured => write!(f, "structured"),
            Self::Repetitive => write!(f, "repetitive"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_zeros() {
        let data = vec![0u8; 1000];
        assert_eq!(shannon_entropy(&data), 0.0);
        assert_eq!(classify_entropy(0.0), EntropyClass::Repetitive);
    }

    #[test]
    fn test_entropy_text() {
        let data = b"The quick brown fox jumps over the lazy dog";
        let e = shannon_entropy(data);
        assert!(e > 3.0 && e < 5.5, "text entropy should be moderate, got {}", e);
    }

    #[test]
    fn test_entropy_random() {
        // Pseudo-random data has high entropy
        let data: Vec<u8> = (0..=255).cycle().take(4096).collect();
        let e = shannon_entropy(&data);
        assert!(e > 7.9, "uniform data should have near-max entropy, got {}", e);
    }
}
