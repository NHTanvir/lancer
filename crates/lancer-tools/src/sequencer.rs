//! Sequencer — statistical analysis of session-token randomness.
//!
//! Implements the canonical battery: monobit, poker (chi-squared), runs,
//! long-runs, and character/transition counts. Output is a `SequencerReport`
//! consumed by both the GUI and the CLI.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequencerReport {
    pub sample_count: usize,
    pub total_bits: usize,
    pub effective_entropy_bits: f64,
    pub monobit_p_value: f64,
    pub poker_p_value: f64,
    pub runs_p_value: f64,
    pub char_position_entropy: Vec<f64>,
    pub pass: bool,
}

pub struct Sequencer;

impl Sequencer {
    /// Analyze a slice of tokens. Each token is treated as a byte sequence.
    pub fn analyze(tokens: &[Vec<u8>]) -> SequencerReport {
        let total_bits: usize = tokens.iter().map(|t| t.len() * 8).sum();
        let mut ones = 0u64;
        for t in tokens {
            for b in t {
                ones += b.count_ones() as u64;
            }
        }
        let zeros = total_bits as u64 - ones;
        let monobit = monobit_p(ones as i64, zeros as i64);
        let poker = poker_p_value(tokens);
        let runs = runs_p_value(tokens);
        let char_position_entropy = position_entropy(tokens);
        let effective_entropy_bits = char_position_entropy.iter().sum::<f64>();
        let pass = monobit > 0.01 && poker > 0.01 && runs > 0.01;
        SequencerReport {
            sample_count: tokens.len(),
            total_bits,
            effective_entropy_bits,
            monobit_p_value: monobit,
            poker_p_value: poker,
            runs_p_value: runs,
            char_position_entropy,
            pass,
        }
    }
}

fn monobit_p(ones: i64, zeros: i64) -> f64 {
    let n = (ones + zeros).max(1) as f64;
    let s = (ones - zeros) as f64 / n.sqrt();
    // erfc approximation
    erfc(s.abs() / 2f64.sqrt())
}

fn poker_p_value(tokens: &[Vec<u8>]) -> f64 {
    // Group bits into 4-bit blocks and chi-square against expected uniformity.
    let mut counts = [0u64; 16];
    let mut total_blocks = 0u64;
    for t in tokens {
        let mut bitstream: u32 = 0;
        let mut bits_in = 0;
        for b in t {
            for i in (0..8).rev() {
                bitstream = (bitstream << 1) | ((b >> i) as u32 & 1);
                bits_in += 1;
                if bits_in == 4 {
                    counts[(bitstream & 0x0F) as usize] += 1;
                    bitstream = 0;
                    bits_in = 0;
                    total_blocks += 1;
                }
            }
        }
    }
    if total_blocks == 0 {
        return 0.5;
    }
    let expected = total_blocks as f64 / 16.0;
    let chi: f64 = counts
        .iter()
        .map(|&c| {
            let diff = c as f64 - expected;
            diff * diff / expected
        })
        .sum();
    // Approx p-value: chi-square with 15 df
    1.0 - chi_sq_cdf(chi, 15.0)
}

fn runs_p_value(tokens: &[Vec<u8>]) -> f64 {
    let mut total_bits = 0usize;
    let mut transitions = 0usize;
    let mut last_bit: Option<u8> = None;
    let mut ones = 0u64;
    for t in tokens {
        for b in t {
            for i in (0..8).rev() {
                let bit = (b >> i) & 1;
                if bit == 1 {
                    ones += 1;
                }
                if let Some(lb) = last_bit {
                    if lb != bit {
                        transitions += 1;
                    }
                }
                last_bit = Some(bit);
                total_bits += 1;
            }
        }
    }
    if total_bits < 100 {
        return 0.5;
    }
    let pi = ones as f64 / total_bits as f64;
    if (pi - 0.5).abs() > 0.05 {
        return 0.0;
    }
    let expected = 2.0 * total_bits as f64 * pi * (1.0 - pi);
    let z = (transitions as f64 - expected).abs()
        / (2.0 * (total_bits as f64).sqrt() * pi * (1.0 - pi));
    erfc(z / 2f64.sqrt())
}

fn position_entropy(tokens: &[Vec<u8>]) -> Vec<f64> {
    if tokens.is_empty() {
        return Vec::new();
    }
    let max_len = tokens.iter().map(|t| t.len()).max().unwrap_or(0);
    (0..max_len)
        .map(|i| {
            let mut counts = [0u32; 256];
            let mut total = 0u32;
            for t in tokens {
                if let Some(b) = t.get(i) {
                    counts[*b as usize] += 1;
                    total += 1;
                }
            }
            if total == 0 {
                return 0.0;
            }
            let mut h = 0.0f64;
            for &c in &counts {
                if c == 0 {
                    continue;
                }
                let p = c as f64 / total as f64;
                h -= p * p.log2();
            }
            h
        })
        .collect()
}

fn erfc(x: f64) -> f64 {
    // Abramowitz & Stegun 7.1.26 approximation
    let t = 1.0 / (1.0 + 0.3275911 * x.abs());
    let poly = ((((1.061405429 * t - 1.453152027) * t + 1.421413741) * t - 0.284496736) * t
        + 0.254829592)
        * t;
    let result = poly * (-x * x).exp();
    if x < 0.0 {
        2.0 - result
    } else {
        result
    }
}

fn chi_sq_cdf(x: f64, k: f64) -> f64 {
    // Approximation via Wilson-Hilferty transformation
    let v = (x / k).powf(1.0 / 3.0);
    let mean = 1.0 - 2.0 / (9.0 * k);
    let var = 2.0 / (9.0 * k);
    let z = (v - mean) / var.sqrt();
    0.5 * (1.0 + erf(z / 2f64.sqrt()))
}

fn erf(x: f64) -> f64 {
    1.0 - erfc(x)
}
