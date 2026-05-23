//! Decoder/encoder pipeline. The real transforms live in
//! `lancer_core::transform`; this module wraps them in a stepwise pipeline
//! useful for the UI.

use anyhow::Result;
use lancer_core::transform::{chain, smart_decode, TransformOp};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecoderStep {
    pub op: String,
}

#[derive(Debug, Default, Clone)]
pub struct Decoder {
    pub steps: Vec<DecoderStep>,
}

impl Decoder {
    pub fn push(&mut self, op: impl Into<String>) {
        self.steps.push(DecoderStep { op: op.into() });
    }

    pub fn run(&self, input: &[u8]) -> Result<Vec<u8>> {
        let ops: Vec<TransformOp> = self
            .steps
            .iter()
            .filter_map(|s| TransformOp::parse(&s.op))
            .collect();
        chain(&ops, input).map_err(anyhow::Error::from)
    }

    pub fn smart_decode(input: &[u8]) -> Vec<u8> {
        smart_decode(input)
    }
}
