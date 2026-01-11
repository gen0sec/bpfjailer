use anyhow::Result;
use log::info;
use std::sync::Arc;
use crate::bpf_loader::BpfJailerBpf;

pub struct PathMatcher {
    _bpf: Arc<BpfJailerBpf>,
}

impl PathMatcher {
    pub fn new(bpf: Arc<BpfJailerBpf>) -> Result<Self> {
        info!("Initializing path matcher");
        Ok(Self { _bpf: bpf })
    }

    pub fn compile_patterns(&self, patterns: &[String]) -> Result<()> {
        info!("Compiling {} path patterns", patterns.len());
        Ok(())
    }

    pub fn invalidate_cache(&self) -> Result<()> {
        info!("Invalidating path matching cache");
        Ok(())
    }
}
