//! Explicit external effects lower to the host-admitted canonical contract.
pub use noxide_protocol::effects::{EffectContract, EffectEndpoint, EmitEffect, PayloadField};

impl super::ApplicationDefinition {
    pub fn effects(&mut self, contract: EffectContract) {
        assert!(
            self.effects.replace(contract).is_none(),
            "duplicate effect contract"
        );
    }
}
