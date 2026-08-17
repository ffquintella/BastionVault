//! The plugin runtime, published as a [`PluginHost`] capability.
//!
//! The notifications engine dispatches plugin-channel delivery, so before
//! Phase 3 its `channel.rs` called [`PluginCatalog`] and
//! [`invoke_active_plugin`] by name. Once notifications became a crate that
//! edge pointed the wrong way: the plugin runtime holds an `Arc<dyn VaultCtx>`
//! and reaches the mount table, which puts it *above* every engine.
//!
//! So the runtime registers itself here instead, and the engine asks
//! [`VaultCtx::plugin_host`] for the capability. Same inversion Phase 2 used
//! for the other direction (`plugins` → `notifications`, via
//! `NotificationSink`) — this is that edge's twin.
//!
//! Registration happens in the assembly layer (`BastionVault::new`) rather
//! than through `Module::register`, because the plugin runtime is not a
//! module.
//!
//! See roadmaps/workspace-decomposition.md § Phase 3.

use std::sync::Arc;

use bv_plugin_manifest::ChannelKind;

use crate::{
    errors::RvError,
    kernel_api::{
        engines::{PluginChannel, PluginHost, PluginInvocation},
        VaultCtx,
    },
    plugins::{invoke_active_plugin, InvokeOutcome, PluginCatalog},
};

/// Holds the kernel handle the runtime needs to reach storage and the catalog.
pub struct PluginRuntimeHost {
    core: Arc<dyn VaultCtx>,
}

impl PluginRuntimeHost {
    pub fn new(core: Arc<dyn VaultCtx>) -> Arc<Self> {
        Arc::new(Self { core })
    }
}

fn channel_kind_str(kind: ChannelKind) -> String {
    match kind {
        ChannelKind::Email => "email",
        ChannelKind::Sms => "sms",
        ChannelKind::Slack => "slack",
        ChannelKind::Teams => "teams",
        ChannelKind::Whatsapp => "whatsapp",
        ChannelKind::Webhook => "webhook",
        ChannelKind::Other => "other",
    }
    .to_string()
}

#[maybe_async::maybe_async]
impl PluginHost for PluginRuntimeHost {
    async fn notification_channels(&self) -> Vec<PluginChannel> {
        let barrier = self.core.barrier();
        let storage = barrier.as_storage();
        // An unreadable catalog yields no plugin channels rather than an
        // error, preserving the behaviour this replaced: the built-in in-app
        // channel must stay listed even when the catalog cannot be read.
        let manifests = PluginCatalog::new().list(storage).await.unwrap_or_default();

        let mut out = Vec::new();
        for m in manifests {
            for ch in &m.capabilities.notification_channels {
                out.push(PluginChannel {
                    plugin: m.name.clone(),
                    id: ch.id.clone(),
                    name: ch.name.clone(),
                    kind: channel_kind_str(ch.kind),
                    description: ch.description.clone(),
                });
            }
        }
        out
    }

    async fn invoke(&self, plugin: &str, input: &[u8]) -> Result<PluginInvocation, RvError> {
        let output = invoke_active_plugin(self.core.clone(), plugin, input).await?;
        let error_status = match output.outcome {
            InvokeOutcome::PluginError(code) => Some(code),
            _ => None,
        };
        Ok(PluginInvocation { response: output.response, error_status })
    }
}
