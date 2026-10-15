//! What a web session window tells the operator about TLS and page loads
//! (features/web-application-connect.md §8.1–8.2, T139): the title notice
//! and audit line for a top-frame load that failed, and the native question
//! about a certificate the platform rejected.
//!
//! macOS only for now: the platform shim that calls it is the WKWebView
//! navigation delegate in `connect_web_http_auth`. WebView2 and WebKitGTK
//! windows keep their Phase 4 behaviour (a rejected certificate without a
//! matching pin is refused).
//!
//! Every decision stays in the session layer: the failure classification in
//! `session::web_load`, the per-key override in
//! `TlsPinGate::operator_override`. This only shows and records them.

use std::sync::Arc;

use tauri::{AppHandle, Url};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};

use crate::session::web::{WebOrigin, WebShared};
use crate::session::web_load::{LoadFailure, PageFailure};
use crate::session::web_tls_pin::PresentedCertificate;
use crate::session::web_tls_prompt::{prompt_message, PromptFacts, CANCEL_LABEL, CONTINUE_LABEL, PROMPT_TITLE};

use super::connect_web::{session_window, set_title_later};

/// One session window's view of the operator.
pub(crate) struct TrustUi {
    app: AppHandle,
    label: String,
    token: String,
    resource: String,
    shared: Arc<WebShared>,
    /// A form or http-auth session: accepting a certificate sends the
    /// stored credential, and the question says so.
    fills_credential: bool,
}

impl TrustUi {
    pub fn new(
        app: &AppHandle,
        label: &str,
        token: &str,
        resource: &str,
        shared: &Arc<WebShared>,
        fills_credential: bool,
    ) -> Arc<Self> {
        Arc::new(Self {
            app: app.clone(),
            label: label.to_string(),
            token: token.to_string(),
            resource: resource.to_string(),
            shared: Arc::clone(shared),
            fills_credential,
        })
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn app_handle(&self) -> AppHandle {
        self.app.clone()
    }

    /// The window refused a server-trust challenge for `origin` (a pin
    /// refusal, or the operator said no): the navigation that WebKit now
    /// reports as cancelled is that failure.
    pub fn refused(&self, origin: &WebOrigin, failure: PageFailure) {
        self.shared.note_tls_refused(origin, failure);
    }

    /// A top-frame navigation failed. `failing_url` is the platform's (only
    /// its origin is kept); `failure` is `session::web_load::classify`'s
    /// verdict, `None` for a cancelled navigation. `code` is the platform's
    /// `domain:code`, for the audit line.
    pub fn load_failed(&self, failing_url: Option<&str>, failure: Option<LoadFailure>, code: &str) {
        let origin = failing_url.and_then(|u| Url::parse(u).ok()).and_then(|u| WebOrigin::of_url(&u));
        let Some((failure, title)) = self.shared.load_failed(origin.as_ref(), failure) else {
            return;
        };
        log::warn!(
            target: "audit",
            "connect.web.load_failed: resource={} token={} origin={} reason={} platform_code={code}",
            self.resource,
            self.token,
            origin.as_ref().map(ToString::to_string).unwrap_or_else(|| "unknown".to_string()),
            failure.check,
        );
        set_title_later(&self.app, &self.label, title);
    }

    /// Ask the operator about a certificate the platform rejected on
    /// `origin`. Non-blocking: `answer` runs once, with the operator's
    /// choice, on a dialog thread. The recipe engine's clock stops while the
    /// question is open.
    pub fn ask(
        self: &Arc<Self>,
        origin: &WebOrigin,
        leaf: Option<PresentedCertificate>,
        platform_reason: Option<String>,
        answer: impl FnOnce(bool) + Send + 'static,
    ) {
        let message = prompt_message(&PromptFacts {
            origin,
            leaf: leaf.as_ref(),
            platform_reason: platform_reason.as_deref(),
            now: chrono::Utc::now().timestamp(),
            fills_credential: self.fills_credential,
        });
        self.shared.begin_prompt();
        set_title_later(
            &self.app,
            &self.label,
            self.shared.set_notice("waiting for you: untrusted TLS certificate".to_string()),
        );
        let ui = Arc::clone(self);
        // Built from a task, not inside the WebKit delegate callback this is
        // called from, so the window lookup cannot re-enter the registry
        // (as `set_title_later`).
        tauri::async_runtime::spawn(async move {
            let mut dialog = ui
                .app
                .dialog()
                .message(message)
                .title(PROMPT_TITLE)
                .kind(MessageDialogKind::Warning)
                .buttons(MessageDialogButtons::OkCancelCustom(CONTINUE_LABEL.to_string(), CANCEL_LABEL.to_string()));
            // A sheet on the session window, so the question names its window.
            if let Some(window) = session_window(&ui.app, &ui.label) {
                dialog = dialog.parent(&window);
            }
            let answering = Arc::clone(&ui);
            dialog.show(move |accepted| {
                answering.shared.end_prompt();
                answer(accepted);
            });
        });
    }
}
