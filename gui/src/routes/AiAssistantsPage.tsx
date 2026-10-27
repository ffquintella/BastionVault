import { Layout } from "../components/Layout";
import { McpAssistantsPanel } from "../components/McpAssistantsPanel";

/**
 * Self-service AI-assistant pairing. Lives in the workspace menu rather than
 * Settings (an operator-only, root-namespace page): an assistant acts with
 * the signed-in user's own permissions, so any non-root user may pair one.
 * GUI gating only — the vault refuses the token exchange for a root session.
 */
export function AiAssistantsPage() {
  return (
    <Layout>
      <div className="space-y-6">
        <h1 className="text-2xl font-bold">AI Assistants</h1>
        <McpAssistantsPanel />
      </div>
    </Layout>
  );
}
