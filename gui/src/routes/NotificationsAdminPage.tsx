import { useEffect, useState } from "react";
import { Layout } from "../components/Layout";
import {
  Button,
  Input,
  Textarea,
  Select,
  Card,
  Table,
  Tabs,
  Badge,
  Modal,
  EntityPicker,
  useToast,
} from "../components/ui";
import * as api from "../lib/api";
import { extractError } from "../lib/error";

type TabId = "compose" | "sent" | "channels" | "settings";
type TargetKind = "all_users" | "user" | "username" | "group";

const SEVERITY_OPTIONS = [
  { value: "info", label: "Info" },
  { value: "success", label: "Success" },
  { value: "warning", label: "Warning" },
  { value: "critical", label: "Critical" },
];

const TARGET_OPTIONS = [
  { value: "all_users", label: "All users" },
  { value: "user", label: "A specific user" },
  { value: "username", label: "A user by login name" },
  { value: "group", label: "A group" },
];

function severityBadge(sev: string): "info" | "success" | "warning" | "error" | "neutral" {
  switch (sev) {
    case "success":
      return "success";
    case "warning":
      return "warning";
    case "critical":
      return "error";
    case "info":
      return "info";
    default:
      return "neutral";
  }
}

export function NotificationsAdminPage() {
  const { toast } = useToast();
  const [tab, setTab] = useState<TabId>("compose");

  // Compose state
  const [title, setTitle] = useState("");
  const [body, setBody] = useState("");
  const [severity, setSeverity] = useState<api.NotificationSeverity>("info");
  const [targetKind, setTargetKind] = useState<TargetKind>("all_users");
  const [entityId, setEntityId] = useState("");
  const [username, setUsername] = useState("");
  const [groupKind, setGroupKind] = useState("user");
  const [groupName, setGroupName] = useState("");
  const [actionUrl, setActionUrl] = useState("");
  const [selectedChannels, setSelectedChannels] = useState<string[]>([]);
  const [sending, setSending] = useState(false);

  // Shared data
  const [channels, setChannels] = useState<api.NotificationChannelInfo[]>([]);
  const [sent, setSent] = useState<api.NotificationItem[]>([]);
  const [config, setConfig] = useState<api.NotificationConfig | null>(null);

  // Test-channel modal
  const [testChannel, setTestChannel] = useState<string | null>(null);
  const [testTo, setTestTo] = useState("");
  const [testing, setTesting] = useState(false);

  const loadChannels = async () => {
    try {
      setChannels(await api.notificationsChannels());
    } catch (e) {
      toast("error", extractError(e));
    }
  };
  const loadSent = async () => {
    try {
      setSent(await api.notificationsSent());
    } catch (e) {
      toast("error", extractError(e));
    }
  };
  const loadConfig = async () => {
    try {
      setConfig(await api.notificationsConfigGet());
    } catch (e) {
      toast("error", extractError(e));
    }
  };

  useEffect(() => {
    void loadChannels();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  useEffect(() => {
    if (tab === "sent") void loadSent();
    if (tab === "settings") void loadConfig();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab]);

  const buildTarget = (): api.NotificationTargetInput | null => {
    switch (targetKind) {
      case "all_users":
        return { kind: "all_users" };
      case "user":
        return entityId ? { kind: "user", entity_id: entityId } : null;
      case "username":
        return username.trim() ? { kind: "username", name: username.trim() } : null;
      case "group":
        return groupName.trim()
          ? { kind: "group", group_kind: groupKind, name: groupName.trim() }
          : null;
    }
  };

  const toggleChannel = (id: string) => {
    setSelectedChannels((prev) =>
      prev.includes(id) ? prev.filter((c) => c !== id) : [...prev, id],
    );
  };

  const send = async () => {
    if (!title.trim()) {
      toast("error", "Title is required.");
      return;
    }
    const target = buildTarget();
    if (!target) {
      toast("error", "Choose a valid target.");
      return;
    }
    setSending(true);
    try {
      const result = await api.notificationsSend(
        title.trim(),
        body,
        severity,
        target,
        selectedChannels,
        actionUrl.trim() || undefined,
      );
      const failed = (result.channel_results ?? []).filter((c) => c.failed > 0);
      if (failed.length > 0) {
        toast(
          "error",
          `Sent to ${result.recipient_count} recipient(s); some channel deliveries failed: ${failed
            .map((f) => `${f.channel} (${f.error ?? "error"})`)
            .join(", ")}`,
        );
      } else {
        toast("success", `Notification sent to ${result.recipient_count} recipient(s).`);
      }
      setTitle("");
      setBody("");
      setActionUrl("");
      setSelectedChannels([]);
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setSending(false);
    }
  };

  const runTest = async () => {
    if (!testChannel) return;
    setTesting(true);
    try {
      const res = await api.notificationsChannelTest(testChannel, testTo.trim());
      if (res.failed > 0) {
        toast("error", `Test failed: ${res.error ?? "unknown error"}`);
      } else {
        toast("success", `Test delivered via ${res.channel}.`);
      }
      setTestChannel(null);
      setTestTo("");
    } catch (e) {
      toast("error", extractError(e));
    } finally {
      setTesting(false);
    }
  };

  const saveConfig = async () => {
    if (!config) return;
    try {
      await api.notificationsConfigPut(config.inbox_cap, config.plugin_rate_per_min);
      toast("success", "Notification settings saved.");
    } catch (e) {
      toast("error", extractError(e));
    }
  };

  return (
    <Layout>
      <div className="space-y-4">
        <div>
          <h1 className="text-2xl font-bold">Notifications</h1>
          <p className="text-sm text-[var(--color-text-muted)]">
            Send in-app notifications to a user, a group, or everyone, and manage delivery channels.
          </p>
        </div>

        <Tabs
          tabs={[
            { id: "compose", label: "Compose" },
            { id: "sent", label: "Sent" },
            { id: "channels", label: "Channels" },
            { id: "settings", label: "Settings" },
          ]}
          active={tab}
          onChange={(id) => setTab(id as TabId)}
        />

        {tab === "compose" && (
          <Card title="New notification">
            <div className="grid grid-cols-2 gap-3">
              <Input
                label="Title"
                className="col-span-2"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                placeholder="Scheduled maintenance tonight"
              />
              <Textarea
                label="Body"
                className="col-span-2"
                value={body}
                onChange={(e) => setBody(e.target.value)}
                rows={4}
              />
              <Select
                label="Severity"
                options={SEVERITY_OPTIONS}
                value={severity}
                onChange={(e) => setSeverity(e.target.value as api.NotificationSeverity)}
              />
              <Select
                label="Target"
                options={TARGET_OPTIONS}
                value={targetKind}
                onChange={(e) => setTargetKind(e.target.value as TargetKind)}
              />

              {targetKind === "user" && (
                <div className="col-span-2">
                  <EntityPicker
                    value={entityId}
                    onChange={(id) => setEntityId(id)}
                    label="Recipient"
                    mountFilter="userpass/"
                  />
                </div>
              )}
              {targetKind === "username" && (
                <Input
                  label="Login name"
                  className="col-span-2"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="alice"
                />
              )}
              {targetKind === "group" && (
                <>
                  <Select
                    label="Group kind"
                    options={[
                      { value: "user", label: "User group" },
                      { value: "app", label: "App group" },
                    ]}
                    value={groupKind}
                    onChange={(e) => setGroupKind(e.target.value)}
                  />
                  <Input
                    label="Group name"
                    value={groupName}
                    onChange={(e) => setGroupName(e.target.value)}
                    placeholder="admins"
                  />
                </>
              )}

              <Input
                label="Action URL (optional)"
                className="col-span-2"
                value={actionUrl}
                onChange={(e) => setActionUrl(e.target.value)}
                hint="Where the notification links to when clicked (e.g. /audit)."
              />

              <div className="col-span-2">
                <label className="block text-sm font-medium mb-1">Delivery channels</label>
                <p className="text-xs text-[var(--color-text-muted)] mb-2">
                  Every notification always appears in the in-app center. Select extra channels to
                  also deliver externally.
                </p>
                <div className="space-y-1">
                  {channels
                    .filter((c) => c.id !== "in-app")
                    .map((c) => (
                      <label key={c.id} className="flex items-center gap-2 text-sm">
                        <input
                          type="checkbox"
                          checked={selectedChannels.includes(c.id)}
                          onChange={() => toggleChannel(c.id)}
                        />
                        <span>{c.name}</span>
                        <Badge variant="neutral" label={c.kind} />
                      </label>
                    ))}
                  {channels.filter((c) => c.id !== "in-app").length === 0 && (
                    <p className="text-xs text-[var(--color-text-muted)]">
                      No external channels registered. Install a channel plugin (e.g. email) to add
                      one.
                    </p>
                  )}
                </div>
              </div>

              <div className="col-span-2 flex justify-end">
                <Button onClick={() => void send()} loading={sending}>
                  Send notification
                </Button>
              </div>
            </div>
          </Card>
        )}

        {tab === "sent" && (
          <Card title="Sent notifications" actions={<Button variant="secondary" size="sm" onClick={() => void loadSent()}>Refresh</Button>}>
            <Table
              columns={[
                {
                  key: "severity",
                  header: "",
                  render: (n) => <Badge variant={severityBadge(n.severity)} label={n.severity} dot />,
                  className: "w-24",
                },
                { key: "title", header: "Title", render: (n) => <span className="font-medium">{n.title}</span> },
                { key: "target", header: "Recipients", render: (n) => String(n.recipient_count ?? 0) },
                { key: "source", header: "Source", render: (n) => n.source },
                { key: "created_at", header: "Sent", render: (n) => n.created_at },
              ]}
              data={sent}
              rowKey={(n) => n.id}
              emptyMessage="No notifications sent yet."
            />
          </Card>
        )}

        {tab === "channels" && (
          <Card title="Delivery channels" actions={<Button variant="secondary" size="sm" onClick={() => void loadChannels()}>Refresh</Button>}>
            <Table
              columns={[
                { key: "name", header: "Channel", render: (c) => <span className="font-medium">{c.name}</span> },
                { key: "kind", header: "Kind", render: (c) => <Badge variant="neutral" label={c.kind} /> },
                { key: "provider", header: "Provider", render: (c) => c.provider },
                {
                  key: "actions",
                  header: "",
                  className: "w-24",
                  render: (c) =>
                    c.id === "in-app" ? null : (
                      <Button
                        size="sm"
                        variant="secondary"
                        onClick={() => {
                          setTestChannel(c.id);
                          setTestTo("");
                        }}
                      >
                        Test
                      </Button>
                    ),
                },
              ]}
              data={channels}
              rowKey={(c) => c.id}
              emptyMessage="No channels."
            />
          </Card>
        )}

        {tab === "settings" && config && (
          <Card title="Notification settings">
            <div className="grid grid-cols-2 gap-3">
              <Input
                label="Inbox retention (per user)"
                type="number"
                value={config.inbox_cap}
                onChange={(e) => setConfig({ ...config, inbox_cap: Number(e.target.value) })}
                hint="Oldest read notifications are pruned beyond this."
              />
              <Input
                label="Plugin send rate (per minute)"
                type="number"
                value={config.plugin_rate_per_min}
                onChange={(e) =>
                  setConfig({ ...config, plugin_rate_per_min: Number(e.target.value) })
                }
                hint="Max notifications a single plugin may raise per minute."
              />
              <div className="col-span-2 flex justify-end">
                <Button onClick={() => void saveConfig()}>Save settings</Button>
              </div>
            </div>
          </Card>
        )}
      </div>

      <Modal
        open={testChannel !== null}
        onClose={() => setTestChannel(null)}
        title="Send test notification"
        size="sm"
        actions={
          <>
            <Button variant="secondary" onClick={() => setTestChannel(null)}>
              Cancel
            </Button>
            <Button onClick={() => void runTest()} loading={testing}>
              Send test
            </Button>
          </>
        }
      >
        <Input
          label="Destination address"
          value={testTo}
          onChange={(e) => setTestTo(e.target.value)}
          placeholder="you@example.com"
          hint="For email channels, the address to send the test to."
        />
      </Modal>
    </Layout>
  );
}
