import { ObjectSharingCard } from "./ObjectSharingCard";
import * as api from "../lib/api";

/**
 * Owner card + shares table + grant/revoke + admin transfer for a
 * single file resource. The share target is the file's server-assigned
 * UUID (`ShareTargetKind::File`), not its display name — names are not
 * unique and are editable, the id is what the ACL evaluator keys on
 * when it matches `files/files/<id>` and its sub-endpoints.
 *
 * Everything but the file-specific bindings below lives in
 * `ObjectSharingCard`, shared with resources and KV secrets.
 */
export function FileSharingCard({
  fileId,
  fileName,
  toast,
}: {
  fileId: string;
  fileName?: string;
  toast: (type: "success" | "error" | "info", msg: string) => void;
}) {
  return (
    <ObjectSharingCard
      kind="file"
      target={fileId}
      label={fileName || fileId}
      noun="file"
      // No `sys/file-owner/claim` endpoint, so Claim rides the admin
      // transfer endpoint — see `OwnerAdapter`.
      owner={{ read: api.getFileOwner, transfer: api.transferFileOwner }}
      capabilities={["read", "list", "update", "delete", "create"]}
      capabilityHint={
        <>
          <code className="font-mono">read</code> covers the metadata, the
          version list and downloading the content.{" "}
          <code className="font-mono">update</code> lets the grantee upload a
          new version and edit the sync targets.
        </>
      }
      toast={toast}
    />
  );
}
