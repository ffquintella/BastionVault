Feature: Exchange export (.bvx) of every scope type
  As an operator
  I need each export scope to capture exactly the data I selected
  So that a backup is never silently empty or silently incomplete

  Background:
    Given a fresh vault with namespaces "tenant-a" and "tenant-a/child"
    And namespace "root" has a kv mount "cubby/" with secret "foo" = "root-secret"
    And namespace "tenant-a" has a kv mount "cubby/" with secret "foo" = "a-secret"
    And namespace "tenant-a" has a kv mount "other/" with secret "bar" = "a-other"
    And namespace "tenant-a/child" has a files mount "files/" holding file "f1" of 300000 bytes
    And namespace "root" has a files mount "files/" holding file "r1" of 2048 bytes
    And namespace "root" has a policy "reader"
    And namespace "tenant-a" has a policy "tenant-reader"

  Scenario: Full export captures the root namespace and nothing else
    When I export scope "full" selecting "none" from namespaces "none"
    Then the export carries namespaces "root"
    And namespace "root" holds 1 kv items
    And namespace "root" holds file "r1" with 2048 bytes

  Scenario: All-namespaces export captures every tenant
    When I export scope "all_namespaces" selecting "none" from namespaces "none"
    Then the export carries namespaces "root,tenant-a,tenant-a/child"
    And namespace "tenant-a/child" holds file "f1" with 300000 bytes
    And namespace "tenant-a" holds 2 kv items

  Scenario: All-namespaces export restricted to one nested namespace
    When I export scope "all_namespaces" selecting "none" from namespaces "tenant-a/child"
    Then the export carries namespaces "tenant-a/child"
    And namespace "tenant-a/child" holds file "f1" with 300000 bytes

  Scenario: Selective export of one engine type from a chosen namespace
    When I export scope "selective" selecting "engine:files" from namespaces "tenant-a/child"
    Then the export carries namespaces "tenant-a/child"
    And namespace "tenant-a/child" holds file "f1" with 300000 bytes
    And namespace "tenant-a/child" holds 0 kv items

  Scenario: Selective export of one mount
    When I export scope "selective" selecting "mount:cubby/" from namespaces "tenant-a"
    Then the export carries namespaces "tenant-a"
    And namespace "tenant-a" holds 1 kv items

  Scenario: Selective export of a KV path
    When I export scope "selective" selecting "kv:other/bar" from namespaces "tenant-a"
    Then namespace "tenant-a" holds 1 kv items

  Scenario: Selective export without namespaces stays in the root namespace
    When I export scope "selective" selecting "engine:files" from namespaces "none"
    Then the export carries namespaces "root"
    And namespace "root" holds file "r1" with 2048 bytes

  Scenario: Selective export of several namespaces at once
    When I export scope "selective" selecting "engine:files" from namespaces "root,tenant-a/child"
    Then the export carries namespaces "root,tenant-a/child"

  Scenario: Split export gives one importable part per namespace
    When I export scope "all_namespaces" selecting "none" from namespaces "none" split by namespace
    Then the split parts are for namespaces "root,tenant-a,tenant-a/child"

  Scenario: An export that matches nothing is refused rather than written empty
    When I export scope "selective" selecting "engine:pki" from namespaces "tenant-a/child"
    Then the export is refused as empty

  Scenario: A namespace that does not exist is reported
    When I export scope "all_namespaces" selecting "none" from namespaces "tenant-a,no-such-ns"
    Then the export carries namespaces "tenant-a"
    And the export warns about "no-such-ns"

  Scenario Outline: Encoded export survives the file format unchanged
    When I export scope "all_namespaces" selecting "none" from namespaces "tenant-a/child"
    Then the export round-trips through format "<format>"

    Examples:
      | format |
      | bvx    |
      | json   |

  Scenario: A wrong password cannot open a bvx export
    When I export scope "all_namespaces" selecting "none" from namespaces "tenant-a/child"
    Then the bvx export cannot be opened with a wrong password

  Scenario: Exported file content restores byte for byte
    When I export scope "selective" selecting "engine:files" from namespaces "tenant-a/child"
    And file "f1" is deleted from namespace "tenant-a/child"
    And I import the export
    Then file "f1" in namespace "tenant-a/child" reads back 300000 bytes identical to the original

  # --- Restore: every scenario below applies the export to a second vault with the same
  # --- namespaces and kv mounts but none of the data (the mount table is not part of an export) ---

  Scenario Outline: A full-vault export restores every tenant, through either file format
    Given an empty destination vault with namespaces "tenant-a,tenant-a/child"
    When I export scope "all_namespaces" selecting "none" from namespaces "none"
    And I restore the export into the destination as "<format>"
    Then the destination namespace "root" secret "cubby/foo" reads "root-secret"
    And the destination namespace "tenant-a" secret "cubby/foo" reads "a-secret"
    And the destination namespace "tenant-a" secret "other/bar" reads "a-other"
    And the destination namespace "root" file "r1" reads back 2048 bytes identical to the original
    And the destination namespace "tenant-a/child" file "f1" reads back 300000 bytes identical to the original
    And the destination namespace "root" policy "reader" matches the source
    And the destination namespace "tenant-a" policy "tenant-reader" matches the source

    Examples:
      | format |
      | bvx    |
      | json   |

  Scenario: Identically named mounts in two namespaces do not overwrite each other on restore
    Given an empty destination vault with namespaces "tenant-a,tenant-a/child"
    When I export scope "all_namespaces" selecting "none" from namespaces "none"
    And I restore the export into the destination as "bvx"
    Then the destination namespace "root" secret "cubby/foo" reads "root-secret"
    And the destination namespace "tenant-a" secret "cubby/foo" reads "a-secret"

  Scenario: A full export restores the root namespace only
    Given an empty destination vault with namespaces "tenant-a,tenant-a/child"
    When I export scope "full" selecting "none" from namespaces "none"
    And I restore the export into the destination as "bvx"
    Then the destination namespace "root" secret "cubby/foo" reads "root-secret"
    And the destination namespace "tenant-a" has no secret "cubby/foo"
    And the destination namespace "tenant-a/child" has no file "f1"

  Scenario: An engine export of one nested namespace restores that namespace's files
    Given an empty destination vault with namespaces "tenant-a,tenant-a/child"
    When I export scope "selective" selecting "engine:files" from namespaces "tenant-a/child"
    And I restore the export into the destination as "bvx"
    Then the destination namespace "tenant-a/child" file "f1" reads back 300000 bytes identical to the original
    And the destination namespace "root" has no file "r1"
    And the destination namespace "tenant-a" has no secret "cubby/foo"

  Scenario: A mount export restores only that mount
    Given an empty destination vault with namespaces "tenant-a"
    When I export scope "selective" selecting "mount:cubby/" from namespaces "tenant-a"
    And I restore the export into the destination as "bvx"
    Then the destination namespace "tenant-a" secret "cubby/foo" reads "a-secret"
    And the destination namespace "tenant-a" has no secret "other/bar"

  Scenario: A KV-path export restores only that path
    Given an empty destination vault with namespaces "tenant-a"
    When I export scope "selective" selecting "kv:other/bar" from namespaces "tenant-a"
    And I restore the export into the destination as "bvx"
    Then the destination namespace "tenant-a" secret "other/bar" reads "a-other"
    And the destination namespace "tenant-a" has no secret "cubby/foo"

  Scenario: Every split part restores into the destination
    Given an empty destination vault with namespaces "tenant-a,tenant-a/child"
    When I export scope "all_namespaces" selecting "none" from namespaces "none" split by namespace
    And I restore every split part into the destination
    Then the destination namespace "root" secret "cubby/foo" reads "root-secret"
    And the destination namespace "tenant-a" secret "cubby/foo" reads "a-secret"
    And the destination namespace "tenant-a/child" file "f1" reads back 300000 bytes identical to the original

  Scenario: Restoring only chosen namespaces leaves the others untouched
    Given an empty destination vault with namespaces "tenant-a,tenant-a/child"
    When I export scope "all_namespaces" selecting "none" from namespaces "none"
    And I restore only namespaces "tenant-a/child" into the destination
    Then the destination namespace "tenant-a/child" file "f1" reads back 300000 bytes identical to the original
    And the destination namespace "root" has no secret "cubby/foo"
    And the destination namespace "tenant-a" has no secret "cubby/foo"

  Scenario: Restoring only chosen mounts leaves the other mounts untouched
    Given an empty destination vault with namespaces "tenant-a"
    When I export scope "selective" selecting "engine:kv" from namespaces "tenant-a"
    And I restore only mounts "other/" into the destination
    Then the destination namespace "tenant-a" secret "other/bar" reads "a-other"
    And the destination namespace "tenant-a" has no secret "cubby/foo"

  Scenario: A preview classifies the restore but writes nothing
    Given an empty destination vault with namespaces "tenant-a,tenant-a/child"
    When I export scope "all_namespaces" selecting "none" from namespaces "none"
    And I preview the restore into the destination
    Then the preview classified items as new
    And the destination namespace "tenant-a" has no secret "cubby/foo"
    And the destination namespace "tenant-a/child" has no file "f1"

  Scenario: Restoring into a vault that lacks the mount warns instead of silently losing the data
    Given an empty destination vault without mounts with namespaces "tenant-a"
    When I export scope "selective" selecting "mount:cubby/" from namespaces "tenant-a"
    And I restore the export into the destination as "bvx"
    Then the restore warns about "does not exist on this vault"
    And the destination namespace "tenant-a" has no secret "cubby/foo"

  Scenario: A bundle for a namespace the destination lacks is reported, not written into root
    Given an empty destination vault with namespaces "none"
    When I export scope "all_namespaces" selecting "none" from namespaces "tenant-a"
    And I restore the export into the destination as "bvx"
    Then the restore warns about "tenant-a"
    And the destination namespace "root" has no secret "cubby/foo"

  Scenario: Conflict policy skip keeps the destination's existing secret
    Given an empty destination vault with namespaces "tenant-a"
    And the destination namespace "tenant-a" has a kv mount "cubby/" with secret "foo" = "dest-original"
    When I export scope "selective" selecting "mount:cubby/" from namespaces "tenant-a"
    And I restore the export into the destination with conflict policy "skip"
    Then the destination namespace "tenant-a" secret "cubby/foo" reads "dest-original"
    And the restore skipped at least 1 items

  Scenario: Conflict policy overwrite replaces the destination's existing secret
    Given an empty destination vault with namespaces "tenant-a"
    And the destination namespace "tenant-a" has a kv mount "cubby/" with secret "foo" = "dest-original"
    When I export scope "selective" selecting "mount:cubby/" from namespaces "tenant-a"
    And I restore the export into the destination with conflict policy "overwrite"
    Then the destination namespace "tenant-a" secret "cubby/foo" reads "a-secret"

  Scenario: Conflict policy rename preserves the original and keeps the imported copy
    Given an empty destination vault with namespaces "tenant-a"
    And the destination namespace "tenant-a" has a kv mount "cubby/" with secret "foo" = "dest-original"
    When I export scope "selective" selecting "mount:cubby/" from namespaces "tenant-a"
    And I restore the export into the destination with conflict policy "rename"
    Then the destination namespace "tenant-a" secret "cubby/foo" reads "dest-original"
    And the restore renamed at least 1 items
