Feature: Hiqlite storage backend
  As BastionVault
  I need a Raft-replicated SQLite storage backend
  So that secrets are persisted with high availability

  Background:
    Given a hiqlite backend
    And the vault table is empty

  Scenario: Store and retrieve an entry
    When I store key "secret/foo" with value "bar_data"
    And I get key "secret/foo"
    Then the result should contain key "secret/foo"
    And the result should contain value "bar_data"

  Scenario: Get returns empty for missing key
    When I get key "nonexistent/key"
    Then the result should be empty

  Scenario: Delete an entry
    When I store key "secret/to_delete" with value "temporary"
    And I delete key "secret/to_delete"
    And I get key "secret/to_delete"
    Then the result should be empty

  Scenario: Delete a nonexistent key succeeds
    When I delete key "nonexistent/key"

  Scenario: List entries at root
    When I store key "alpha" with value "val1"
    And I store key "beta/one" with value "val2"
    And I list keys with prefix ""
    Then the key list should have 2 entries
    And the key list should contain "alpha"
    And the key list should contain "beta/"

  Scenario: List entries with prefix
    When I store key "app/db/host" with value "localhost"
    And I store key "app/db/port" with value "5432"
    And I store key "app/cache/ttl" with value "300"
    And I list keys with prefix "app/"
    Then the key list should have 2 entries
    And the key list should contain "db/"
    And the key list should contain "cache/"

  Scenario: List returns empty for unmatched prefix
    When I store key "secret/foo" with value "bar"
    And I list keys with prefix "other/"
    Then the key list should have 0 entries

  Scenario: Overwrite an existing entry
    When I store key "secret/mutable" with value "original"
    And I store key "secret/mutable" with value "updated"
    And I get key "secret/mutable"
    Then the result should contain value "updated"
