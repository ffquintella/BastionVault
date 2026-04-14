Feature: Hiqlite HA cluster operations
  As a BastionVault operator
  I need the cluster to handle node lifecycle events
  So that the vault remains available during maintenance and failures

  Scenario: Single-node cluster reports as leader and healthy
    Given a single-node hiqlite cluster
    Then the node should be the leader
    And the cluster should be healthy

  Scenario: Cluster status shows storage type
    Given a single-node hiqlite cluster
    When I query the cluster status
    Then the storage type should be "hiqlite"
    And the cluster flag should be true

  Scenario: Health endpoint returns correct status for active node
    Given a single-node hiqlite cluster
    When I query the health endpoint
    Then the node should not be in standby
    And the cluster should be healthy

  Scenario: Data survives node restart
    Given a single-node hiqlite cluster
    When I store key "persist/test" with value "survive_restart"
    And I restart the node
    And I get key "persist/test"
    Then the result should contain value "survive_restart"

  Scenario: Migration copies all data between backends
    Given a file backend with test data
    And an empty hiqlite backend
    When I migrate from file to hiqlite
    Then all entries should exist in the hiqlite backend
    And the entry count should match
