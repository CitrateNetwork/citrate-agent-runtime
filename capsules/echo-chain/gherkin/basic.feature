Feature: echo-chain capsule — chain-call allow-list enforcement
  As the cit-agent harness
  I want capsules to be blocked from calling addresses outside their manifest
  So that the per-capsule capability sandbox is empirically verifiable

  Scenario: authorized address succeeds
    Given the echo-chain capsule is loaded with manifest allow-list
      | address                                  |
      | 0x4a86659BDab24dc444C72fbbaD4cd83491820E40 |
    When I call query with to = 0x4a86659BDab24dc444C72fbbaD4cd83491820E40 and data = 0x
    Then the result is Ok with empty bytes

  Scenario: unauthorized address blocked
    Given the echo-chain capsule is loaded with manifest allow-list
      | address                                  |
      | 0x4a86659BDab24dc444C72fbbaD4cd83491820E40 |
    When I call query with to = 0x0000000000000000000000000000000000000001 and data = 0x
    Then the result is Err with prefix "ChainCallNotAuthorized"

  Scenario: malformed address blocked
    Given the echo-chain capsule is loaded with manifest allow-list
      | address                                  |
      | 0x4a86659BDab24dc444C72fbbaD4cd83491820E40 |
    When I call query with to = 0x00 (1 byte) and data = 0x
    Then the result is Err with prefix "ChainCallNotAuthorized"
