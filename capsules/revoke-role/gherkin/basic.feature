Feature: revoke-role capsule — write path via three-layer enforcement
  Scenario: encodes correct ABI calldata
    Given the manifest allow-lists the target contract
    When the operator calls the capsule's exported action
    Then the calldata sent through eth-send matches the canonical encoder

  Scenario: allow-list miss blocks at layer 1
    Given the capsule's compiled-in address differs from the manifest
    Then the host fn rejects with ChainSendNotAuthorized

  Scenario: approval denial blocks at layer 2
    Given the ApprovalGate returns Err
    Then the dispatcher is never invoked
