Feature: eth-sender-test capsule — three-layer write-path enforcement
  As the cit-agent harness
  I want every write call to traverse allow-list + HIC + dispatcher
  So that no state change reaches the chain without operator consent

  Scenario: unauthorized address blocked at layer 1
    Given the capsule's manifest allow-lists only address X
    When send(to=Y, data=anything) is called
    Then the result is Err with prefix "ChainSendNotAuthorized"
    And the ApprovalGate is NEVER consulted
    And the EthSendDispatcher is NEVER invoked

  Scenario: HIC denial blocked at layer 2
    Given the address is allow-listed
    And the ApprovalGate returns Err("denied")
    When send(...) is called
    Then the result is Err with prefix "ChainSendApprovalRejected"
    And the EthSendDispatcher is NEVER invoked

  Scenario: full path succeeds
    Given the address is allow-listed
    And the ApprovalGate returns Ok
    And the EthSendDispatcher returns tx_hash 0xDEAD..BEEF
    When send(...) is called
    Then the result is Ok with the tx_hash bytes
    And eth_send_history records the call
