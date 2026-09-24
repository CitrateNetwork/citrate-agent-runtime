Feature: list-compliance-posture capsule
  As an Operator
  I want to read compliance posture rows from defense_primeComplianceRegistry
  So that the harness exposes the same data the BFR-INT-12 tool returned

  Scenario: encodes correct ABI calldata
    Given the capsule's manifest allow-lists 0x8dbbbc46...d55d8
    When the operator calls query("fedramp-moderate", "0x<scope-hex>")
    Then the eth-call host fn receives calldata starting with selector(framework(bytes32,bytes32))
    And the next 32 bytes equal keccak256("fedramp-moderate")
    And the next 32 bytes equal the parsed scope bytes

  Scenario: decodes a known posture-row response
    Given the host fn returns a 288-byte response with posture=2, expires=12345
    When the operator calls query("fedramp-moderate", "0x<scope-hex>")
    Then the result is Ok with posture=2 and expires-at-block=12345

  Scenario: capsule rejects calldata for an unauthorized address
    Given the capsule's manifest allow-list does NOT include the contract address
    When the operator calls query(...)
    Then the host fn returns Err("ChainCallNotAuthorized: 0x...")
    And the capsule re-emits that error string through its result
