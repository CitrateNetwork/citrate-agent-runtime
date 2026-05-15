Feature: verify-provenance-chain capsule
  As an Operator
  I want to verify a part's provenance chain
  So that I can audit traceability against PartProvenanceRegistry

  Scenario: encodes verifyChain(bytes32) calldata
    Given the capsule is loaded with the PartProvenanceRegistry allow-list
    When the operator calls query(part-hash=0x<32-hex>)
    Then the eth-call calldata starts with selector(verifyChain(bytes32))
    And the next 32 bytes equal the supplied part-hash

  Scenario: decodes (bool, bytes32[]) with non-empty chain
    Given the host fn returns ok=true and chain=[A, B, C]
    When the operator calls query(...)
    Then the result is Ok with ok=true and chain.length=3

  Scenario: empty chain is a valid response
    Given the host fn returns ok=false and chain=[]
    When the operator calls query(unknown-part-hash)
    Then the result is Ok with ok=false and chain.length=0
