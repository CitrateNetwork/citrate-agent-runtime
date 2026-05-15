Feature: query-supplier-status capsule
  As an Operator
  I want to read a supplier row from SupplierRegistry
  So that I can audit supplier qualification state

  Scenario: encodes get(bytes32) calldata
    Given the capsule is loaded with the SupplierRegistry allow-list
    When the operator calls query(supplier-id=0x<32-hex>)
    Then the eth-call calldata starts with selector(get(bytes32))
    And the next 32 bytes equal the supplied supplier-id

  Scenario: decodes a static-struct response
    Given the host fn returns a 192-byte response with state=3, registered_at=42
    When the operator calls query(...)
    Then the result is Ok with state=3 and registered-at=42

  Scenario: rejects malformed supplier-id hex
    When the operator calls query(supplier-id="not-hex")
    Then the result is Err with prefix "expected 32-byte hex"
