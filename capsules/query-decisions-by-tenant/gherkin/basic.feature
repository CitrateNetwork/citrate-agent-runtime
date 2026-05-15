Feature: query-decisions-by-tenant capsule (multi-call)
  As an Operator
  I want to read the N most-recent decisions for a tenant
  So that I can audit recent activity in AgentDecisionRegistryV2

  Scenario: encodes both call selectors correctly
    Given the capsule is loaded with the AgentDecisionRegistryV2 allow-list
    When the operator calls query(tenant=0x..., n=3)
    Then the first eth-call calldata starts with selector(latestByTenant(bytes32,uint256))
    And subsequent eth-calls (one per returned ID) start with selector(getDecision(bytes32))

  Scenario: decodes 2 decisions into structured summaries
    Given the host fn returns an ID array of length 2
    And the host fn returns two valid getDecision responses
    When the operator calls query(tenant, n=10)
    Then the result is Ok with a list of 2 decision-summary records
    And each record exposes decision-id, user, tenant, corr-id, class, recorded-at-block

  Scenario: caps n at 50
    Given the operator passes n=100
    When the capsule encodes the latestByTenant calldata
    Then the encoded n value is 50, not 100
