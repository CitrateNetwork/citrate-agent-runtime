Feature: hello capsule — pure-compute proof of pipeline
  As an Operator
  I want the hello capsule to load and execute
  So that the build → archive → load → instantiate pipeline is verified

  Scenario: greet returns a personalized greeting
    Given the hello capsule is loaded
    When I call greet with "Saul"
    Then the result is "Hello, Saul"

  Scenario: greet handles empty name
    Given the hello capsule is loaded
    When I call greet with ""
    Then the result is "Hello, world"

  Scenario: capsule has zero side effects
    Given the hello capsule is loaded
    Then the capsule's manifest declares network = "none"
    And the capsule's manifest declares filesystem = []
    And the capsule's manifest declares chain_calls = []
