//! HUP-S3.4: the SkillRegistry publish payload is byte-identical to what `cast` encodes for the
//! deployed contract's `registerSkill(string,string,string,string,string[])`, and it is built only.
use citrate_agent_learn::registry::*;

fn fixture() -> serde_json::Value {
    let raw = include_str!("fixtures/register_skill_cast.json");
    serde_json::from_str(raw).expect("fixture parses")
}

#[test]
fn the_selector_is_keccak_of_the_contract_signature() {
    let fx = fixture();
    assert_eq!(
        REGISTER_SKILL_SIGNATURE,
        "registerSkill(string,string,string,string,string[])"
    );
    assert_eq!(
        format!("0x{}", hex_lower(&register_skill_selector())),
        fx["selector"].as_str().unwrap()
    );
}

fn hex_lower(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn calldata_matches_cast_for_every_fixture_case() {
    let fx = fixture();
    for case in fx["calldata"].as_array().unwrap() {
        let tags: Vec<String> = case["tags"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t.as_str().unwrap().to_string())
            .collect();
        let data = encode_register_skill(
            case["name"].as_str().unwrap(),
            case["version"].as_str().unwrap(),
            case["manifest_cid"].as_str().unwrap(),
            case["description"].as_str().unwrap(),
            &tags,
        );
        assert_eq!(
            format!("0x{}", hex_lower(&data)),
            case["calldata"].as_str().unwrap(),
            "case {}",
            case["name"]
        );
    }
}

#[test]
fn skill_hash_matches_the_contracts_keccak_of_owner_name_version() {
    let fx = fixture();
    for sh in fx["skill_hash"].as_array().unwrap() {
        let owner = parse_address(sh["owner"].as_str().unwrap()).unwrap();
        let h = skill_hash(
            &owner,
            sh["name"].as_str().unwrap(),
            sh["version"].as_str().unwrap(),
        );
        assert_eq!(format!("0x{}", hex_lower(&h)), sh["hash"].as_str().unwrap());
    }
}

#[test]
fn addresses_must_be_20_byte_hex() {
    assert!(parse_address("0x00000000000000000000000000000000000000aa").is_ok());
    assert!(parse_address("0X00000000000000000000000000000000000000AA").is_ok());
    assert!(
        parse_address("00000000000000000000000000000000000000aa").is_err(),
        "0x required"
    );
    assert!(parse_address("0x00aa").is_err());
    assert!(parse_address("0x00000000000000000000000000000000000000zz").is_err());
    assert!(parse_address("0x000000000000000000000000000000000000000000").is_err());
}

#[test]
fn versions_are_plain_semver_core() {
    for ok in ["0.1.0", "1.0.0", "10.20.30"] {
        assert!(valid_version(ok), "{ok}");
    }
    for bad in [
        "",
        "1",
        "1.0",
        "1.0.0.0",
        "v1.0.0",
        "01.0.0",
        "1.0.0-rc1",
        "1..0",
        "1.0.x",
    ] {
        assert!(!valid_version(bad), "{bad}");
    }
}

#[test]
fn tags_and_cids_are_bounded() {
    assert!(valid_tag("solidity"));
    assert!(valid_tag("sha256:0123abcd"));
    assert!(!valid_tag(""));
    assert!(!valid_tag("Has Space"));
    assert!(!valid_tag(&"a".repeat(MAX_TAG_LEN + 1)));
    assert!(
        valid_manifest_cid(""),
        "empty = pending pin, which the contract allows"
    );
    assert!(valid_manifest_cid(
        "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"
    ));
    assert!(valid_manifest_cid(
        "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"
    ));
    assert!(!valid_manifest_cid("ipfs://bafy"));
    assert!(!valid_manifest_cid("bafy with space"));
    assert!(!valid_manifest_cid(&"b".repeat(MAX_CID_LEN + 1)));
}
