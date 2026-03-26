import pytest
import yaml
from pathlib import Path

ROOT_DIR = Path(__file__).parent.parent / "semgrep-rules"
YAML_FILES = list(ROOT_DIR.rglob("*.yaml")) + list(ROOT_DIR.rglob("*.yml"))

ASSET_TYPE_METADATA = {
    "algorithm": ["algorithmPrimitive", "algorithmFamily"],
    "related-crypto-material": [],
    "protocol": ["protocolType"],
    "certificate": []
}

ALGORITHM_PRIMITIVE_METADATA = [
    "ae", "block-cipher", "stream-cipher", "hash", "signature", "mac", 
    "kdf", "pke", "key-agree", "kem", "drbg", "xof", "key-wrap", "other"
]

@pytest.mark.parametrize("filepath", YAML_FILES)
def test_yaml_required_metadata(filepath):
    """Test that each YAML file contains required crypto metadata"""
    with open(filepath, "r") as f:
        try:
            ruleset = yaml.safe_load(f)
        except yaml.YAMLError as e:
            pytest.fail(f"File {filepath} is not valid YAML: {e}")

    assert "rules" in ruleset, f"File '{filepath}' is missing the 'rules' list"

    for index, rule in enumerate(ruleset["rules"]):
        rule_id = rule.get("id", f"at index {index}")

        crypto = rule.get("metadata", {}).get("crypto")
        assert crypto, f"Rule '{rule_id}' in '{filepath}' is missing 'metadata.crypto' block"

        # Check required assetType values and fields
        assert "assetType" in crypto, f"Rule '{rule_id}' is missing 'assetType' in crypto metadata"
        asset_type = crypto["assetType"]
        assert asset_type in ASSET_TYPE_METADATA, f"Rule '{rule_id}' has unknown assetType: {asset_type}"

        required_fields = ASSET_TYPE_METADATA[asset_type]
        for field in required_fields:
            assert field in crypto, f"Rule '{rule_id}' (type: {asset_type}) is missing field: '{field}'"

        # Check required values for algorithm assetType
        if asset_type == "algorithm":
            primitive_value = crypto.get("algorithmPrimitive")
            assert primitive_value in ALGORITHM_PRIMITIVE_METADATA, (
                f"Rule '{rule_id}' has invalid algorithmPrimitive: '{primitive_value}'. "
                f"Allowed: {ALGORITHM_PRIMITIVE_METADATA}"
            )
