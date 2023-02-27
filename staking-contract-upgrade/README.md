# Staking contract upgrader

This tool is used to upgrade the staking contract to the latest version.

### Calldata update

Generate upgrade calldata by batch of 200 validator

``cargo run -- --rpc-url https://localhost:8545 --limit 200 ``

### Verification

Verify the upgrade is done properly, panics if a timestamp is not correct

``cargo run -- --rpc-url https://localhost:8545  --verify``