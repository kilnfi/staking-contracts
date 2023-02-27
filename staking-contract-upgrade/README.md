# Staking contract upgrader

This tool is used to upgrade the staking contract to the latest version.

### Calldata update

Generate upgrade calldata by batch of 200 validator
Each batch will be stored as a line in a file called ``calldata.txt``

``cargo run -- --rpc-url https://localhost:8545 --limit 200 ``

You may need to install some dependencies

``apt-get update && apt-get install build-essential pkgconf libssl-dev``

To change the target contract simply replace the addresses in lines 15-16 of src/main.rs

```    
deployments {
    1 => "<MAINNET ADDRESS HERE>",
    5 => "<GOERLI ADDRESS HERE>",
},
```

The code automatically select the address matching the chain id of the RPC endpoint.

### Verification

Verify the upgrade is done properly, panics if a timestamp is not correct

``cargo run -- --rpc-url https://localhost:8545  --verify``