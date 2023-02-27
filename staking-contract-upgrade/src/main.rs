use clap::Parser;
use ethcontract::common::abi::{Function, Param, ParamType, StateMutability, Token};
use ethcontract::prelude::*;
use ethcontract::BlockNumber::Earliest;
use ethers_core::utils::hex;
use std::collections::HashMap;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

// TO CHANGE THE TARGET CONTRACT REPLACE THE ADDRESS HERE
ethcontract::contract!(
    "abi/StakingContract.json",
    contract = StakingContract,
    deployments {
        1 => "0x1e68238cE926DEC62b3FBC99AB06eB1D85CE0270",
        5 => "0xe8Ff2a04837aac535199eEcB5ecE52b2735b3543",
    },
   event_derives (serde::Deserialize, serde::Serialize),
);

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Rpc url
    #[arg(short, long, required = true)]
    rpc_url: String,

    /// Maximum number of validator batched in one call
    #[arg(short, long, default_value = "300")]
    limit: u16,

    /// Flag to verify the timestamps after the migration
    #[arg(short, long)]
    verify: bool,
}

#[allow(deprecated)]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let http = Http::new(&args.rpc_url).expect("transport failed");
    let web3 = Web3::new(http);

    let staking_contract = StakingContract::deployed(&web3)
        .await
        .expect("locating deployed contract failed");

    let chain_id = web3.net().version().await.unwrap();

    println!(
        "Generating calldata to migrate staking contract at {:?}, chain id : {}",
        staking_contract.address(),
        chain_id
    );
    println!("Retrieving all past events (this could take a while)...");
    let event_history = staking_contract
        .events()
        .deposit()
        .from_block(Earliest)
        .query()
        .await
        .expect("Couldn't get event history");

    println!("{:} deposit events found", event_history.len());
    let mut timestamp_cache = TimestampCache::new();

    if args.verify {
        println!("Verifying timestamps...");
        for event in event_history {
            // Call the contract to verify the last withdrawal is set at the right timestamp
            let timestamp = timestamp_cache
                .get_timestamp_of_block(&web3, event.meta.expect("").block_number)
                .await;
            let public_key = event.data.public_key.0;
            let pub_key_bytes = Bytes(public_key.clone());
            let stored_timestamp = staking_contract
                .get_last_withdraw(pub_key_bytes)
                .call()
                .await
                .unwrap();
            let is_valid = stored_timestamp == timestamp.into();
            println!(
                "Public key: {}, timestamp: {} is valid",
                hex::encode(&public_key),
                timestamp
            );
            if !is_valid {
                panic!("Invalid timestamp for {:?}!", &public_key);
            }
        }
        println!("All timestamps are valid! :)");
        return Ok(());
    } else {
        let func = Function {
            name: "adminSetTimestamp".to_owned(),
            inputs: vec![
                Param {
                    name: "publicKeys".to_owned(),
                    kind: ParamType::Bytes,
                    internal_type: None,
                },
                Param {
                    name: "timestamps".to_owned(),
                    kind: ParamType::Array(Box::from(ParamType::Uint(64))),
                    internal_type: None,
                },
            ],
            outputs: vec![],
            constant: false,
            state_mutability: StateMutability::NonPayable,
        };

        let file_path = "calldata.txt";
        if Path::new(file_path).exists() {
            fs::remove_file(file_path).unwrap();
        }
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .append(true)
            .open(file_path)
            .unwrap();

        println!("Generating calldata...");
        let mut public_keys = vec![];
        let mut timestamps = vec![];
        let mut i = 0;
        let mut n = 0;
        for mut event in event_history.clone() {
            public_keys.append(&mut event.data.public_key.0);
            timestamps.push(Token::Uint(
                (timestamp_cache
                    .get_timestamp_of_block(&web3, event.meta.expect("").block_number)
                    .await)
                    .into(),
            ));
            i += 1;
            if i % args.limit == 0 || i == event_history.len() as u16 {
                n += 1;
                let calldata = func
                    .encode_input(&[
                        Token::Bytes(public_keys.clone()),
                        Token::Array(timestamps.clone()),
                    ])
                    .unwrap();
                if let Err(e) = writeln!(file, "{}", hex::encode(calldata)) {
                    eprintln!("Couldn't write to file: {}", e);
                }
                println!("Batch {} done {}/{}", n, i, event_history.len());

                public_keys.clear();
                timestamps.clear();
            }
        }
    }

    Ok(())
}

struct TimestampCache {
    cache: HashMap<u64, u64>,
}

impl TimestampCache {
    fn new() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }

    async fn get_timestamp_of_block(&mut self, web3: &Web3<Http>, block_number: u64) -> u64 {
        if let Some(timestamp) = self.cache.get(&block_number) {
            return *timestamp;
        }
        let timestamp = get_timestamp_of_block(web3, block_number).await;
        self.cache.insert(block_number, timestamp);
        timestamp
    }
}

async fn get_timestamp_of_block(web3: &Web3<Http>, block_number: u64) -> u64 {
    let block = web3
        .eth()
        .block(BlockId::Number(BlockNumber::from(block_number)))
        .await
        .unwrap()
        .unwrap();
    block.timestamp.as_u64()
}
