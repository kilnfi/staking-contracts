import { ethers } from 'ethers';
import { init, verify } from '@chainsafe/bls';
import { ssz } from '@chainsafe/lodestar-types';
import {
    DepositMessage,
    ForkData,
    SigningData,
} from '@chainsafe/lodestar-types/lib/phase0/types';
import { DOMAIN_DEPOSIT } from '@chainsafe/lodestar-params';
import { load } from 'ts-dotenv';
import StakingContractAbi from './StakingContract.abi';
import fs from 'fs';

const FORK_VERSIONS: { [key: string]: Buffer } = {
    mainnet: Buffer.from('00000000', 'hex'),
    prater: Buffer.from('00001020', 'hex'),
    pyrmont: Buffer.from('00002009', 'hex'),
};
const GENESIS_VALIDATOR_ROOT = Buffer.from('00'.repeat(32), 'hex');

const env = load({
    EXECUTION_LAYER_RPC: String,
    STAKING_CONTRACT_ADDRESS: String,
    NETWORK: String,
});

const initBls = async (): Promise<void> => {
    await init('herumi');
};

const generateForkData = (forkVersion: Buffer): ForkData => {
    return {
        currentVersion: forkVersion,
        genesisValidatorsRoot: GENESIS_VALIDATOR_ROOT,
    };
};

const generateDepositDomain = (forkVersion: Buffer): Buffer => {
    const forkData = generateForkData(forkVersion);

    return Buffer.concat([
        Buffer.from(DOMAIN_DEPOSIT),
        ssz.phase0.ForkData.hashTreeRoot(forkData).slice(0, 28),
    ]);
};

interface ValidatorData {
    transactions: {
        contractInputsValues: {
            _publicKeys: string;
            _signatures: string;
            _keyCount: string;
        };
    }[];
}

const readValidatorDataFromJson = (filePath: string): ValidatorData => {
    const rawData = fs.readFileSync(filePath, 'utf8');
    return JSON.parse(rawData);
};

const splitConcatenatedData = (data: string, chunkSize: number): string[] => {
    const result = [];
    for (let i = 2; i < data.length; i += chunkSize) { // Start from 2 to skip '0x'
        result.push('0x' + data.slice(i, i + chunkSize));
    }
    return result;
};

const main = async () => {
    await initBls();
    let hasInvalid = false;
    const network = env.NETWORK;
    const provider = new ethers.providers.JsonRpcProvider(
        env.EXECUTION_LAYER_RPC
    );
    const StakingContract = new ethers.Contract(
        env.STAKING_CONTRACT_ADDRESS,
        StakingContractAbi,
        provider
    );

    // Read the validator data from add-validators0.json then add-validators1.json, etc. stop when the file is not found
    let finished = false;

    let idx = 0;
    while (!finished) {
        const filePath = `../add-validators${idx}.json`;
        try {
            const validatorData = readValidatorDataFromJson(filePath);
            console.log(`Checking: ${filePath}`);
            const transaction = validatorData.transactions[0]; // Assuming we're only dealing with the auto-generated file
            const publicKeysHex = transaction.contractInputsValues._publicKeys;
            const signaturesHex = transaction.contractInputsValues._signatures;
            const keyCount = parseInt(transaction.contractInputsValues._keyCount, 10);

            const publicKeys = splitConcatenatedData(publicKeysHex, 96); // 48 bytes * 2 (hex)
            const signatures = splitConcatenatedData(signaturesHex, 192); // 96 bytes * 2 (hex)

            if (publicKeys.length !== keyCount || signatures.length !== keyCount) {
                console.error('Mismatch in key count and actual data');
                process.exit(1);
            }

            for (let idx = 0; idx < keyCount; ++idx) {
                const publicKey = publicKeys[idx];
                const signature = signatures[idx];
                const withdrawalAddress = await StakingContract.getCLFeeRecipient(publicKey);
                const withdrawalCredentials = Buffer.from(
                    `010000000000000000000000` + withdrawalAddress.slice(2),
                    'hex'
                );
                const publicKeyBuffer = Buffer.from(publicKey.slice(2), 'hex');
                //console.log(`public key: ${publicKey}`);
                const signatureBuffer = Buffer.from(signature.slice(2), 'hex');
                //console.log(`signature: ${signature}`);
                const depositMessage: DepositMessage = {
                    pubkey: publicKeyBuffer,
                    withdrawalCredentials: withdrawalCredentials,
                    amount: 32000000000,
                };
                const forkVersion: Buffer = FORK_VERSIONS[network];
                const depositDomain = generateDepositDomain(forkVersion);
                const signingData: SigningData = {
                    objectRoot:
                        ssz.phase0.DepositMessage.hashTreeRoot(depositMessage),
                    domain: depositDomain,
                };
                const signingDataRoot =
                    ssz.phase0.SigningData.hashTreeRoot(signingData);
                const valid = verify(publicKeyBuffer, signingDataRoot, signatureBuffer);
                if (!valid) {
                    console.log(
                        `INVALIDKEY ERROR: invalid key at index ${idx}`
                    );
                    hasInvalid = true;
                } else {
                    console.log(`key ${idx} is valid`);
                }
            }
            console.log('Proposal:' + JSON.stringify(filePath) + ' is valid');
        } catch (e) {
            finished = true;
        }
        idx++;
    }
};

main();