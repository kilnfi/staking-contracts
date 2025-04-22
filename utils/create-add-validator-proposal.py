import requests
import sys

def main():

	if len(sys.argv) != 4:
		print('Usage: create-add-validator-batch.py ACCOUNT_ID STAKING_CONTRACT FEE_RECIPIENT_IMPLEMENTATION')
		sys.exit(1)

	ACCOUNT_ID = sys.argv[1]
	STAKING_CONTRACT = sys.argv[2]
	FEE_RECIPIENT = sys.argv[3]


	api_url = ""
	chain = input('Enter the chain (1 for mainnet, 2 for testnet, 3 for devnet): ')
	if chain == '1':
		api_url = 'https://api.kiln.fi/v1/eth/onchain/v1/keys'
	if chain == '2':
		api_url = 'https://api.testnet.kiln.fi/v1/eth/onchain/v1/keys'
	if chain == '3':
		api_url = 'https://api.devnet.kiln.fi/v1/eth/onchain/v1/keys'
	else:
		print('Invalid chain. Please enter 1 for mainnet, 2 for testnet, or 3 for devnet.')
		sys.exit(1)

		
	api_token = input('Enter the Kiln API token: ')

	total_count = input('Enter the total number of validators to create: ')

	tx_batch_size = int(input('Enter the transaction batch size: '))

	batch_size = int(input('Enter the API query batch size: '))

	print("")

	batch_count = int(total_count) // batch_size

	concatenated_public_keys = ''
	concatenated_signatures = ''

	for i in range(batch_count):
		print(f'Querying batch {i+1} of {batch_count}')
		# Create the request
		response = requests.post(
			api_url,
			headers={
				'Content-Type': 'application/json',
				'Authorization': f'Bearer {api_token}'
			},
			json={
				'account_id': ACCOUNT_ID,
				'fee_recipient_contract_address': FEE_RECIPIENT,
				'staking_contract_address': STAKING_CONTRACT,
				'number': batch_size,
				'format': "cli_deposit"
			}
		)

		# extract the json response
		data = response.json()["data"]

		for item in data:
			concatenated_public_keys += item['pubkey']
			concatenated_signatures += item['signature']

		# extract the data and concatenate the public keys and signatures
		print(f"Done with batch {i+1}")

	print('All batches queried successfully')

	for i in range(0, int(total_count) // int(tx_batch_size)):
		pubkeys = concatenated_public_keys[i*tx_batch_size*96:(i+1)*tx_batch_size*96]
		signatures = concatenated_signatures[i*tx_batch_size*192:(i+1)*tx_batch_size*192]

		# dirty way to create the transaction json
		transaction = '{"version":"1.0","chainId":"1","createdAt":1725982694510,"meta":{"name":"Transactions Batch","description":"","txBuilderVersion":"1.17.0","createdFromSafeAddress":"0xFafCba8F8F4282c4C629A6Bb4b98226A7C3E989f","createdFromOwnerAddress":"","checksum":"0x651d0ee6dc73fb8eb5bc170da82f9147e97267367af72e75cb38a05a27da26b7"},"transactions":[{"to":"'+ STAKING_CONTRACT +'","value":"0","data":null,"contractMethod":{"inputs":[{"internalType":"uint256","name":"_operatorIndex","type":"uint256"},{"internalType":"uint256","name":"_keyCount","type":"uint256"},{"internalType":"bytes","name":"_publicKeys","type":"bytes"},{"internalType":"bytes","name":"_signatures","type":"bytes"}],"name":"addValidators","payable":false},"contractInputsValues":{"_operatorIndex":"0","_keyCount":"'+str(tx_batch_size)+'","_publicKeys":"0x'+ pubkeys +'","_signatures":"0x'+ signatures +'"}}]}'

		# save in file
		with open(f'add-validators{i}.json', 'w') as f:
			f.write(transaction)

		print(f'Proposal saved in add-validators{i}.json')

	print('All proposals saved successfully')


if __name__ == "__main__":
    """ This is executed when run from the command line """
    main()