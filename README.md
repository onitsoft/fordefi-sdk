# fordefi-sdk

SDK for interacting with the [ForDeFi API](https://docs.fordefi.com/api/openapi).

## Installation

To install the package, run the following command:

```bash
# update the tag v.0.5.1 to the latest version
pip install git+https://github.com/onitsoft/fordefi-sdk.git@v0.5.1#egg=fordefi-sdk
```

Or add the following line to your `requirements.txt` file and
run `pip install -r requirements.txt`:

```txt
# update the tag v.0.5.1 to the latest version
git+https://github.com/onitsoft/fordefi-sdk.git@0.5.1#egg=fordefi-sdk
```

## Usage

```python
from fordefi.client import Fordefi

fordefi = Fordefi(
    api_key="<FORDEFI-API-KEY>",
    private_key="<FORDEFI-PRIVATE-KEY>",
    base_url="https://api.fordefi.com/api/v1",  # Optional, defaults to this URL
    page_size=50,  # Optional, default page size
    timeout=30  # Optional, request timeout in seconds
)

vaults: Iterable[JsonDict] = client.list_vaults()

vault: JsonDict = client.get_vault("<VAULT-ID>")

vault_assets: Iterable[JsonDict] = client.get_assets("<VAULT-ID>")

all_assets: Iterable[JsonDict] = client.list_assets(
    vault_ids=[
        "<VAULT-ID>1",
        "<VAULT-ID>2",
        "<VAULT-ID>3",
    ],
)

response = client.create_transfer(
    vault_id="<VAULT-ID>",
    destination_address="0x1234567890123456789012345678901234567890",
    amount=Decimal('1000000000000000000'),  # Example for 1 ETH (in Wei)
    idempotence_client_id=UUID("63af32c1-c737-4435-a7e5-03edadee62a6"),
    asset=Asset(
        blockchain=Blockchain.ARBITRUM,
        token=Token(
            token_type=EvmTokenType.ERC20,
            token_id="0x1234567890123456789012345678901234567890", # contract address
        ),
    ),
)

transactions: Iterable[JsonDict] = client.list_transactions()

# sign a EIP-712 message
# https://eips.ethereum.org/EIPS/eip-712
message = EIP712TypedData({
    "types": {
         "Message": [
            {"name": "contents", "type": "string"},
        ],
    },
    "primaryType": "Message",
    "domain": EIP712Domain(
        {
            "name": "Ether Mail",
            "version": "1",
            "chainId": 1,
            "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
        },
    ),
    "message": {
        "contents": "Hello, Bob!",
    },
})
signed_message: SignedMessage = client.sign_message(
    message=message,
    blockchain=blockchain,
    blockchain=Blockchain.ARBITRUM,
    vault_id="<VAULT-ID>",
)
r, s, v = sign_message
```

## Development

### Setup

1. Install [uv](https://docs.astral.sh/uv/getting-started/installation/)

   ```bash
   curl -LsSf https://astral.sh/uv/install.sh | sh
   ```

1. Create a virtual environment:

   ```bash
   uv venv -p 3.11 .venv
   ```

1. Install the dependencies:

   ```bash
   . .venv/bin/activate
   uv sync
   ```

1. Create an `.env` file:

   ```bash
   cp .env.example .env
   ```

1. Create an [API User](https://docs.fordefi.com/developers/getting-started/create-an-api-user)
   and set `FORDEFI_API_KEY` in the `.env` with the corresponding API Key.

1. Install the [direnv](https://direnv.net/docs/installation.html).

1. Allow `direnv` so it loads the environment variables and the virtual
   environment when you `cd` into the project directory:

   ```bash
   direnv allow
   ```

1. Install the pre-commit hooks:

   ```bash
   pre-commit install
   ```

### Linting

```bash
pre-commit run --all-files
```

### Testing

To run all test with coverage:

```bash
pytest -c pytest-cov.ini
```

The tests record and replay HTTP interactions using [VCR.py](https://vcrpy.readthedocs.io/en/latest/).

The [pytest-recording](https://github.com/kiwicom/pytest-recording) plugin stores,
and loads the VCR cassettes for each test decorated with `@pytest.mark.vcr`
from the appropriate YAML files.

It also provides `pytest` command-line options to control the recording behavior.

To run the tests with the recorded HTTP interactions:

```bash
pytest tests/test_client.py::test_list_vaults
```

or

```bash
pytest --record-mode=none tests/test_client.py::test_list_vaults
```

To record new HTTP interactions and replay recorded ones, e.g. after adding endpoints:

```bash
pytest --record-mode=once tests/test_client.py
```

To (re-)record all HTTP interactions, e.g. when the API changes,
when you change the request, or when you change the test data:

```bash
pytest --record-mode=rewrite tests/test_client.py::test_list_vaults
```

Refer to the [VCR.py documentation](https://vcrpy.readthedocs.io/en/latest/usage.html#record-modes)
for other modes.

### End-to-End Testing

To run the tests without replaying the recorded HTTP interactions, i.e.,
end-to-end with real Fordefi:

```bash
pytest --disable-recording tests/test_client.py::test_list_vaults
```

Some Fordefi write operations as _creating transfers_ or _sign messages_ only complete
after a running [API Signer](https://docs.fordefi.com/developers/getting-started/set-up-an-api-signer)
signs them. For testing most testing purposes, there is no need to run it.
The operations will stay in _Pending signature_ status but you be able to ensure
that the HTTP interactions with Fordefi API succeed.

If you need to specifically test signing, like in _sign message_ operations,
you can run a API Signer locally.
It will pull pending signatures form Fordefi API periodically, sign and
send the signatures to Fordefi.

To run the API Signer locally:

1. Request the password for the docker registry
   [fordefi.jfrog.io](fordefi.jfrog.io).

1. Pull the API Signer docker image and type the password when prompted:

   ```bash
   ./scripts/get-local-signer.sh
   ```

1. Generate an SSH key pair:

   ```bash
   ./scripts/keys.py gen-keys
   ```

1. Run the API Signer docker image:

   ```bash
   ./scripts/run-local-signer.sh
   ```

1. Select **Register API user key**

1. Select API User from the list and press **Enter**

1. Paste the generated SSH public key and press **Enter**

1. Activate the API Signer in
   [Fordefi dashboard](https://docs.fordefi.com/developers/getting-started/set-up-an-api-signer/activate-api-signer).

Find more details in the [Fordefi documentation](https://docs.fordefi.com/developers/program-overview).
