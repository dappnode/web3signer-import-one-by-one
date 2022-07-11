# Import one-by-one keystores with its slashing data

Import one by one keystores to the web3signer by providing the following args:
- `--keystores-path` path to the directory where keystores files are present in the format `keystore*.json`
- `--slashing-protection-path` path to the slashing protection file
- `--wallet-pasword-path` path to the wallet password file
- `--network <prater|gnosis|mainnet>

### Instructions of use

**Compile**: should be compiled with golang version 1.17

```
go build -o slashing-prune slashing-prune.go
```

The output will be an executable named `slashing-prune`

**Run**:

```
./slashing-prune --source-path <source path of the slashing protection file to be prunned> --target-path <target path to create the prunned slashing protection file>
```