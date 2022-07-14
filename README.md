# Import one-by-one keystores with its slashing data

Import one by one keystores to the web3signer by providing the following args:

- `--keystores-path` path to the directory where keystores files are present in the format `keystore*.json`
- `--slashing-protection-path` path to the slashing protection file
- `--wallet-pasword-path` path to the wallet password file
- `--network <prater|gnosis|mainnet>

### Instructions of use

**Compile**: should be compiled with golang version 1.17

```
go build -o import-one-by-one import_one_by_one.go
```

The output will be an executable named `import-one-by-one`

**Run**:

```
./import-one-by-one --keystores-path --slashing-protection-path --wallet-password-path --network
```
