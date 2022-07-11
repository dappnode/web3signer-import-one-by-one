package main

// This script must be executed with four arguments:
// --keystores-path <path>
// --slashing-protection-path
// --wallet-pasword-path <path>
// --network <prater|gnosis|mainnet>

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"
)

type Keystore struct {
	Crypto struct {
		KDF struct {
			Function string `json:"function"`
			Params   struct {
				DKLen int    `json:"dklen"`
				N     int    `json:"n"`
				R     int    `json:"r"`
				P     int    `json:"p"`
				Salt  string `json:"salt"`
			} `json:"params"`
			Message string `json:"message"`
		} `json:"kdf"`
		Checksum struct {
			Function string `json:"function"`
			Params   struct {
			} `json:"params"`
			Message string `json:"message"`
		} `json:"checksum"`
		Cipher struct {
			Function string `json:"function"`
			Params   struct {
				IV string `json:"iv"`
			} `json:"params"`
			Message string `json:"message"`
		} `json:"cipher"`
	} `json:"crypto"`
	Description string `json:"description"`
	Pubkey      string `json:"pubkey"`
	Path        string `json:"path"`
	UUID        string `json:"uuid"`
	Version     int    `json:"version"`
}

type SlashingProtection struct {
	Metadata struct {
		InterchangeFormatVersion string `json:"interchange_format_version"`
		GenesisValidatorsRoot    string `json:"genesis_validators_root"`
	} `json:"metadata"`
	Data []PubkeyData `json:"data"`
}

type PubkeyData struct {
	Pubkey       string `json:"pubkey"`
	SignedBlocks []struct {
		Slot        string `json:"slot"`
		SigningRoot string `json:"signing_root"`
	} `json:"signed_blocks"`
	SignedAttestations []struct {
		SourceEpoch string `json:"source_epoch"`
		TargetEpoch string `json:"target_epoch"`
		SigningRoot string `json:"signing_root"`
	} `json:"signed_attestations"`
}

func main() {
	if len(os.Args) != 9 {
		fmt.Println("Usage: migrate-manual --keystores-path <path> --slashing-protection-path <path> --wallet-password-path <path> --network <prater|gnosis|mainnet>")
		os.Exit(1)
	}

	keystoresPath := ""
	slashingProtectionPath := ""
	walletPasswordPath := ""
	network := ""
	for i := 0; i < len(os.Args); i++ {
		if os.Args[i] == "--keystores-path" {
			keystoresPath = os.Args[i+1]
		}
		if os.Args[i] == "--slashing-protection-path" {
			slashingProtectionPath = os.Args[i+1]
		}

		if os.Args[i] == "--wallet-password-path" {
			walletPasswordPath = os.Args[i+1]
		}

		if os.Args[i] == "network" {
			network = os.Args[i+1]
		}
	}
	if keystoresPath == "" {
		fmt.Println("keystores path not provided")
		os.Exit(1)
	}

	if slashingProtectionPath == "" {
		fmt.Println("slashing protection path not provided")
		os.Exit(1)
	}

	if walletPasswordPath == "" {
		fmt.Println("wallet password path not provided")
		os.Exit(1)
	}

	if network == "" {
		fmt.Println("network api url not provided")
		os.Exit(1)
	}

	web3signerApiUrl, err := getWeb3signerApiUrl(network)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	migrationDns, err := getMigrationDns(network)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// load slashing protection
	slashingProtection, err := loadSlashingProtection(slashingProtectionPath)
	if err != nil {
		fmt.Println("error loading slashing protection:", err)
		os.Exit(1)
	}

	// load wallet password (it is in txt format)
	walletPassword, err := loadTxt(walletPasswordPath)
	if err != nil {
		fmt.Println("error loading wallet password:", err)
		os.Exit(1)
	}

	// Iterate over all files in format "keystore*.json" at the path --keystores-path
	files, err := ioutil.ReadDir(keystoresPath)
	if err != nil {
		fmt.Println("error reading keystores directory:", err)
		os.Exit(1)
	}
	for _, file := range files {
		if !file.IsDir() {
			if !strings.HasPrefix(file.Name(), "keystore") {
				continue
			}
			keystorePath := keystoresPath + "/" + file.Name()
			keystore, err := loadKeystore(keystorePath)
			if err != nil {
				fmt.Println("error loading keystore:", err)
				os.Exit(1)
			}

			requestBody := createRequestBody(keystore, walletPassword, slashingProtection)

			response, err := importKeystore(requestBody, web3signerApiUrl, migrationDns)
			if err != nil {
				fmt.Println("error importing keystore:", err)
				os.Exit(1)
			}

			fmt.Println("imported keystore:", file.Name())
			fmt.Println("response:", response)
		}
	}
}

func createRequestBody(keystore Keystore, walletPassword string, slashingProtection SlashingProtection) string {
	// keystore
	keystoreJson, err := json.Marshal(keystore)
	if err != nil {
		fmt.Println("error marshalling keystore:", err)
		os.Exit(1)
	}
	keystoreStr := string(keystoreJson)
	keystoreStr = strings.Replace(keystoreStr, "\"", "\\\"", -1)
	keystoreStr = strings.Replace(keystoreStr, "\n", "\\n", -1)

	// slashing protection (if any)
	slashingProtectionPubkeyStr := ""
	for _, pubkeyData := range slashingProtection.Data {
		if pubkeyData.Pubkey == "0x"+keystore.Pubkey {
			slashingProtectionPubkey := SlashingProtection{
				Metadata: slashingProtection.Metadata,
				Data: []PubkeyData{
					{
						Pubkey:             pubkeyData.Pubkey,
						SignedBlocks:       pubkeyData.SignedBlocks,
						SignedAttestations: pubkeyData.SignedAttestations,
					},
				},
			}

			slashingProtectionPubkeyJson, err := json.Marshal(slashingProtectionPubkey)
			if err != nil {
				fmt.Println("error marshalling slashing protection:", err)
				os.Exit(1)
			}

			slashingProtectionPubkeyStr := string(slashingProtectionPubkeyJson)
			slashingProtectionPubkeyStr = strings.Replace(slashingProtectionPubkeyStr, "\"", "\\\"", -1)
			slashingProtectionPubkeyStr = strings.Replace(slashingProtectionPubkeyStr, "\n", "\\n", -1)
			break
		}
	}

	return fmt.Sprintf(`{"keystores": ["%s"], "passwords": ["%s"], "slashing_protection": "%s"}`, keystoreStr, walletPassword, slashingProtectionPubkeyStr)
}

func importKeystore(body string, web3signerApiUrl string, migrationDns string) (string, error) {
	// create a post request with the body and the headers
	req, err := http.NewRequest("POST", web3signerApiUrl+"/eth/v1/keystores", bytes.NewBuffer([]byte(body)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Host = migrationDns
	var responseBody string
	for i := 0; i < 5; i++ {
		resp, err := http.Post(web3signerApiUrl+"/eth/v1/keystores", "application/json", bytes.NewBuffer([]byte(body)))
		if err != nil {
			fmt.Println("error POSTing to web3signer API:", err)
			time.Sleep(3 * time.Second)
			continue
		}
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Println("error reading response body:", err)
			time.Sleep(3 * time.Second)
			continue
		}
		responseBody = string(body)
		break
	}
	return responseBody, nil
}

func loadSlashingProtection(path string) (SlashingProtection, error) {
	var slashingProtection SlashingProtection
	err := loadJson(path, &slashingProtection)
	if err != nil {
		return slashingProtection, err
	}
	return slashingProtection, nil
}

func loadKeystore(path string) (Keystore, error) {
	var keystore Keystore
	err := loadJson(path, &keystore)
	if err != nil {
		return keystore, err
	}
	return keystore, nil
}

func loadJson(path string, v interface{}) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	err = decoder.Decode(v)
	if err != nil {
		return err
	}

	return nil
}

func loadTxt(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Scan()
	return scanner.Text(), nil
}

func getWeb3signerApiUrl(network string) (string, error) {
	if network == "gnosis" || network == "prater" {
		return "http://web3signer.web3signer-" + network + ".dappnode:9000", nil
	} else if network == "mainnet" {
		return "http://web3signer.web3signer.dappnode:9000", nil
	} else {
		return "", errors.New("network not supported")
	}
}

func getMigrationDns(network string) (string, error) {
	if network == "gnosis" || network == "prater" {
		return "prysm.migration-" + network + ".dappnode", nil
	} else if network == "mainnet" {
		return "prysm.migration.dappnode", nil
	} else {
		return "", errors.New("network not supported")
	}
}
