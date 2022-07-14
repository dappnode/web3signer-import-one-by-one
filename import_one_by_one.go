package main

// This script must be executed with four arguments:
// --keystores-path <path>
// --slashing-protection-path (optional)
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
	if len(os.Args) != 9 && len(os.Args) != 7 {
		fmt.Println("Usage: migrate-manual --keystores-path <path> --slashing-protection-path <path> (optional) --wallet-password-path <path> --network <prater|gnosis|mainnet>")
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

		if os.Args[i] == "--network" {
			network = os.Args[i+1]
		}
	}
	if keystoresPath == "" {
		fmt.Println("keystores path not provided")
		os.Exit(1)
	}

	if walletPasswordPath == "" {
		fmt.Println("wallet password path not provided")
		os.Exit(1)
	}

	if network == "" {
		fmt.Println("network not provided")
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

	slashingProtection := SlashingProtection{}
	if slashingProtectionPath != "" {
		// load slashing protection
		slashingProtection, err = loadSlashingProtection(slashingProtectionPath)
		if err != nil {
			fmt.Println("error loading slashing protection:", err)
			os.Exit(1)
		}
	}

	// load wallet password (it is in txt format)
	walletPassword, err := loadTxt(walletPasswordPath)
	if err != nil {
		fmt.Println("error loading wallet password:", err)
		os.Exit(1)
	}

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

			responseBody, responseStatus, err := importKeystore(requestBody, web3signerApiUrl, migrationDns)
			if err != nil {
				fmt.Println("error importing keystore:", err)
				os.Exit(1)
			}

			// check response status
			if responseStatus != 200 {
				fmt.Println("error importing keystore:", responseBody)
				os.Exit(1)
			} else {
				fmt.Println("Keystore imported successfully:", file.Name())
				fmt.Println("response:", responseBody)
			}
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
	if slashingProtection.Data != nil {
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
	}

	// only retyrb the slashing protection if it is not empty
	if slashingProtectionPubkeyStr != "" {
		return fmt.Sprintf(`{"keystores": ["%s"], "passwords": ["%s"], "slashing_protection":"%s"}`, keystoreStr, walletPassword, slashingProtectionPubkeyStr)
	}
	return fmt.Sprintf(`{"keystores": ["%s"], "passwords": ["%s"]}`, keystoreStr, walletPassword)
}

func importKeystore(body string, web3signerApiUrl string, migrationDns string) (string, int, error) {
	req, err := http.NewRequest("POST", web3signerApiUrl+"/eth/v1/keystores", bytes.NewBuffer([]byte(body)))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Host = migrationDns
	var responseBody string
	var responseStatus int
	for i := 0; i < 5; i++ {
		resp, err := http.DefaultClient.Do(req)
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
		responseStatus = resp.StatusCode
		break
	}
	return responseBody, responseStatus, nil
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
