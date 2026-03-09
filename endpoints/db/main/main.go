package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/urfave/cli/v2"

	"github.com/OpenNHP/opennhp/endpoints/db"
	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
	ztdolib "github.com/OpenNHP/opennhp/nhp/core/ztdo"
	"github.com/OpenNHP/opennhp/nhp/log"
	"github.com/OpenNHP/opennhp/nhp/version"
)

func main() {
	initApp()
}
func initApp() {
	app := cli.NewApp()
	app.Name = "nhp-device"
	app.Usage = "device entity for NHP protocol"
	app.Version = version.Version

	runCmd := &cli.Command{
		Name:  "run",
		Usage: "create and run device process for NHP protocol",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "mode", Value: "none", Usage: "encrypt;decrypt"},
			&cli.StringFlag{Name: "source", Value: "", Usage: "source file to be encrypted, this is not required for streaming mode"},
			&cli.StringFlag{Name: "data-source-type", Value: "", Usage: "type of data source, the default value is online, supported values are online, offline and stream"},
			&cli.StringFlag{Name: "smart-policy", Value: "", Usage: "The wasm policy file"},
			&cli.StringFlag{Name: "metadata", Value: "", Usage: "metadata file"},
			&cli.StringFlag{Name: "output", Value: "", Usage: "Save path of the ztdo file or decrypted file"},
			&cli.StringFlag{Name: "access-url", Value: "", Usage: "ZTDO access url for online or offline mode or API url for streaming mode"},
			&cli.StringFlag{Name: "ztdo", Value: "", Usage: "path to the ztdo file"},
			&cli.StringFlag{Name: "ztdo-id", Value: "", Usage: "identifier of the ztdo file"},
			&cli.StringFlag{Name: "data-private-key", Value: "", Usage: "data private key with base64 format"},
			&cli.StringFlag{Name: "provider-public-key", Value: "", Usage: "provider public key with base64 format"},
		},
		Before: func(c *cli.Context) error {
			if c.String("mode") == "encrypt" {
				if c.String("data-source-type") != "" {
					if !slices.Contains([]string{"online", "offline", "stream"}, c.String("data-source-type")) {
						return errors.New("invalid --data-source-type, allowed values are online, offline and stream")
					}
				}

				if c.String("ztdo-id") != "" { // update ztdo
					if c.String("source") != "" || c.String("output") != "" || c.String("metadata") != "" || c.String("data-source-type") != "" {
						return errors.New("--source, --output, --data-source-type and --metadata are not allowed when --ztdo-id is specified")
					}
				} else { // create ztdo
					if c.String("data-source-type") != "stream" {
						if c.String("source") == "" {
							return errors.New("--source is required when --data-source-type is not stream and --ztdo-id is not specified")
						}
					} else {
						if c.String("access-url") == "" {
							return errors.New("--access-url is required when --data-source-type is stream")
						}
					}
				}

				if c.String("smart-policy") == "" {
					return errors.New("--smart-policy is required in encrypt mode")
				}

				// only be available in decrypt mode
				if c.String("ztdo") != "" || c.String("data-private-key") != "" || c.String("provider-public-key") != "" {
					return errors.New("--ztdo, --data-private-key and --provider-public-key are only allowed in decrypt mode")
				}
			} else if c.String("mode") == "decrypt" {
				if c.String("source") != "" || c.String("smart-policy") != "" || c.String("access-url") != "" {
					return errors.New("--source, --smart-policy and --access-url are only allowed in encrypt mode")
				}

				// only be available in encrypt mode
				if c.String("ztdo") == "" || c.String("output") == "" || c.String("data-private-key") == "" || c.String("provider-public-key") == "" {
					return errors.New("--ztdo, --output, --data-private-key and --provider-public-key are required in decrypt mode")
				}
			} else {
				return nil
			}

			return nil
		},
		Action: func(c *cli.Context) error {
			mode := c.String("mode")
			source := c.String("source")
			dsType := c.String("data-source-type")
			smartPolicy := c.String("smart-policy")
			metadata := c.String("metadata")
			output := c.String("output")
			ztdo := c.String("ztdo")
			ztdoId := c.String("ztdo-id")
			dataPrivateKey := c.String("data-private-key")
			accessUrl := c.String("access-url")
			providerPublicKeyBase64 := c.String("provider-public-key")

			params := db.AppParams{
				Mode:                    mode,
				Source:                  source,
				DsType:                  dsType,
				SmartPolicy:             smartPolicy,
				Metadata:                metadata,
				Output:                  output,
				ZtdoFilePath:            ztdo,
				ZtdoId:                  ztdoId,
				DataPrivateKeyBase64:    dataPrivateKey,
				AccessUrl:               accessUrl,
				ProviderPublicKeyBase64: providerPublicKeyBase64,
			}

			return runApp(params)
		},
	}

	keygenCmd := &cli.Command{
		Name:  "keygen",
		Usage: "generate key pairs for NHP devices",
		Action: func(c *cli.Context) error {
			e, err := core.NewECDH(core.ECC_CURVE25519)
			if err != nil {
				return fmt.Errorf("failed to generate key pair: %w", err)
			}
			pub := e.PublicKeyBase64()
			priv := e.PrivateKeyBase64()
			fmt.Println("Private key: ", priv)
			fmt.Println("Public key: ", pub)
			return nil
		},
	}

	pubkeyCmd := &cli.Command{
		Name:  "pubkey",
		Usage: "get public key from private key",
		Action: func(c *cli.Context) error {
			privKey, err := base64.StdEncoding.DecodeString(c.Args().First())
			if err != nil {
				return err
			}
			e, err := core.ECDHFromKey(core.ECC_CURVE25519, privKey)
			if err != nil {
				return fmt.Errorf("invalid input key: %w", err)
			}
			pub := e.PublicKeyBase64()
			fmt.Println("Public key: ", pub)
			return nil
		},
	}

	app.Commands = []*cli.Command{
		runCmd,
		keygenCmd,
		pubkeyCmd,
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}

func runApp(params db.AppParams) error {
	exeFilePath, err := os.Executable()
	if err != nil {
		return err
	}
	exeDirPath := filepath.Dir(exeFilePath)
	a := &db.UdpDevice{}
	if params.Mode == "none" {
		a.EnableOnlineReport = true
	}
	err = a.Start(exeDirPath, 4)
	if err != nil {
		return err
	}

	if params.Mode == "none" {
		termCh := make(chan os.Signal, 1)
		signal.Notify(termCh, syscall.SIGTERM, os.Interrupt, syscall.SIGABRT)

		// block until terminated
		<-termCh
		a.Stop()

		return nil
	}

	ztdo := ztdolib.NewZtdo()
	dataMsgPattern := [][]ztdolib.MessagePattern{
		{ztdolib.MessagePatternS, ztdolib.MessagePatternDHSS},
		{ztdolib.MessagePatternRS, ztdolib.MessagePatternDHSS},
	}

	dataKeyPairEccMode := ztdolib.CURVE25519

	switch params.Mode {
	case "encrypt":
		outputFilePath := params.Output
		smartPolicy, err := params.NewSmartPolicy()
		if err != nil {
			log.Error("failed to read policy file: %s", err)
			return err
		}
		if strings.HasPrefix(smartPolicy.Policy, "file://") {
			smartPolicyDir := filepath.Dir(params.SmartPolicy)
			policyPath := smartPolicy.Policy[7:]
			if !filepath.IsAbs(policyPath) {
				policyPath = filepath.Join(smartPolicyDir, policyPath)
			}

			smartPolicy.Policy, err = a.UploadFileToNHPServer(context.Background(), policyPath)
			if err != nil {
				log.Error("failed to upload policy file: %s", err)
				return err
			}
		}

		ztdoId := params.ZtdoId

		if ztdoId == "" {
			ztdoId = ztdo.GetObjectID()

			var metadata string

			if smartPolicy.Embedded {
				structMetadata, err := params.LoadMetadataAsStruct()
				if err != nil {
					log.Error("failed to load metadata: %s", err)
					return err
				}

				wasmBytes, err := smartPolicy.GetPolicy()
				if err != nil {
					log.Error("failed to get policy: %s", err)
					return err
				}

				structMetadata["smartPolicy"] = base64.StdEncoding.EncodeToString(wasmBytes)

				metadataBytes, err := json.Marshal(structMetadata)
				if err != nil {
					log.Error("failed to marshal metadata: %s", err)
					return err
				}

				metadata = string(metadataBytes)
			} else {
				metadata, err = params.GetMetadata()
				if err != nil {
					log.Error("failed to read metadata file: %s", err)
					return err
				}
			}

			if err := ztdo.SetMetadata(metadata); err != nil {
				log.Error("failed to set metadata: %s", err)
				return err
			}

			// generate data private key
			dataPrkStore := db.NewDataPrivateKeyStore(a.GetOwnEcdh().PublicKeyBase64())
			dataPrk, err := dataPrkStore.Generate(dataKeyPairEccMode)
			if err != nil {
				log.Error("failed to generate data private key: %s", err)
				return err
			}

			if !(params.DsType == "stream") { // generate ztdo file
				if params.DsType == "online" {
					if err := ztdo.SetNhpServer(a.GetServerPeer().SendAddr().String()); err != nil {
						log.Error("failed to set NHP server: %s", err)
						return err
					}
				} else { // offline
					if err := ztdo.SetNhpServer(""); err != nil {
						log.Error("failed to set NHP server: %s", err)
						return err
					}
				}

				dataEcdh, err := core.ECDHFromKey(dataKeyPairEccMode.ToEccType(), dataPrk)
				if err != nil {
					log.Error("failed to create ECDH from data key: %v", err)
					return err
				}
				dataPbk := dataEcdh.PublicKey()
				sa := ztdolib.NewSymmetricAgreement(dataKeyPairEccMode, true)
				sa.SetMessagePatterns(dataMsgPattern)

				sa.SetStaticKeyPair(a.GetOwnEcdh())
				sa.SetRemoteStaticPublicKey(dataPbk)

				gcmKey, ad := sa.AgreeSymmetricKey()

				symmetricCipherMode, err := ztdolib.NewSymmetricCipherMode(a.GetSymmetricCipherMode())
				if err != nil {
					log.Error("failed to create symmetric cipher mode: %s", err)
					return err
				}
				ztdo.SetCipherConfig(true, symmetricCipherMode, dataKeyPairEccMode)

				log.Info("Encrypt ztdo file(file name: %s and ztdo id: %s) with cipher settings: ECC mode(%s) and Symmetric Cipher Mode(%s)", params.Source, ztdoId, dataKeyPairEccMode, symmetricCipherMode)

				if err := ztdo.EncryptZtdoFile(params.Source, outputFilePath, gcmKey[:], ad); err != nil {
					log.Error("failed to encrypt ztdo file: %s", err)
					return err
				}

				if params.AccessUrl == "" {
					// upload ztdo to nhp server
					params.AccessUrl, err = a.UploadFileToNHPServer(context.Background(), outputFilePath)
					if err != nil {
						log.Error("failed to upload ztdo file: %s", err)
						return err
					}
				}
			}

			// Save data private key after success encryption
			if err := dataPrkStore.Save(ztdoId); err != nil {
				log.Error("failed to save data private key: %s", err)
				return err
			}
		}

		if params.DsType != "offline" {
			drgMsg := common.DRGMsg{
				DoType:         db.DoType_Default,
				DoId:           ztdoId,
				DbId:           a.GetDataBrokerId(),
				DataSourceType: params.DsType,
				AccessUrl:      params.AccessUrl,
				AccessByNHP:    false,
				Spo:            smartPolicy,
			}

			a.SendDHPRegister(drgMsg)
		}

		os.Exit(0)
	case "decrypt":
		if err := ztdo.ParseHeader(params.ZtdoFilePath); err != nil {
			log.Error("failed to parse ztdo header: %s", err)
			fmt.Printf("Error: failed to parse ztdo header:%s.\n", err)
			os.Exit(1)
		}

		dataKeyPairEccMode := ztdo.GetECCMode()

		dataPrk, err := base64.StdEncoding.DecodeString(params.DataPrivateKeyBase64)
		if err != nil {
			log.Error("failed to decode data private key base64: %v", err)
			fmt.Printf("Error: failed to decode data private key base64: %v\n", err)
			os.Exit(1)
		}
		decryptEcdh, err := core.ECDHFromKey(dataKeyPairEccMode.ToEccType(), dataPrk)
		if err != nil {
			log.Error("failed to create ECDH from data key: %v", err)
			fmt.Printf("Error: failed to create ECDH from data key: %v\n", err)
			os.Exit(1)
		}
		sa := ztdolib.NewSymmetricAgreement(dataKeyPairEccMode, false)
		sa.SetMessagePatterns(dataMsgPattern)
		sa.SetStaticKeyPair(decryptEcdh)

		providerPublicKey, err := base64.StdEncoding.DecodeString(params.ProviderPublicKeyBase64)
		if err != nil {
			log.Error("failed to decode provider public key base64: %v", err)
			fmt.Printf("Error: failed to decode provider public key base64: %v\n", err)
			os.Exit(1)
		}
		sa.SetRemoteStaticPublicKey(providerPublicKey)

		gcmKey, ad := sa.AgreeSymmetricKey()

		log.Info("Decrypting ztdo file(file name: %s and ztdo id: %s) with cipher settings: ECC mode(%s) and Symmetric Cipher Mode(%s)", params.ZtdoFilePath, ztdo.GetObjectID(), dataKeyPairEccMode, ztdo.GetCipherMode())

		if err := ztdo.DecryptZtdoFile(params.ZtdoFilePath, params.Output, gcmKey[:], ad); err != nil {
			log.Error("failed to decrypt ztdo file: %s", err)
			fmt.Printf("Error: failed to decrypt ztdo file:%s.\n", err)
			os.Exit(1)
		} else {
			log.Info("Decrypt ztdo file successfully")
			fmt.Printf("Successfully decrypt ztdo file.\n")
		}

		os.Exit(0)
	}

	return nil
}
