```bash
Usage: hsm-tool --cfg=STRING <command> [flags]

CLI tool for HSM or KMS

Flags:
  -h, --help                 Show context-sensitive help.
      --cfg=STRING           Location of HSM config file, as default crypto
                             provider
      --crypto=CRYPTO        Location of additional HSM config files
      --plain-key            Generate plain key
  -D, --debug                Enable debug mode
  -l, --log-level="error"    Set the logging level (debug|info|warn|error)

Commands:
  hsm key list        list keys
  hsm key info        print key information
  hsm key generate    generate key
  hsm key remove      delete key
  csr create          create certificate request
  csr gen-cert        create CSR and sign certificate
  csr sign            sign certificate

Run "hsm-tool <command> --help" for more information on a command.
```
