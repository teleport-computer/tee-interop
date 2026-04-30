// Helper: invokes tinfoil-go's real SEV-SNP / TDX verification on either a
// vendored test vector or a live https://atc.tinfoil.sh/attestation bundle.
// Prints the verified Verification struct as JSON on stdout. Exits non-zero
// on verification failure.
//
// This is the off-chain piece of the ERC-733 §C "TEE Proof" pattern: in
// production it would run inside an attested CVM whose encumbered key signs
// the verified envelope. Here we just exercise the verification logic.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/tinfoilsh/tinfoil-go/verifier/attestation"
)

// Vendored vector from tinfoil-go's TestGuestVerify (SEV-SNP guest v2 case).
const vendoredSEVAttestation = `{"format":"https://tinfoil.sh/predicate/sev-snp-guest/v2","body":"H4sIAAAAAAAA/2JmgAEEixBgZGBg4AKzxEPU0eQETrU6V/UVB3t6X/nzPHnDqkuB7Ge7tj5ZEHio29Wfkc1uX9Sclq9brfxurj5f8/1vsLnEKWGd+VvbrZlW1uopNP7g1X277qF1y53Evj/F31o35j7JULPg0r0S+zF28d3utXtmKJ26X/2ndOpEHVfxXfmrpYMOEO1oGgGNBec2/VR6lX2Gl0OiQHRZX6rfLIn+iuYbKf+jFB4bqZ34TwDAwlFSkBGr+VIfV+XIhzFXsbbMitzRGPOTM8J+9sr3+qxGEkfMP1svbH7yRHSD5eb6JlZVrovx3R0LFq+9+eVA44HyWR5vlUTM+1xg5muYMzKAMIxPxyCiCHQ6e7XWK8xY82mR/JozTx04Vy5l8FSb5PHojvm2wD2bL32f4PhFweCczqKfEgb9gr/XG+Iy57HDxR1FBzhUzT5FZUW/TOHzX/fB7uei0kcHzO5v62TjbzG4Zxh1YsrdgwmpTrsN8vatoq8vRwEuAAgAAP//tiY3daAEAAA="}`

const vendoredTDXAttestation = `{"format":"https://tinfoil.sh/predicate/tdx-guest/v2","body":"H4sIAAAAAAAA/7RXC5QT5b0P7PIaFRBBRR7ilXsVg2Ty2Efg3qvfN/PNZJJ8k8wzmXjv1WSSTCbP3c0mk4zKhStXDz4uAopH5YraYwXPsWitVG2lLVWrtdRjsXpUqI9W6QNaqRVttdqTXRayuFQep/9zdrP7m+//zf8/3+83v886HeMdKx3Dsf6uAe/HG8NbbiPOeOz2/5446ZMrnui5cfOHP/r8ko4t44yNN7XWTBrX4WgPblvlITRv9u+e3r66Z84tW52Zh/yr9t16Zgf1m3d//4Ozt07+32n3T1123pbNg6/Zmd6pe993nHxMb/3aO37i0D/V2H1nLLlo4Vuf51b++78+89LO91fiwU2ubUv80nuR8mnR+2c38p8vfqVxcNXji5PXLT9z5inc9x8S59525a8+wLdf8unajisGd4jLe9Ga1we2vz3n6nsXdO6e5tq35IXJ/9y3SH2x/pHrP+Ztil6wunTT2l75/3TrrhlzbnaeN/naN75257h3/jpFn/2FY8KT5qa38ctL3/ROXDovsye0c8dHj27YsmLfK4sm3bnhBfqs74bDzs8Oiq/+y7Y3/vjAggXlh6OZPZJjrjO+9MrtYN2sle9emd14ovXfv2yqxb627Km5wf9/Jjlh1S+vLm96Cq/17liBb48tPuv7f9kVeal7x/zebs/+7lkXPXfL4+DXkdX71uUe3v3i6sVX/fbihT+Z7nBsWn/A+4ulF320Xbz3moPf+d6cn+769LEluw8uSN1ZWz7j7gPrp1x3fcNckStsf6J58fTLVo1f9ODswoXXiucvvuDPa3788jOBA1dd/sauCY/NZzrGPbeELa7t3PTy3M7qzFW7Zlz2xQpx/vUfrnn19eUfL/rDz89/fu2zHdmDj67b0/De3Ttzp/3IpTead+yZ6GCmOxwdHbPndH7hmHi8nc869Ln30Oe3v3HXtnvqHzeD6iNvzp518TzqPwM3r31l4n7vg+s3br2B/OSr9tt9zyXXVG5bcw7L+x78jNrfMe2aWfqBp55+S7/8+SVT5c3PnujJnGiMd0w6pfzNbylPnv5O+LJHKrMuXFbO/lP3/3zzvRveLG5Y/dzNt359nTn/q/KpCyd/6+4P6OL+g8v26I97wls7s3vv1R94Yiez/E/iuOvW3fHQwupmovjT+yKdG1xdcz3ru2Yun7Ji+cL+MrXj+v3sDxc4HOPGd3ROmDhp8hTitNPPmDpt+pkzzpo56+xzzp079969Exz/NdXhuLQVELEcv4BCosww4z6T0CT0kEaMV31a4yBMgcVBYHBKUMt5rIY7pgLT5J0cTjb9btdAOEPGLYsyNC5USXB2nkTA4ixCp5GJKcACt4KAZSWkWBeZiFmGQqY1joG01IRCimXIRMnfTEmQFmSUxNAYWk8ZlkiMJAgef1Nn/U0tLvalPL4GQwMJGrwKgY4pN59LlcUch/iqFg/msFC1KEGjVUHgCBoEW7uGMSgM7QpzmFJVbAVyOo/zihWhkRvTyOJpgYy1MJsbhRGxPLSwxFkcGNqRpmExmCqLxRQFZdFtGArig5YTH2j5x+x3wZ9ZgWHe/GFucDzlj+oW5x4LNuLFoCYRlV5IETGzcePO0ESxIDmQ75LP3JxqCExDcyLLDz+/fRVZWaW/zSe24fwGS5Ynz4ELhbDRNwDpphi13/ck5DG1UjbfWy4EBTWsW8RxzlZAZxz+Aqo28ABRIPxqfHvgAGrNS1ezfLpZpdW4GePUMy4U16f9SQbLsK40ZjShl+SjiFxgvVcEiUz3Mq8MzJWhNHxHrmDYQ70TG/+8j7ldXYFJfgUGPTnA5GMm6LtOMjmqyVzjP6Yad8ECRdg+B5jzlOSiqaB1lnh5Q5lEXOTOh8AAAA//8sBLLZ4QAAAA=="}`

type result struct {
	Format            string   `json:"format"`
	TLSPublicKeyFP    string   `json:"tls_public_key"`
	HPKEPublicKey     string   `json:"hpke_public_key"`
	MeasurementType   string   `json:"measurement_type"`
	Registers         []string `json:"registers"`
	MultiPlatformHash string   `json:"multiplatform_hash,omitempty"`
}

func main() {
	source := flag.String("source", "vendored-sev", "vendored-sev | vendored-tdx | live | host | stdin")
	host := flag.String("host", "", "enclave hostname (e.g. devproof-hello.andrew-miller.containers.tinfoil.dev) — used when --source=host")
	flag.Parse()

	var attJSON []byte
	var err error
	switch *source {
	case "vendored-sev":
		attJSON = []byte(vendoredSEVAttestation)
	case "vendored-tdx":
		attJSON = []byte(vendoredTDXAttestation)
	case "live":
		bundle, ferr := attestation.FetchBundle()
		if ferr != nil {
			fmt.Fprintf(os.Stderr, "FetchBundle failed: %v\n", ferr)
			os.Exit(2)
		}
		// Re-marshal the attestation document part for VerifyAttestationJSON
		attJSON, err = json.Marshal(bundle.EnclaveAttestationReport)
		if err != nil {
			fmt.Fprintf(os.Stderr, "marshal: %v\n", err)
			os.Exit(2)
		}
	case "host":
		// Tinfoil-Containers third-party deploys do not expose an ATC bundle
		// at atc.tinfoil.sh. They serve /.well-known/tinfoil-attestation directly.
		if *host == "" {
			fmt.Fprintln(os.Stderr, "--source=host requires --host <hostname>")
			os.Exit(2)
		}
		doc, ferr := attestation.Fetch(*host)
		if ferr != nil {
			fmt.Fprintf(os.Stderr, "Fetch %s: %v\n", *host, ferr)
			os.Exit(2)
		}
		attJSON, err = json.Marshal(doc)
		if err != nil {
			fmt.Fprintf(os.Stderr, "marshal: %v\n", err)
			os.Exit(2)
		}
	case "stdin":
		buf := make([]byte, 0, 8192)
		tmp := make([]byte, 4096)
		for {
			n, rerr := os.Stdin.Read(tmp)
			if n > 0 {
				buf = append(buf, tmp[:n]...)
			}
			if rerr != nil {
				break
			}
		}
		attJSON = buf
	default:
		fmt.Fprintln(os.Stderr, "bad --source")
		os.Exit(2)
	}

	v, err := attestation.VerifyAttestationJSON(attJSON)
	if err != nil {
		fmt.Fprintf(os.Stderr, "VerifyAttestationJSON failed: %v\n", err)
		os.Exit(1)
	}

	out := result{
		Format:          string(v.Measurement.Type),
		TLSPublicKeyFP:  v.TLSPublicKeyFP,
		HPKEPublicKey:   v.HPKEPublicKey,
		MeasurementType: string(v.Measurement.Type),
		Registers:       v.Measurement.Registers,
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintf(os.Stderr, "json encode: %v\n", err)
		os.Exit(2)
	}
}
