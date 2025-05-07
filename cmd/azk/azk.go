package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/tracing"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/Azure/azure-sdk-for-go/sdk/tracing/azotel"
	"github.com/heaths/azcrypto"
	"github.com/mattn/go-isatty"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/sdk/trace"
)

var (
	// Commands (openssl-like)
	encryptFlag = flag.Bool("encrypt", false, "Encrypt with public key")
	decryptFlag = flag.Bool("decrypt", false, "Decrypt with private key")
	signFlag    = flag.Bool("sign", false, "Sign with private key")
	verifyFlag  = flag.Bool("verify", false, "Verify with public key")

	// Key options
	keyIDFlag = flag.String("kid", "", "Key ID (URL)")
	pkcsFlag  = flag.Bool("pkcs", true, "PKCS#1 v1.5 padding (default)")
	oaepFlag  = flag.Bool("oaep", false, "PKCS#1 OAEP padding")

	// Input options
	inFlag = flag.String("in", "", "Input file `infile`")

	// Output options
	outFlag    = flag.String("out", "", "Output file `outfile`")
	base64Flag = flag.Bool("base64", false, "Base64 encode/decode, depending on encryption flag")
	debugFlag  = flag.Bool("debug", false, "Verbose output")

	// Errors
	errCommand = errors.New("one of encrypt, decrypt, sign, or verify is required")
	errKeyID   = errors.New("keyID is required")
)

func main() {
	var err error
	flag.Parse()

	type command func(client *azcrypto.Client, r io.Reader, w io.Writer) error
	var fn command
	cmds := map[*bool]command{
		encryptFlag: encrypt,
		decryptFlag: decrypt,
		signFlag:    sign,
		verifyFlag:  verify,
	}
	for k, v := range cmds {
		if isSet(k) {
			if fn != nil {
				exit(errCommand)
			}
			fn = v
		}
	}
	if fn == nil {
		exit(errCommand)
	}

	if keyIDFlag == nil {
		exit(errKeyID)
	}

	// Open/create the input and output files, or stdin/stdout.
	var r io.Reader
	r = os.Stdin
	if inFlag != nil && *inFlag != "" {
		r, err = os.Open(*inFlag)
		if err != nil {
			exit(err)
		}
	}

	var w io.WriteCloser
	w = os.Stdout
	if outFlag != nil && *outFlag != "" {
		w, err = os.Create(*outFlag)
		if err != nil {
			exit(err)
		}
	} else {
		// Make sure prompt is on new line.
		defer w.Write([]byte{'\n'})
	}
	if isSet(base64Flag) {
		w = base64.NewEncoder(base64.StdEncoding, w)
		defer w.Close()
	}

	// Create the credentials and client to pass to the command.
	credential, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		exit(err)
	}

	options := &azcrypto.ClientOptions{
		ClientOptions: azkeys.ClientOptions{
			ClientOptions: azcore.ClientOptions{
				TracingProvider: tracingProvider(),
			},
		},
	}
	client, err := azcrypto.NewClient(*keyIDFlag, credential, options)
	if err != nil {
		exit(err)
	}

	err = fn(client, r, w)
	if err != nil {
		exit(err)
	}
}

func exit(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func isSet(b *bool) bool {
	return b != nil && *b
}

func tracingProvider() tracing.Provider {
	if !isSet(debugFlag) {
		return tracing.Provider{}
	}

	exp, err := stdouttrace.New(stdouttrace.WithWriter(colorize(os.Stderr)))
	if err != nil {
		exit(err)
	}

	tracer := trace.NewTracerProvider(
		// Trace to stderr immediately.
		trace.WithSpanProcessor(trace.NewSimpleSpanProcessor(exp)),
	)

	return azotel.NewTracingProvider(tracer, nil)
}

func encrypt(client *azcrypto.Client, r io.Reader, w io.Writer) error {
	plaintext, err := io.ReadAll(r)
	if err != nil {
		return err
	}

	alg, err := encryptionAlgorithm()
	if err != nil {
		return err
	}

	result, err := client.Encrypt(context.Background(), alg, plaintext, nil)
	if err != nil {
		return err
	}

	_, err = w.Write(result.Ciphertext)
	return err
}

func decrypt(client *azcrypto.Client, r io.Reader, w io.Writer) error {
	ciphertext, err := io.ReadAll(r)
	if err != nil {
		return err
	}

	alg, err := encryptionAlgorithm()
	if err != nil {
		return err
	}

	result, err := client.Decrypt(context.Background(), alg, ciphertext, nil)
	if err != nil {
		return err
	}

	_, err = w.Write(result.Plaintext)
	return err
}

func sign(client *azcrypto.Client, r io.Reader, w io.Writer) error {
	return errors.ErrUnsupported
}

func verify(client *azcrypto.Client, r io.Reader, w io.Writer) error {
	return errors.ErrUnsupported
}

func encryptionAlgorithm() (azcrypto.EncryptAlgorithm, error) {
	switch {
	case isSet(oaepFlag):
		return azcrypto.EncryptAlgorithmRSAOAEP, nil
	case isSet(pkcsFlag):
		return azcrypto.EncryptAlgorithmRSA15, nil
	}

	return "", errors.New("one of pkcs or oaep required")
}

func colorize(w io.Writer) io.Writer {
	if f, ok := w.(*os.File); ok && isatty.IsTerminal(f.Fd()) {
		return colorizer{
			w: w,
		}
	}

	return w
}

type colorizer struct {
	w io.Writer
}

func (v colorizer) Write(p []byte) (int, error) {
	v.w.Write([]byte("\x1b[2;97m"))
	defer v.w.Write([]byte("\x1b[m"))

	return v.w.Write(p)
}
