package azcrypto_test

// cspell:ignore azotel opentelemetry otel stdouttrace otrace semconv
import (
	"context"
	"fmt"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/Azure/azure-sdk-for-go/sdk/tracing/azotel"
	"github.com/heaths/azcrypto"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/sdk/resource"
	otrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
)

func Example_tracing() {
	exporter, err := stdouttrace.New(
		stdouttrace.WithWriter(os.Stderr),
		stdouttrace.WithPrettyPrint(),
	)
	if err != nil {
		// TODO: handle error
	}

	provider := otrace.NewTracerProvider(
		otrace.WithBatcher(exporter),
		otrace.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String("Example_tracing"),
		)),
	)
	defer func() {
		if err := provider.Shutdown(context.TODO()); err != nil {
			// TODO: handle error
		}
	}()

	credential, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		// TODO: handle error
	}

	client, err := azcrypto.NewClient(
		"https://{vault-name}.vault.azure.net/keys/{key-name}/{key-version}",
		credential,
		&azcrypto.ClientOptions{
			ClientOptions: azkeys.ClientOptions{
				ClientOptions: azcore.ClientOptions{
					TracingProvider: azotel.NewTracingProvider(provider, nil),
				},
			},
		},
	)
	if err != nil {
		// TODO: handle error
	}

	signed, err := client.SignData(context.TODO(), azcrypto.SignAlgorithmES256, []byte("plaintext"), nil)
	if err != nil {
		// TODO: handle error
	}

	verified, err := client.VerifyData(context.TODO(), signed.Algorithm, []byte("plaintext"), signed.Signature, nil)
	if err != nil {
		// TODO: handle error
	}

	fmt.Printf("Valid: %t\n", verified.Valid)
}
