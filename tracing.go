// Copyright 2023 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

package azcrypto

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/tracing"
)

func (client *Client) startSpan(ctx context.Context, name string) (context.Context, span) {
	if !client.tracer.Enabled() {
		return ctx, span{}
	}

	attrs := []tracing.Attribute{
		{Key: "azcrypto.kid", Value: client.keyID},
	}
	if client.localClient != nil {
		attrs = append(attrs, tracing.Attribute{Key: "azcrypto.kty", Value: client.localClient.KeyType()})
	}
	ctx, s := client.tracer.Start(ctx, "Client."+name, &tracing.SpanOptions{
		// https://opentelemetry.io/docs/specs/otel/trace/api/#spankind
		Kind:       tracing.SpanKindInternal,
		Attributes: attrs,
	})

	return ctx, span{s, client}
}

type span struct {
	tracing.Span
	*Client
}

func (s span) SetLocal(algorithm string) {
	s.Span.AddEvent("azcrypto.local",
		tracing.Attribute{Key: "azcrypto.alg", Value: algorithm},
	)
}

func (s span) End(err error) {
	if err != nil {
		s.Span.SetStatus(tracing.SpanStatusError, err.Error())
	}
	s.Span.End(nil)
}
