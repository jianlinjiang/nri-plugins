package main

import (
	"bytes"
	"context"
	"crypto"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/google/go-tpm-tools/cel"
	"github.com/google/go-tpm-tools/client"
	attestpb "github.com/google/go-tpm-tools/proto/attest"
	"github.com/google/go-tpm-tools/verifier"
	"github.com/google/go-tpm-tools/verifier/oci"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// TpmKeyFetcher abstracts the fetching of various types of Attestation Key from TPM
type TpmKeyFetcher func(rw io.ReadWriter) (*client.Key, error)

type principalIDTokenFetcher func(audience string) ([][]byte, error)

type AttestationAgent interface {
	MeasureEvent(cel.Content) error
	Attest(context.Context, AttestAgentOpts) ([]byte, error)
	Refresh(context.Context) error
	Close() error
}

// AttestAgentOpts contains user generated options when calling the
// VerifyAttestation API
type AttestAgentOpts struct {
	Aud       string
	Nonces    []string
	TokenType string
}

type agent struct {
	tpm              io.ReadWriteCloser
	tpmMu            sync.Mutex
	fetchedAK        *client.Key
	client           verifier.Client
	principalFetcher principalIDTokenFetcher
	sigsFetcher      Fetcher
	cosCel           cel.CEL
	logger           *logrus.Logger
	sigsCache        *sigsCache
}

type sigsCache struct {
	mu    sync.RWMutex
	items []oci.Signature
}

var defaultCELHashAlgo = []crypto.Hash{crypto.SHA256, crypto.SHA1}

func (a *agent) Close() error {
	a.fetchedAK.Close()
	return nil
}

// MeasureEvent takes in a cel.Content and appends it to the CEL eventlog
// under the attestation agent.
func (a *agent) MeasureEvent(event cel.Content) error {
	a.tpmMu.Lock()
	defer a.tpmMu.Unlock()
	return a.cosCel.AppendEvent(a.tpm, cel.CosEventPCR, defaultCELHashAlgo, event)
}

func (c *sigsCache) set(sigs []oci.Signature) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = make([]oci.Signature, len(sigs))
	copy(c.items, sigs)
}

func (c *sigsCache) get() []oci.Signature {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.items
}

// Attest fetches the nonce and connection ID from the Attestation Service,
// creates an attestation message, and returns the resultant
// principalIDTokens and Metadata Server-generated ID tokens for the instance.
func (a *agent) Attest(ctx context.Context, opts AttestAgentOpts) ([]byte, error) {
	challenge, err := a.client.CreateChallenge(ctx)
	if err != nil {
		return nil, err
	}

	a.tpmMu.Lock()
	attestation, err := FetchAttestation(a.fetchedAK, challenge.Nonce, &a.cosCel)
	a.tpmMu.Unlock()
	if err != nil {
		return nil, err
	}

	principalTokens, err := a.principalFetcher(challenge.Name)

	req := verifier.VerifyAttestationRequest{
		Challenge:      challenge,
		GcpCredentials: principalTokens,
		Attestation:    attestation,
		TokenOptions: verifier.TokenOptions{
			CustomAudience: opts.Aud,
			CustomNonce:    opts.Nonces,
			TokenType:      opts.TokenType,
		},
	}

	//var signatures []oci.Signature
	//signatures = fetchContainerImageSignatures(ctx, a.sigsFetcher, a.launchSpec.SignedImageRepos, a.logger)
	//if len(signatures) > 0 {
	//	req.ContainerImageSignatures = signatures
	//	a.logger.Printf("Found container image signatures: %v\n", signatures)
	//}

	resp, err := a.client.VerifyAttestation(ctx, req)
	if err != nil {
		return nil, err
	}
	if len(resp.PartialErrs) > 0 {
		a.logger.Printf("Partial errors from VerifyAttestation: %v", resp.PartialErrs)
	}
	return resp.ClaimsToken, nil
}

// Refresh refreshes the internal state of the attestation agent.
// It will reset the container image signatures for now.
func (a *agent) Refresh(ctx context.Context) error {
	return nil
}

func CreateAttestationAgent(tpm io.ReadWriteCloser, akFetcher TpmKeyFetcher, verifierClient verifier.Client, sigsFetcher Fetcher, principalFetcher principalIDTokenFetcher, logger *logrus.Logger) (AttestationAgent, error) {
	// Fetched the AK and save it, so the agent doesn't need to create a new key everytime
	ak, err := akFetcher(tpm)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to fetch AK")
	}
	return &agent{
		tpm:              tpm,
		fetchedAK:        ak,
		client:           verifierClient,
		principalFetcher: principalFetcher,
		logger:           logger,
		sigsFetcher:      sigsFetcher,
		sigsCache:        &sigsCache{},
	}, nil
}

// FetchAttestation gathers the materials required for remote attestation from TPM
func FetchAttestation(ak *client.Key, nonce []byte, cosCEL *cel.CEL) (*attestpb.Attestation, error) {
	var buf bytes.Buffer
	if cosCEL != nil {
		if err := cosCEL.EncodeCEL(&buf); err != nil {
			return nil, err
		}
	}

	attestation, err := ak.Attest(client.AttestOpts{Nonce: nonce, CanonicalEventLog: buf.Bytes(), CertChainFetcher: http.DefaultClient})
	if err != nil {
		return nil, fmt.Errorf("failed to attest: %v", err)
	}
	return attestation, nil
}
