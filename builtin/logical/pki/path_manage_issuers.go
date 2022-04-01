package pki

import (
	"bytes"
	"context"
	"encoding/pem"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/errutil"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathImportIssuer(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "issuers/import/(cert|bundle)",
		Fields: map[string]*framework.FieldSchema{
			"pem_bundle": {
				Type: framework.TypeString,
				Description: `PEM-format, concatenated unencrypted
secret-key (optional) and certificates.`,
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathImportIssuers,
		},

		HelpSynopsis:    pathImportIssuersHelpSyn,
		HelpDescription: pathImportIssuersHelpDesc,
	}
}

func (b *backend) pathImportIssuers(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	keysAllowed := strings.HasSuffix(req.Path, "bundle")

	pemBundle := data.Get("pem_bundle").(string)
	if len(pemBundle) == 0 {
		return logical.ErrorResponse("'pem_bundle' parameter was empty"), nil
	}

	var createdKeys []keyId
	createdIssuers := make(map[issuerId]keyId)

	// Rather than using certutil.ParsePEMBundle (which restricts the
	// construction of the PEM bundle), we manually parse the bundle instead.
	pemBytes := []byte(pemBundle)
	var pemBlock *pem.Block

	var issuers []string
	var keys []string

	for len(bytes.TrimSpace(pemBytes)) > 0 {
		pemBlock, pemBytes = pem.Decode(pemBytes)
		if pemBlock == nil {
			return nil, errutil.UserError{Err: "no data found in PEM block"}
		}

		pemBlockString := string(pem.EncodeToMemory(pemBlock))

		switch pemBlock.Type {
		case "CERTIFICATE", "X509 CERTIFICATE":
			// Must be a certificate
			issuers = append(issuers, pemBlockString)
		case "CRL", "X509 CRL":
			// Ignore any CRL entries.
		default:
			// Otherwise, treat them as keys.
			keys = append(keys, pemBlockString)
		}
	}

	if len(keys) > 0 && !keysAllowed {
		return logical.ErrorResponse("private keys found in the PEM bundle but not allowed by the path; use /issuers/import/bundle"), nil
	}

	for _, keyPem := range keys {
		// Handle import of private key.
		key, err := importKey(ctx, req.Storage, keyPem)
		if err != nil {
			return logical.ErrorResponse(err.Error()), nil
		}

		createdKeys = append(createdKeys, key.ID)
	}

	for _, certPem := range issuers {
		cert, err := importIssuer(ctx, req.Storage, certPem)
		if err != nil {
			return logical.ErrorResponse(err.Error()), nil
		}

		createdIssuers[cert.ID] = cert.KeyID
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"id":            createdIssuers,
			"imported_keys": createdKeys,
		},
	}, nil
}

const (
	pathImportIssuersHelpSyn  = `Import the specified issuing certificates.`
	pathImportIssuersHelpDesc = `
This endpoint allows importing the specified issuer certificates.

:type is either the literal value "cert", to only allow importing
certificates, else "bundle" to allow importing keys as well as
certificates.

Depending on the value of :type, the pem_bundle request parameter can
either take PEM-formatted certificates, and, if :type="bundle", unencrypted
secret-keys.
`
)
