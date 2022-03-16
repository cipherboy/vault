package pki

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/errutil"
	"github.com/hashicorp/vault/sdk/logical"
)

// CRLConfig holds basic CRL configuration information
type crlConfig struct {
	Expiry      string `json:"expiry" mapstructure:"expiry"`
	Disable     bool   `json:"disable"`
	Lightweight bool   `json:"lightweight"`
}

func pathConfigCRL(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "config/crl",
		Fields: map[string]*framework.FieldSchema{
			"expiry": {
				Type: framework.TypeString,
				Description: `The amount of time the generated CRL should be
valid; defaults to 72 hours`,
				Default: "72h",
			},
			"disable": {
				Type:        framework.TypeBool,
				Description: `If set to true, disables generating the CRL entirely.`,
			},
			"lightweight": {
				Type:        framework.TypeBool,
				Description: `If set to true, enables lightweight CRL storage.`,
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathCRLRead,
			logical.UpdateOperation: b.pathCRLWrite,
		},

		HelpSynopsis:    pathConfigCRLHelpSyn,
		HelpDescription: pathConfigCRLHelpDesc,
	}
}

func (b *backend) CRL(ctx context.Context, s logical.Storage) (*crlConfig, error) {
	entry, err := s.Get(ctx, "config/crl")
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var result crlConfig
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (b *backend) pathCRLRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := b.CRL(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"expiry":      config.Expiry,
			"disable":     config.Disable,
			"lightweight": config.Lightweight,
		},
	}, nil
}

func (b *backend) pathCRLWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	config, err := b.CRL(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		config = &crlConfig{}
	}

	if expiryRaw, ok := d.GetOk("expiry"); ok {
		expiry := expiryRaw.(string)
		_, err := time.ParseDuration(expiry)
		if err != nil {
			return logical.ErrorResponse(fmt.Sprintf("given expiry could not be decoded: %s", err)), nil
		}
		config.Expiry = expiry
	}

	var oldDisable bool
	if disableRaw, ok := d.GetOk("disable"); ok {
		oldDisable = config.Disable
		config.Disable = disableRaw.(bool)
	}

	if lightweightRaw, ok := d.GetOk("lightweight"); ok {
		config.Lightweight = lightweightRaw.(bool)
	}

	entry, err := logical.StorageEntryJSON("config/crl", config)
	if err != nil {
		return nil, err
	}
	err = req.Storage.Put(ctx, entry)
	if err != nil {
		return nil, err
	}

	if oldDisable != config.Disable {
		lwcrl, lwcrlErr := fetchLWCRL(ctx, b, req)
		if lwcrlErr != nil {
			return nil, fmt.Errorf("error encountered during CRL building: %w", lwcrlErr)
		}

		// It wasn't disabled but now it is, rotate
		crlErr := buildCRL(ctx, b, req, lwcrl, true)
		if crlErr != nil {
			switch crlErr.(type) {
			case errutil.UserError:
				return logical.ErrorResponse(fmt.Sprintf("Error during CRL building: %s", crlErr)), nil
			default:
				return nil, fmt.Errorf("error encountered during CRL building: %w", crlErr)
			}
		}
	}

	return nil, nil
}

const pathConfigCRLHelpSyn = `
Configure the CRL expiration.
`

const pathConfigCRLHelpDesc = `
This endpoint allows configuration of the CRL lifetime.
`
