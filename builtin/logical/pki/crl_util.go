package pki

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/helper/certutil"
	"github.com/hashicorp/vault/sdk/helper/errutil"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
)

type revocationInfo struct {
	CertificateBytes  []byte    `json:"certificate_bytes"`
	RevocationTime    int64     `json:"revocation_time"`
	RevocationTimeUTC time.Time `json:"revocation_time_utc"`
}

// Revokes a cert, and tries to be smart about error recovery
func revokeCert(ctx context.Context, b *backend, req *logical.Request, serial string, fromLease bool) (*logical.Response, error) {
	// As this backend is self-contained and this function does not hook into
	// third parties to manage users or resources, if the mount is tainted,
	// revocation doesn't matter anyways -- the CRL that would be written will
	// be immediately blown away by the view being cleared. So we can simply
	// fast path a successful exit.
	if b.System().Tainted() {
		return nil, nil
	}

	signingBundle, caErr := fetchCAInfo(ctx, b, req)
	switch caErr.(type) {
	case errutil.UserError:
		return logical.ErrorResponse(fmt.Sprintf("could not fetch the CA certificate: %s", caErr)), nil
	case errutil.InternalError:
		return nil, fmt.Errorf("error fetching CA certificate: %s", caErr)
	}
	if signingBundle == nil {
		return nil, errors.New("CA info not found")
	}

	colonSerial := denormalizeSerial(serial)
	if colonSerial == certutil.GetHexFormatted(signingBundle.Certificate.SerialNumber.Bytes(), ":") {
		return logical.ErrorResponse("adding CA to CRL is not allowed"), nil
	}

	lwcrl, err := revokeLWCRLEntry(ctx, b, req, normalizeSerial(serial))
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("unable to load lightweight CRL entry: %v", err)), nil
	}

	alreadyRevoked := false
	var revInfo revocationInfo

	revEntry, err := fetchCertBySerial(ctx, req, "revoked/", serial)
	if err != nil {
		switch err.(type) {
		case errutil.UserError:
			return logical.ErrorResponse(err.Error()), nil
		case errutil.InternalError:
			return nil, err
		}
	}
	if revEntry != nil {
		// Set the revocation info to the existing values
		alreadyRevoked = true
		err = revEntry.DecodeJSON(&revInfo)
		if err != nil {
			return nil, fmt.Errorf("error decoding existing revocation info")
		}
	}

	if !alreadyRevoked {
		certEntry, err := fetchCertBySerial(ctx, req, "certs/", serial)
		if err != nil {
			switch err.(type) {
			case errutil.UserError:
				return logical.ErrorResponse(err.Error()), nil
			case errutil.InternalError:
				return nil, err
			}
		}
		if certEntry == nil {
			if fromLease {
				// We can't write to revoked/ or update the CRL anyway because we don't have the cert,
				// and there's no reason to expect this will work on a subsequent
				// retry.  Just give up and let the lease get deleted.
				b.Logger().Warn("expired certificate revoke failed because not found in storage, treating as success", "serial", serial)
				return nil, nil
			}

			// Only return error when we failed to add it to the lwcrl because
			// it didn't exist or we don't have a corresponding entry. Otherwise,
			// we might've just set no_store on the role to only have lw CRL.
			if lwcrl == nil {
				return logical.ErrorResponse(fmt.Sprintf("certificate with serial %s not found", serial)), nil
			}
			if _, ok := lwcrl.Entries[normalizeSerial(serial)]; !ok {
				return logical.ErrorResponse(fmt.Sprintf("certificate with serial %s not found", serial)), nil
			}
		} else {

			cert, err := x509.ParseCertificate(certEntry.Value)
			if err != nil {
				return nil, fmt.Errorf("error parsing certificate: %w", err)
			}
			if cert == nil {
				return nil, fmt.Errorf("got a nil certificate")
			}

			// Add a little wiggle room because leases are stored with a second
			// granularity
			if cert.NotAfter.Before(time.Now().Add(2 * time.Second)) {
				return nil, nil
			}

			// Compatibility: Don't revoke CAs if they had leases. New CAs going
			// forward aren't issued leases.
			if cert.IsCA && fromLease {
				return nil, nil
			}

			currTime := time.Now()
			revInfo.CertificateBytes = certEntry.Value
			revInfo.RevocationTime = currTime.Unix()
			revInfo.RevocationTimeUTC = currTime.UTC()

			revEntry, err = logical.StorageEntryJSON("revoked/"+normalizeSerial(serial), revInfo)
			if err != nil {
				return nil, fmt.Errorf("error creating revocation entry")
			}

			err = req.Storage.Put(ctx, revEntry)
			if err != nil {
				return nil, fmt.Errorf("error saving revoked certificate to new location")
			}
		}
	}

	crlErr := buildCRL(ctx, b, req, lwcrl, false)
	switch crlErr.(type) {
	case errutil.UserError:
		return logical.ErrorResponse(fmt.Sprintf("Error during CRL building: %s", crlErr)), nil
	case errutil.InternalError:
		return nil, fmt.Errorf("error encountered during CRL building: %w", crlErr)
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"revocation_time": revInfo.RevocationTime,
		},
	}
	if !revInfo.RevocationTimeUTC.IsZero() {
		resp.Data["revocation_time_rfc3339"] = revInfo.RevocationTimeUTC.Format(time.RFC3339Nano)
	}
	return resp, nil
}

// Builds a CRL by going through the list of revoked certificates and building
// a new CRL with the stored revocation times and serial numbers.
func buildCRL(ctx context.Context, b *backend, req *logical.Request, lwcrl *LWCRL, forceNew bool) error {
	crlInfo, err := b.CRL(ctx, req.Storage)
	if err != nil {
		return errutil.InternalError{Err: fmt.Sprintf("error fetching CRL config information: %s", err)}
	}

	crlLifetime := b.crlLifetime
	var revokedCerts []pkix.RevokedCertificate
	var revInfo revocationInfo
	var revokedSerials []string

	if crlInfo != nil {
		if crlInfo.Expiry != "" {
			crlDur, err := time.ParseDuration(crlInfo.Expiry)
			if err != nil {
				return errutil.InternalError{Err: fmt.Sprintf("error parsing CRL duration of %s", crlInfo.Expiry)}
			}
			crlLifetime = crlDur
		}

		if crlInfo.Disable {
			if !forceNew {
				return nil
			}
			goto WRITE
		}
	}

	if lwcrl != nil {
		for hexSerial, entry := range lwcrl.Entries {
			if entry.RevocationTimeUtc == nil {
				continue
			}

			serial, ok := hexSerialToNum(hexSerial)
			if !ok {
				continue
			}

			when, err := ptypes.Timestamp(entry.RevocationTimeUtc)
			if err != nil {
				continue
			}

			// Certificate has been revoked.
			newRevCert := pkix.RevokedCertificate{
				SerialNumber:   serial,
				RevocationTime: when,
			}
			revokedCerts = append(revokedCerts, newRevCert)
		}
	}

	revokedSerials, err = req.Storage.List(ctx, "revoked/")
	if err != nil && lwcrl == nil {
		return errutil.InternalError{Err: fmt.Sprintf("error fetching list of revoked certs: %s", err)}
	}

	for _, serial := range revokedSerials {
		// Skip duplicate entries from lwcrl.
		if lwcrl != nil {
			if _, ok := lwcrl.Entries[serial]; ok {
				continue
			}
		}

		revokedEntry, err := req.Storage.Get(ctx, "revoked/"+serial)
		if err != nil {
			return errutil.InternalError{Err: fmt.Sprintf("unable to fetch revoked cert with serial %s: %s", serial, err)}
		}
		if revokedEntry == nil {
			return errutil.InternalError{Err: fmt.Sprintf("revoked certificate entry for serial %s is nil", serial)}
		}
		if revokedEntry.Value == nil || len(revokedEntry.Value) == 0 {
			// TODO: In this case, remove it and continue? How likely is this to
			// happen? Alternately, could skip it entirely, or could implement a
			// delete function so that there is a way to remove these
			return errutil.InternalError{Err: fmt.Sprintf("found revoked serial but actual certificate is empty")}
		}

		err = revokedEntry.DecodeJSON(&revInfo)
		if err != nil {
			return errutil.InternalError{Err: fmt.Sprintf("error decoding revocation entry for serial %s: %s", serial, err)}
		}

		revokedCert, err := x509.ParseCertificate(revInfo.CertificateBytes)
		if err != nil {
			return errutil.InternalError{Err: fmt.Sprintf("unable to parse stored revoked certificate with serial %s: %s", serial, err)}
		}

		// NOTE: We have to change this to UTC time because the CRL standard
		// mandates it but Go will happily encode the CRL without this.
		newRevCert := pkix.RevokedCertificate{
			SerialNumber: revokedCert.SerialNumber,
		}
		if !revInfo.RevocationTimeUTC.IsZero() {
			newRevCert.RevocationTime = revInfo.RevocationTimeUTC
		} else {
			newRevCert.RevocationTime = time.Unix(revInfo.RevocationTime, 0).UTC()
		}
		revokedCerts = append(revokedCerts, newRevCert)
	}

WRITE:
	signingBundle, caErr := fetchCAInfo(ctx, b, req)
	switch caErr.(type) {
	case errutil.UserError:
		return errutil.UserError{Err: fmt.Sprintf("could not fetch the CA certificate: %s", caErr)}
	case errutil.InternalError:
		return errutil.InternalError{Err: fmt.Sprintf("error fetching CA certificate: %s", caErr)}
	}

	crlBytes, err := signingBundle.Certificate.CreateCRL(rand.Reader, signingBundle.PrivateKey, revokedCerts, time.Now(), time.Now().Add(crlLifetime))
	if err != nil {
		return errutil.InternalError{Err: fmt.Sprintf("error creating new CRL: %s", err)}
	}

	err = req.Storage.Put(ctx, &logical.StorageEntry{
		Key:   "crl",
		Value: crlBytes,
	})
	if err != nil {
		return errutil.InternalError{Err: fmt.Sprintf("error storing CRL: %s", err)}
	}

	return nil
}

func shouldUpdateLWCRLEntry(ctx context.Context, b *backend, req *logical.Request) (bool, error) {
	crlConfig, crlErr := b.CRL(ctx, req.Storage)
	if crlErr != nil {
		return false, crlErr
	}
	if crlConfig != nil {
		return crlConfig.Lightweight, nil
	}

	return false, nil
}

// Creates a LWCRL entry
func storeLWCRLEntry(ctx context.Context, b *backend, req *logical.Request, serial string, expiration time.Time) error {
	update, err := shouldUpdateLWCRLEntry(ctx, b, req)
	if err != nil {
		return err
	}
	if !update {
		return nil
	}

	now := time.Now()
	notAfterProto, err := ptypes.TimestampProto(expiration)
	if err != nil {
		return fmt.Errorf("Unable to encode expiration (%v) into protobuf format: %v", expiration, err)
	}
	newEntry := LWCRLEntry{NotAfter: notAfterProto, RevocationTimeUtc: nil}

	b.lwCRLLock.Lock()
	defer b.lwCRLLock.Unlock()

	if b.presentLWCRL == nil {
		var lwcrl LWCRL
		lwcrlEntry, err := req.Storage.Get(ctx, "lwcrl")
		if err != nil {
			return fmt.Errorf("unable to read lightweight CRL entry: %v", err)
		}
		if lwcrlEntry != nil {
			// CRL exists, so decode it.
			if err := proto.Unmarshal(lwcrlEntry.Value, &lwcrl); err != nil {
				return fmt.Errorf("unable to decode local lightweight CRL entry: %v", err)
			}
		} else {
			lwcrl.Entries = make(map[string]*LWCRLEntry)
		}
		b.presentLWCRL = &lwcrl
	}

	duplicateEntry := false
	for candidate, entry := range b.presentLWCRL.Entries {
		notAfter, err := ptypes.Timestamp(entry.NotAfter)
		if err != nil {
			continue
		}

		// Certificate has expired; remove this entry.
		if notAfter.Before(now) {
			delete(b.presentLWCRL.Entries, candidate)
		} else if candidate == serial {
			// Ensures we re-add any expired entires for duplicate serials.
			duplicateEntry = true
		}
	}

	if !duplicateEntry {
		b.presentLWCRL.Entries[serial] = &newEntry
	}

	encoded, err := proto.Marshal(b.presentLWCRL)
	if err != nil {
		return fmt.Errorf("unable to encode local lightweight CRL entry: %v", err)
	}

	err = req.Storage.Put(ctx, &logical.StorageEntry{
		Key:   "lwcrl",
		Value: encoded,
	})
	if err != nil {
		return fmt.Errorf("unable to write lightweight CRL entry: %v", err)
	}

	return nil
}

// Revokes a LWCRL entry
func revokeLWCRLEntry(ctx context.Context, b *backend, req *logical.Request, serial string) (*LWCRL, error) {
	update, err := shouldUpdateLWCRLEntry(ctx, b, req)
	if err != nil {
		return nil, err
	}
	if !update {
		return nil, nil
	}

	now := time.Now()
	nowProto := ptypes.TimestampNow()

	b.lwCRLLock.Lock()
	defer b.lwCRLLock.Unlock()

	var lwcrlFound bool = b.presentLWCRL != nil
	if b.presentLWCRL == nil {
		var lwcrl LWCRL
		lwcrlEntry, err := req.Storage.Get(ctx, "lwcrl")
		if err != nil {
			return nil, fmt.Errorf("unable to read lightweight CRL entry: %v", err)
		}
		if lwcrlEntry != nil {
			// CRL exists, so decode it.
			if err := proto.Unmarshal(lwcrlEntry.Value, &lwcrl); err != nil {
				return nil, fmt.Errorf("unable to decode local lightweight CRL entry: %v", err)
			}
			lwcrlFound = true
			b.presentLWCRL = &lwcrl
		}

	}

	for candidate, entry := range b.presentLWCRL.Entries {
		notAfter, err := ptypes.Timestamp(entry.NotAfter)
		if err != nil {
			continue
		}

		// Certificate has expired; remove this entry.
		if notAfter.Before(now) {
			delete(b.presentLWCRL.Entries, candidate)
		} else if candidate == serial {
			// Matched our candidate serial number; revoke it.
			entry.RevocationTimeUtc = nowProto
		}
	}

	if lwcrlFound || update {
		encoded, err := proto.Marshal(b.presentLWCRL)
		if err != nil {
			return nil, fmt.Errorf("unable to encode local lightweight CRL entry: %v", err)
		}

		err = req.Storage.Put(ctx, &logical.StorageEntry{
			Key:   "lwcrl",
			Value: encoded,
		})
		if err != nil {
			return nil, fmt.Errorf("unable to write lightweight CRL entry: %v", err)
		}

		return b.presentLWCRL, nil
	} else {
		// If the lwcrl didn't exist, don't return our temporary (empty).
		return nil, nil
	}
}

func fetchLWCRL(ctx context.Context, b *backend, req *logical.Request) (*LWCRL, error) {
	if b.presentLWCRL != nil {
		return b.presentLWCRL, nil
	}

	var lwcrl LWCRL
	lwcrlEntry, err := req.Storage.Get(ctx, "lwcrl")
	if err != nil {
		return nil, fmt.Errorf("unable to read lightweight CRL entry: %v", err)
	}
	if lwcrlEntry != nil {
		// CRL exists, so decode it.
		if err := proto.Unmarshal(lwcrlEntry.Value, &lwcrl); err != nil {
			return nil, fmt.Errorf("unable to decode local lightweight CRL entry: %v", err)
		}

		b.presentLWCRL = &lwcrl
		return b.presentLWCRL, nil
	}

	return nil, nil
}
