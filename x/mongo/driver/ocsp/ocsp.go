// Copyright (C) MongoDB, Inc. 2017-present.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

package ocsp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/asn1"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/crypto/ocsp"
)

var (
	mustStapleExtensionOID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}
	ocspSigningExtensionID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}
)

// Verify performs OCSP verification for the provided ConnectionState instance.
func Verify(ctx context.Context, connState tls.ConnectionState) error {
	if len(connState.VerifiedChains) == 0 {
		return newOCSPError(errors.New("no verified certificate chains reported after TLS handshake"))
	}

	certChain := connState.VerifiedChains[0]
	if numCerts := len(certChain); numCerts == 0 {
		return newOCSPError(errors.New("verified chain contained no certificates"))
	}

	ocspCfg, err := newConfig(certChain)
	if err != nil {
		return newOCSPError(err)
	}

	res, err := parseStaple(ocspCfg, connState.OCSPResponse)
	if err != nil {
		return newOCSPError(err)
	}
	if res == nil {
		// If there was no staple, contact responders.
		res, err = contactResponders(ctx, ocspCfg)
		if err != nil {
			return newOCSPError(err)
		}
	}
	if res == nil {
		// If no response was parsed from the staple and responders, the status of the certificate is unknown, so
		// don't error.
		return nil
	}

	if err = verifyResponse(ocspCfg, res); err != nil {
		return newOCSPError(err)
	}
	return nil
}

func newOCSPError(wrapped error) error {
	return fmt.Errorf("OCSP verification failed: %v", wrapped)
}

// parseStaple returns a parsed OCSP response for a staple. An error will be returned if the server certificate has the
// Must-Staple extension and the stapled response is empty or if there is an error parsing the staple.
func parseStaple(cfg config, staple []byte) (*ocsp.Response, error) {
	var mustStaple bool
	for _, extension := range cfg.serverCert.Extensions {
		if extension.Id.Equal(mustStapleExtensionOID) {
			mustStaple = true
			break
		}
	}

	// If the server has a Must-Staple certificate and the server does not present a stapled OCSP response, error.
	if mustStaple && len(staple) == 0 {
		return nil, errors.New("server provided a certificate with the Must-Staple extension but did not " +
			"provde a stapled OCSP response")
	}

	if len(staple) == 0 {
		return nil, nil
	}

	parsedResponse, err := ocsp.ParseResponseForCert(staple, cfg.serverCert, nil)
	if err != nil {
		// If the stapled response could not be parsed correctly, error. This can happen if the response is malformed,
		// the response does not cover the certificate presented by the server, or if the response contains an error
		// status.
		return nil, fmt.Errorf("error parsing stapled response: %v", err)
	}
	return parsedResponse, nil
}

// contactResponders will send an HTTP POST request to each responder reported in the server certificate and return a
// parsed OCSP response for the first response with a non-unknown status. If no responder can be successfully contacted,
// nil will be returned.
func contactResponders(ctx context.Context, cfg config) (*ocsp.Response, error) {
	if len(cfg.serverCert.OCSPServer) == 0 {
		return nil, nil
	}

	requestBytes, err := ocsp.CreateRequest(cfg.serverCert, cfg.issuer, nil)
	if err != nil {
		return nil, nil
	}

	for _, endpoint := range cfg.serverCert.OCSPServer {
		// Use bytes.NewReader instead of bytes.NewBuffer because a bytes.Buffer is an owning representation and the
		// docs recommend not using the underlying []byte after creating the buffer, so a new copy of requestBytes would
		// be needed for each request.
		httpRequest, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(requestBytes))
		if err != nil {
			continue
		}
		httpRequest.Header.Add("Content-Type", "application/ocsp-request")

		httpResponse, err := http.DefaultClient.Do(httpRequest)
		if err != nil {
			// If the request errored due to a timeout or context cancellation, abort the verification process.
			// Otherwise, the status of the certificate is still unknown, so try the next responder.
			urlErr, ok := err.(*url.Error)
			if !ok {
				continue
			}

			if urlErr.Timeout() || urlErr.Err == context.Canceled {
				return nil, errors.New("request to OCSP responder timed out or was cancelled")
			}
			continue
		}
		if httpResponse.StatusCode != 200 {
			continue
		}

		ocspResponse, err := ioutil.ReadAll(httpResponse.Body)
		if err != nil {
			_ = httpResponse.Body.Close()
			continue
		}
		_ = httpResponse.Body.Close()

		parsedResponse, err := ocsp.ParseResponseForCert(ocspResponse, cfg.serverCert, nil)
		if err != nil || parsedResponse.Status == ocsp.Unknown {
			// If there was an error parsing the response or the response was inconclusive, try the next responder.
			// TODO: should we special case errors here? e.g. malformed response = error?
			continue
		}
		return parsedResponse, nil
	}

	// Either all responders were unavailable or responded that the certificate status is unknown.
	return nil, nil
}

func verifyResponseSignature(cfg config, res *ocsp.Response) error {
	if res.Certificate == nil {
		// The issuer for the OCSP response is the same as the issuer of the server certificate.
		// Verify that the issuer signed the response.
		if err := res.CheckSignatureFrom(cfg.issuer); err != nil {
			return fmt.Errorf("error checking that issuer signed the OCSP response: %v", err)
		}
		return nil
	}

	// RFC 6960 Section 4.2.2.2: The responder can return a certificate that is the issuer of the leaf certificate. In
	// this case, there is no delegate and the issuer is already trusted. Return without additional checks.
	if bytes.Equal(res.Certificate.RawSubject, cfg.issuer.RawSubject) {
		return nil
	}

	// There is a delegate. The initial call to ParseResponseForCert has already verified that the response was
	// correctly signed by the delegate. Verify that the delegate is authorized to sign OCSP responses and that the
	// delegate has been signed by a certificate in the known verified chain.

	var canSign bool
	for _, extension := range res.Certificate.Extensions {
		if extension.Id.Equal(ocspSigningExtensionID) {
			canSign = true
			break
		}
	}
	if !canSign {
		return errors.New("certificate reported in OCSP response does not have the OCSP-Signing extension")
	}

	issuer := getIssuer(res.Certificate, cfg.chain)
	if issuer == nil {
		return errors.New("issuer for certificate reported in OCSP response not found in certificate chain")
	}

	err := issuer.CheckSignature(
		res.Certificate.SignatureAlgorithm,
		res.Certificate.RawTBSCertificate,
		res.Certificate.Signature,
	)
	if err != nil {
		return fmt.Errorf("error checking that the issuer signed the delegate OCSP certificate: %v", err)
	}
	return nil
}

func verifyResponse(cfg config, res *ocsp.Response) error {
	if err := verifyResponseSignature(cfg, res); err != nil {
		return fmt.Errorf("error verifying response signature: %v", err)
	}

	currTime := time.Now().UTC()
	if res.ThisUpdate.After(currTime) {
		return fmt.Errorf("reported thisUpdate time %s is after current time %s", res.ThisUpdate, currTime)
	}
	if !res.NextUpdate.IsZero() && res.NextUpdate.Before(currTime) {
		return fmt.Errorf("reported nextUpdate time %s is before current time %s", res.NextUpdate, currTime)
	}
	if res.Status == ocsp.Revoked {
		return errors.New("certificate is revoked")
	}
	return nil
}
