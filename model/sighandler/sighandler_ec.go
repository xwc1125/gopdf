/*
 * This file is subject to the terms and conditions defined in
 * file 'LICENSE.md', which is part of this source code package.
 */

package sighandler

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"github.com/gunnsth/pkcs7"
	"github.com/xwc1125/gopdf/core"
	"github.com/xwc1125/gopdf/model"
)

// Adobe ECC detached signature handler.
type adobeECCDetached struct {
	privateKey  *ecdsa.PrivateKey
	certificate *x509.Certificate

	emptySignature    bool
	emptySignatureLen int
}

// NewEmptyAdobeECCDetached creates a new Adobe.PPKMS/Adobe.PPKLite adbe.ECC.detached
// signature handler. The generated signature is empty and of size signatureLen.
// The signatureLen parameter can be 0 for the signature validation.
func NewEmptyAdobeECCDetached(signatureLen int) (model.SignatureHandler, error) {
	return &adobeECCDetached{
		emptySignature:    true,
		emptySignatureLen: signatureLen,
	}, nil
}

// NewAdobeECCDetached creates a new Adobe.PPKMS/Adobe.PPKLite adbe.ECC.detached signature handler.
// Both parameters may be nil for the signature validation.
func NewAdobeECCDetached(privateKey *ecdsa.PrivateKey, certificate *x509.Certificate) (model.SignatureHandler, error) {
	return &adobeECCDetached{
		certificate: certificate,
		privateKey:  privateKey,
	}, nil
}

// InitSignature initialises the PdfSignature.
func (a *adobeECCDetached) InitSignature(sig *model.PdfSignature) error {
	if !a.emptySignature {
		if a.certificate == nil {
			return errors.New("certificate must not be nil")
		}
		if a.privateKey == nil {
			return errors.New("privateKey must not be nil")
		}
	}

	handler := *a
	sig.Handler = &handler
	sig.Filter = core.MakeName("Adobe.PPKLite")
	sig.SubFilter = core.MakeName("ETSI.CAdES.detached")
	sig.Reference = nil

	digest, err := handler.NewDigest(sig)
	if err != nil {
		return err
	}
	digest.Write([]byte("calculate the Contents field size"))
	return handler.Sign(sig, digest)
}

func (a *adobeECCDetached) getCertificate(sig *model.PdfSignature) (*x509.Certificate, error) {
	certificate := a.certificate
	if certificate == nil {
		certData := sig.Cert.(*core.PdfObjectString).Bytes()
		certs, err := x509.ParseCertificates(certData)
		if err != nil {
			return nil, err
		}
		certificate = certs[0]
	}
	return certificate, nil
}

// NewDigest creates a new digest.
func (a *adobeECCDetached) NewDigest(sig *model.PdfSignature) (model.Hasher, error) {
	return bytes.NewBuffer(nil), nil
}

// Validate validates PdfSignature.
func (a *adobeECCDetached) Validate(sig *model.PdfSignature, digest model.Hasher) (model.SignatureValidationResult, error) {
	signed := sig.Contents.Bytes()
	p7, err := pkcs7.Parse(signed)
	if err != nil {
		return model.SignatureValidationResult{}, err
	}

	buffer := digest.(*bytes.Buffer)
	p7.Content = buffer.Bytes()
	if err = p7.Verify(); err != nil {
		return model.SignatureValidationResult{}, err
	}

	return model.SignatureValidationResult{
		IsSigned:   true,
		IsVerified: true,
	}, nil
}

// Sign sets the Contents fields.
func (a *adobeECCDetached) Sign(sig *model.PdfSignature, digest model.Hasher) error {
	if a.emptySignature {
		sigLen := a.emptySignatureLen
		if sigLen <= 0 {
			sigLen = 8192
		}

		sig.Contents = core.MakeHexString(string(make([]byte, sigLen)))
		return nil
	}

	buffer := digest.(*bytes.Buffer)
	signedData, err := pkcs7.NewSignedData(buffer.Bytes())
	if err != nil {
		return err
	}

	// Add the signing cert and private key
	if err := signedData.AddSigner(a.certificate, a.privateKey, pkcs7.SignerInfoConfig{}); err != nil {
		return err
	}

	// Call Detach() is you want to remove content from the signature
	// and generate an S/MIME detached signature
	signedData.Detach()
	// Finish() to obtain the signature bytes
	detachedSignature, err := signedData.Finish()
	if err != nil {
		return err
	}

	//data := make([]byte, 8192)
	data := make([]byte, 8192 * 2 + 2)
	copy(data, detachedSignature)

	// contents=8192 * 2 + 2
	sig.Contents = core.MakeHexString(string(data))
	return nil
}

// IsApplicable returns true if the signature handler is applicable for the PdfSignature
func (a *adobeECCDetached) IsApplicable(sig *model.PdfSignature) bool {
	if sig == nil || sig.Filter == nil || sig.SubFilter == nil {
		return false
	}
	return (*sig.Filter == "Adobe.PPKMS" || *sig.Filter == "Adobe.PPKLite") && *sig.SubFilter == "ETSI.CAdES.detached"
}
