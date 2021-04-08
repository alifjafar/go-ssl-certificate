package ssl_certificate

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"time"
)

type SSLCertificate struct {
	certificate *x509.Certificate
}

var PORT = "443"

func CreateForHostname(url string) (*SSLCertificate, error) {
	cfg := tls.Config{
		InsecureSkipVerify: true,
		ServerName:         url,
	}
	conn, err := tls.Dial("tcp", url+":"+PORT, &cfg)
	if err != nil {
		log.Fatalln("Connection failed: " + err.Error())
		return nil, err
	}

	certChain := conn.ConnectionState().PeerCertificates
	cert := certChain[0]
	return &SSLCertificate{
		certificate: cert,
	}, nil
}

func (x SSLCertificate) GetIssuer() string {
	return x.certificate.Issuer.CommonName
}

func (x SSLCertificate) GetDomain() string {
	return x.certificate.Subject.CommonName
}

func (x SSLCertificate) GetDomains() []string {
	return x.certificate.DNSNames
}

func (x SSLCertificate) IsValid() bool {
	return !x.IsExpired()
}

func (x SSLCertificate) IsExpired() bool {
	return time.Now().After(x.certificate.NotAfter)
}

func (x SSLCertificate) LifespanInDays() int {
	return int(x.certificate.NotAfter.Sub(x.certificate.NotBefore) / (24 * time.Hour))
}

func (x SSLCertificate) IsSelfSigned() bool {
	return x.GetIssuer() == x.GetDomain()
}