package ssl_certificate

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log"
	netUrl "net/url"
	"time"
)

type SSLCertificate struct {
	certificate *x509.Certificate
}

var PORT = "443"

func CreateForHostname(host string) (*SSLCertificate, error) {
	cfg := tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
	}
	conn, err := tls.Dial("tcp", host+":"+PORT, &cfg)
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

func CreateForURL(rawUrl string) (*SSLCertificate, error) {
	url, err := netUrl.Parse(rawUrl)
	if err != nil {
		return nil, err
	}

	if url.Hostname() == "" {
		return nil, errors.New("invalid URL")
	}

	if url.Scheme != "https" {
		return nil, errors.New("url scheme must be https")
	}

	return CreateForHostname(url.Hostname())
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
	return int(x.certificate.NotAfter.Sub(x.certificate.NotBefore).Hours() / 24)
}

func (x SSLCertificate) IsSelfSigned() bool {
	return x.GetIssuer() == x.GetDomain()
}

func (x SSLCertificate) DaysUntilExpiredDate() int {
	return int(x.certificate.NotAfter.Sub(time.Now()).Hours() / 24)
}

func (x SSLCertificate) ExpiredDate() time.Time {
	return x.certificate.NotAfter
}
