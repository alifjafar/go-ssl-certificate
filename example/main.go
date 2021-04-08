package main

import (
	"fmt"
	"github.com/alifjafar/go-ssl-certificate"
	"log"
)

func main() {
	cert, err := ssl_certificate.CreateForHostname("farnetwork.net")
	if err != nil {
		log.Fatalln(err.Error())
	}
	fmt.Println("Issuer: " + cert.GetIssuer())
	fmt.Println("Domain:" +cert.GetDomain() )
	fmt.Println(fmt.Sprintf("Valid?: %t", cert.IsValid()))
	fmt.Println(fmt.Sprintf("Self Signed?: %t", cert.IsSelfSigned()))
	fmt.Println(fmt.Sprintf("Lifespan in days: %d", cert.LifespanInDays()))
}
