package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"log"
	"os"
)

func main() {
	file, err := os.Open("serverip") //Open file with IP to pull cert information for

	if err != nil {
		log.Fatalf("failed opening file: %s", err)
	}

	scanner := bufio.NewScanner(file) //Read file information
	scanner.Split(bufio.ScanLines)    //Read all lines
	var txtlines []string             //Create splice for file contents

	for scanner.Scan() { //Read file contents into splice
		txtlines = append(txtlines, scanner.Text())
	}

	file.Close()

	tlsConfig := tls.Config{InsecureSkipVerify: true} //Set TLS to ignore cert errors
	listIPName := make(map[string][]string)           //Map to hold the IP Address and DNS names
	for _, ipaddress := range txtlines {              //Loop through list of IP and output certname associated
		ipWithPort := ipaddress + ":443"                     //Set IP & port for passing
		conn, err := tls.Dial("tcp", ipWithPort, &tlsConfig) //Make TLS call
		fmt.Println(err)

		if err != nil {
			log.Print(err)
			continue
		} else {
			certChain := conn.ConnectionState().PeerCertificates //Pull entire certificate chain
			cert := certChain[0]                                 //Set certificate to server based certificate
			listIPName[ipaddress] = cert.DNSNames                //Add the full list of names associated with cert to map
		}
	}
	fmt.Print(listIPName)
}

//outputcsv will take hash map of IP & addresses and output a CSV 
//representation of values within the passed map
func outputcsv(listIPName *map[string][]string) string, error {
	for k, v := range listIPName {

	}
	return csvIPName, err
}