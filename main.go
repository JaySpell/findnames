package main

import (
	"bufio"
	"crypto/tls"
	"encoding/csv"
	"fmt"
	"log"
	"os"
)

/*************************************************************************
Program will take a file with an IP on each line and output the IP and the
DNS name associated with the certificate that is returned.
**************************************************************************/

func main() {
	args := os.Args[1:]
	var inputfile, outputfile string
	if args != nil {
		for i := 0; i < len(args); i++ {
			if args[i] == "-i" {
				inputfile = args[i+1]
			} else if args[i] == "-o" {
				outputfile = args[i+1]
			}
		}
	}
	if inputfile == "" || outputfile == "" {
		inputfile, outputfile = getfilenames()
	}
	fmt.Println("files = ", inputfile, outputfile)
	file, err := os.Open(inputfile) //Open file with IP to pull cert information for

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
	listIPName := [][]string{}                        //Map to hold the IP Address and DNS names
	for _, ipaddress := range txtlines {              //Loop through list of IP and output certname associated
		ipWithPort := ipaddress + ":443"                     //Set IP & port for passing
		conn, err := tls.Dial("tcp", ipWithPort, &tlsConfig) //Make TLS call
		//fmt.Println(err)

		if err != nil {
			log.Print(err)
			continue
		} else {
			certChain := conn.ConnectionState().PeerCertificates //Pull entire certificate chain
			cert := certChain[0]                                 //Set cert to the first certificate in chain
			if len(cert.DNSNames) != 0 {
				ip := []string{ipaddress, cert.DNSNames[0]} //Set IP slice to the IP address & DNS name for cert
				addtoslice(&listIPName, ip)                 //Add the full list of names associated with cert to map
			} else {
				continue
			}
		}
	}
	//fmt.Print(listIPName)
	outputcsv(&listIPName)
}

//addtoslice will take a slice and add another slice to it
//first slice will be passed by address / second passed by value
func addtoslice(sarr *[][]string, s []string) {
	defer func() {
		if err := recover(); err != nil {
			fmt.Println(err)
		}
	}()
	*sarr = append(*sarr, s)
}

//outputcsv will take hash map of IP & addresses and output a CSV
//representation of values within the passed map
func outputcsv(sarr *[][]string) error {
	err := fmt.Errorf("Could not write to file") //Send error if unable to write
	w := csv.NewWriter(os.Stdout)                //Write output to console
	w.WriteAll(*sarr)                            // calls Flush internally
	if err := w.Error(); err != nil {
		log.Fatalln("error writing csv:", err)
	}
	return err
}

/*getfilenames will scan from command line and set variables for
input / output files and return them in as two variables inputfile & outputfile*/
func getfilenames() (string, string) {
	fmt.Println("Enter name of input file: ")
	inputfile := bufio.NewScanner(os.Stdin) //Get input file name
	inputfile.Scan()
	fmt.Println("Enter name of output file: ")
	outputfile := bufio.NewScanner(os.Stdin) //Get output file name
	outputfile.Scan()

	return inputfile.Text(), outputfile.Text()

}
