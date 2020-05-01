package main

import (
	"bufio"
	"crypto/tls"
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"os"
)

/*************************************************************************
Program will take a file with an IP on each line and output the IP and the
DNS name associated with the certificate that is returned.
**************************************************************************/

func main() {
	//Setup variables
	inputFile := flag.String("i", "filename", "input filename")
	outputFile := flag.String("o", "filename", "output filename")
	screenOnly := flag.Bool("s", false, "print to screen")
	flag.Parse()

	fmt.Println(*inputFile)
	fmt.Println(*outputFile)
	fmt.Println(*screenOnly)

	file, err := os.Open(*inputFile) //Open file with IP to pull cert information for

	if err != nil {
		log.Fatalf("failed opening file: %s", err)
	}

	//Read file information
	scanner := bufio.NewScanner(file) //Read file information
	scanner.Split(bufio.ScanLines)    //Read all lines
	var txtlines []string             //Create splice for file contents

	for scanner.Scan() { //Read file contents into splice
		txtlines = append(txtlines, scanner.Text())
	}

	file.Close()

	//Connect via TLS and pull certificate information
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

	//fmt.Println(listIPName)
	outputcsv(&listIPName, outputFile, screenOnly)
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
func outputcsv(sarr *[][]string, of *string, s *bool) error {
	err := fmt.Errorf("error in outputcsv") //Send error if unable to write
	if *s {
		w := csv.NewWriter(os.Stdout) //Write output to console
		w.WriteAll(*sarr)             // calls Flush internally
		if err := w.Error(); err != nil {
			log.Fatalln("error writing csv:", err)
		}
	} else {
		csvFile, err := os.Create(*of)
		if err != nil {
			log.Fatalf("failed creating file: %s", err)
		}
		csvwriter := csv.NewWriter(csvFile)
		for _, row := range *sarr {
			_ = csvwriter.Write(row)
		}
		csvwriter.Flush()
		csvFile.Close()

	}
	return err
}

/*getfilenames will scan from command line and set variables for
input / output files and return them in as two variables inputfile & outputFile*/
func getfilenames() (string, string) {
	fmt.Println("Enter name of input file: ")
	inputfile := bufio.NewScanner(os.Stdin) //Get input file name
	inputfile.Scan()
	fmt.Println("Enter name of output file: ")
	outputfile := bufio.NewScanner(os.Stdin) //Get output file name
	outputfile.Scan()
	return inputfile.Text(), outputfile.Text()

}
