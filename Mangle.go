package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"strconv"
	"strings"
	"time"

	"github.com/Binject/debug/pe"
)

var hex = "abcef12345678890"

func GenerateNumer(min, max int) string {
	rand.Seed(time.Now().UnixNano())
	num := rand.Intn(max-min) + min
	n := num
	s := strconv.Itoa(n)
	return s

}

func RandStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = hex[rand.Intn(len(hex))]

	}
	return string(b)
}

type FlagOptions struct {
	outFile    string
	inputFile  string
	CertCloner string
	GoStrip    bool
	size       int
}

func options() *FlagOptions {
	outFile := flag.String("O", "", "The new file name")
	inputFile := flag.String("I", "", "Path to the orginal file")
	CertCloner := flag.String("C", "", "Path to the file containing the certificate you want to clone")
	GoStrip := flag.Bool("M", false, "Edit the PE file to strip out Go indicators")
	size := flag.Int("S", 0, "How many MBs to increase the file by")
	flag.Parse()
	return &FlagOptions{outFile: *outFile, inputFile: *inputFile, CertCloner: *CertCloner, GoStrip: *GoStrip, size: *size}
}

func main() {
	fmt.Println(` 
	   _____                        .__          
	  /     \ _____    ____    ____ |  |   ____  
	 /  \ /  \\__  \  /    \  / ___\|  | _/ __ \ 
	/    Y    \/ __ \|   |  \/ /_/  >  |_\  ___/ 
	\____|__  (____  /___|  /\___  /|____/\___  >
		\/     \/     \//_____/   	  \/                    
					(@Tyl0us)`)

	opt := options()
	if opt.inputFile == "" {
		log.Fatal("Error: Please provide a path to a file you wish to mangle")
	}

	if opt.outFile == "" {
		log.Fatal("Error: Please provide a name for the final file")
	}
	InputFileData, err := ioutil.ReadFile(opt.inputFile)

	if err != nil {
		log.Fatalf("Error: %s", err)
	}
	if opt.CertCloner != "" {
		FiletoCopy, err := ioutil.ReadFile(opt.CertCloner)
		if err != nil {
			log.Fatalf("Error: %s", err)
		}
		InputFileData = Stealer(InputFileData, FiletoCopy)
	}
	if opt.size > 0 {
		InputFileData = Padding(InputFileData, opt.size)
	}

	if opt.GoStrip == true {
		InputFileData = GoEditor(InputFileData)
	}

	ioutil.WriteFile(opt.outFile, InputFileData, 0777)

}

func GoEditor(buff []byte) []byte {
	gostringg1 := "to unallocated span37252902984619140625Arabic Standard TimeAzores Standard"
	gostringg2 := "TimeCertFindChainInStoreCertOpenSystemStoreWChangeServiceConfigWCheckTokenMembershipCreateProcessAsUserWCryptAcquireContextWEgyptian_HieroglyphsEtwReplyNotificationGetAcceptExSockaddrsGetAdaptersAddressesGetCurrentDirectoryWGetFileAttributesExWGetModuleInformationGetProcessMemoryInfoGetWindowsDirectoryWIDS_Trinary_OperatorIsrael Standard TimeJordan Standard TimeMeroitic_Hieroglyphs"
	gostringg3 := "Standard Timebad defer size classbad font file formatbad system page sizebad use of bucket.bpbad use of bucket.mpchan send (nil chan)close of nil channelconnection timed outdodeltimer0: wrong Pfloating point errorforcegc: phase errorgo of nil func valuegopark: bad g statusinconsistent lockedminvalid request"
	gostringg4 := "codeinvalid write resultis a named type filekey has been revokedmalloc during signalnotetsleep not on g0p mcache not flushedpacer: assist ratio=preempt off reason: reflect.Value.SetIntreflect.makeFuncStubruntime: double waitruntime: unknown pc semaRoot rotateRighttime: invalid numbertrace: out of memorywirep: already in goworkbuf is not emptywrite of Go pointer ws2_32.dll not foundzlib: invalid header of unexported method previous allocCount=, levelBits[level] = 186264514923095703125931322574615478515625AdjustTokenPrivilegesAlaskan Standard TimeAnatolian_HieroglyphsArabian Standard TimeBelarus Standard TimeCentral Standard TimeChangeServiceConfig2WDeregisterEventSourceEastern Standard"
	gostringg5 := "0123456789abcdefghijklmnopqrstuvwxyz444089209850062616169452667236328125Go pointer stored into non-Go memory"
	gostringg6 := "buildinf:"
	gostringg7 := " Go build ID:"
	gostringg8 := "gogo"
	gostringg9 := "goid"
	gostringg10 := "go.buildid"
	gostringg11 := "_cgo_dummy_export"
	stringnum := []string{gostringg1, gostringg2, gostringg3, gostringg4, gostringg5, gostringg6, gostringg7, gostringg8, gostringg9, gostringg10, gostringg11}

	mydata := string(buff)
	for i := range stringnum {
		val := RandStringBytes(len(stringnum[i]))
		mydata = strings.ReplaceAll(string(mydata), stringnum[i], val)
	}
	return []byte(mydata)

}

func Padding(buff []byte, size int) []byte {
	str1 := "0"
	res1 := strings.Repeat(str1, (size * 1024 * 1024))
	sum := string(buff) + res1
	mydata := []byte(sum)
	return mydata

}

func Stealer(InputFileData, FiletoCopy []byte) []byte {
	signedFileReader := bytes.NewReader(FiletoCopy)
	signedPEFile, err := pe.NewFile(signedFileReader)
	if err != nil {

	}

	targetFileReader := bytes.NewReader(InputFileData)
	targetPEFile, err := pe.NewFile(targetFileReader)
	if err != nil {

	}

	targetPEFile.CertificateTable = signedPEFile.CertificateTable
	Data, err := targetPEFile.Bytes()
	if err != nil {
	}

	return Data
}
