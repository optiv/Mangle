package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	mrand "math/rand"
	"strconv"
	"strings"
	"time"

	"github.com/Binject/debug/pe"
)

var hex = "abcef12345678890"

func GenerateNumer(min, max int) string {
	mrand.Seed(time.Now().UnixNano())
	num := mrand.Intn(max-min) + min
	n := num
	s := strconv.Itoa(n)
	return s

}

func RandStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = hex[mrand.Intn(len(hex))]

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

	fmt.Println("[!] Writing to new file " + opt.outFile)
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
	fmt.Println("[*] Stripped out golang strings")
	return []byte(mydata)

}

func Padding(buff []byte, size int) []byte {
	str1 := "0"
	res1 := strings.Repeat(str1, (size * 1024 * 1024))
	sourceBytes, err := pe.NewFile(bytes.NewReader(buff))
	if err != nil {
		log.Panic("Error Reading Inputed File")
	}
	//Shoutout to Binject for their project binjection where I borrowed some of the code below.
	var sectionAlignment, fileAlignment, scAddr uint32
	var imageBase uint64
	var shellcode []byte
	lastSection := sourceBytes.Sections[sourceBytes.NumberOfSections-1]
	switch file := (sourceBytes.OptionalHeader).(type) {
	case *pe.OptionalHeader32:
		imageBase = uint64(file.ImageBase)
		sectionAlignment = file.SectionAlignment
		fileAlignment = file.FileAlignment
		scAddr = align(lastSection.Size, fileAlignment, lastSection.Offset)
		break
	case *pe.OptionalHeader64:
		imageBase = file.ImageBase
		sectionAlignment = file.SectionAlignment
		fileAlignment = file.FileAlignment
		scAddr = align(lastSection.Size, fileAlignment, lastSection.Offset)
		break
	}

	buf := bytes.NewBuffer([]byte(res1))
	w := bufio.NewWriter(buf)
	binary.Write(w, binary.LittleEndian, imageBase)
	w.Flush()
	shellcode = buf.Bytes()

	shellcodeLen := len(shellcode)
	newsection := new(pe.Section)
	newsection.Name = "." + RandomString(5)
	o := []byte(newsection.Name)
	newsection.OriginalName = [8]byte{o[0], o[1], o[2], o[3], o[4], o[5], 0, 0}
	newsection.VirtualSize = uint32(shellcodeLen)
	newsection.VirtualAddress = align(lastSection.VirtualSize, sectionAlignment, lastSection.VirtualAddress)
	newsection.Size = align(uint32(shellcodeLen), fileAlignment, 0)
	newsection.Offset = align(lastSection.Size, fileAlignment, lastSection.Offset)
	newsection.Characteristics = pe.IMAGE_SCN_CNT_CODE | pe.IMAGE_SCN_MEM_EXECUTE | pe.IMAGE_SCN_MEM_READ
	sourceBytes.InsertionAddr = scAddr
	sourceBytes.InsertionBytes = shellcode

	switch file := (sourceBytes.OptionalHeader).(type) {
	case *pe.OptionalHeader32:
		v := newsection.VirtualSize
		if v == 0 {
			v = newsection.Size
		}
		file.SizeOfImage = align(v, sectionAlignment, newsection.VirtualAddress)
		file.CheckSum = 0
		break
	case *pe.OptionalHeader64:
		v := newsection.VirtualSize
		if v == 0 {
			v = newsection.Size
		}
		file.SizeOfImage = align(v, sectionAlignment, newsection.VirtualAddress)
		file.CheckSum = 0
		break
	}
	sourceBytes.FileHeader.NumberOfSections++
	sourceBytes.Sections = append(sourceBytes.Sections, newsection)
	Bytes, _ := sourceBytes.Bytes()

	fmt.Println("[*] Padding has been added to increase size")
	return Bytes

}

func Stealer(InputFileData, FiletoCopy []byte) []byte {
	signedFileReader := bytes.NewReader(FiletoCopy)
	signedsourceBytes, err := pe.NewFile(signedFileReader)
	if err != nil {

	}

	targetFileReader := bytes.NewReader(InputFileData)
	targetsourceBytes, err := pe.NewFile(targetFileReader)
	if err != nil {

	}

	targetsourceBytes.CertificateTable = signedsourceBytes.CertificateTable
	Data, err := targetsourceBytes.Bytes()
	if err != nil {
	}
	fmt.Println("[*] Cloned certificate values")
	return Data
}

func align(size, align, addr uint32) uint32 {
	if 0 == (size % align) {
		return addr + size
	}
	return addr + (size/align+1)*align
}

func RandomString(len int) string {
	bytes := make([]byte, len)
	for i := 0; i < len; i++ {
		r, _ := rand.Int(rand.Reader, big.NewInt(25))
		bytes[i] = 97 + byte(r.Int64()) //a=97
	}
	return string(bytes)
}
