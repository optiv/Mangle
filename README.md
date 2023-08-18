# THIS REPOSITORY HAS BEEN ARCHIVED

To view the latest version of Mangle or to submit an issue, reference https://github.com/Tylous/Mangle.


# Mangle




<p align="center"> <img src=Screenshots/logo.png>

<p align="center"> <b>Authored By Tyl0us</b>


<p align="left"><b>Featured at Source Zero Con 2022</b>

Mangle is a tool that manipulates aspects of compiled executables (.exe or DLL). Mangle can remove known Indicators of Compromise (IoC) based strings and replace them with random characters, change the file by inflating the size to avoid EDRs, and can clone code-signing certs from legitimate files. In doing so, Mangle helps loaders evade on-disk and in-memory scanners.

## Contributing
Mangle was developed in Golang.

## Install

The first step, as always, is to clone the repo. Before you compile Mangle, you'll need to install the dependencies. To install them, run the following commands:

```
go get github.com/Binject/debug/pe
```

Then build it

```
go build Mangle.go
```

## Important 
While Mangle is written in Golang, a lot of the features are designed to work on executable files from other languages. At the time of release, the only feature that is Golang specific is the string manipulation part.

## Usage

```
./mangle -h

	   _____                        .__
	  /     \ _____    ____    ____ |  |   ____
	 /  \ /  \\__  \  /    \  / ___\|  | _/ __ \
	/    Y    \/ __ \|   |  \/ /_/  >  |_\  ___/
	\____|__  (____  /___|  /\___  /|____/\___  >
		\/     \/     \//_____/   	  \/
					(@Tyl0us)
Usage of ./Mangle:
  -C string
        Path to the file containing the certificate you want to clone
  -I string
        Path to the orginal file
  -M    Edit the PE file to strip out Go indicators
  -O string
        The new file name
  -S int
        How many MBs to increase the file by

```
## Strings

Mangle takes the input executable and looks for known strings that security products look for or alert on. These strings alone are not the sole point of detection. Often, these strings are in conjunction with other data points and pieces of telemetry for detection and prevention. Mangle finds these known strings and replaces the hex values with random ones to remove them. IMPORTANT: Mangle replaces the exact size of the strings it’s manipulating. It doesn’t add any more or any less, as this would create misalignments and instabilities in the file. Mangle does this using the `-M` command-line option.

Currently, Mangle only does Golang files but as time goes on other languages will be added. If you know of any for other languages, please open an issue ticket and submit them.


<p align="center"><b>Before</b>
<p align="center"> <img src=Screenshots/Strings_Before.png border="2px solid #555">

<p align="center"><b>After</b>
<p align="center"> <img src=Screenshots/Strings_After.png border="2px solid #555">




## Inflate


Pretty much all EDRs can’t scan both on disk or in memory files beyond a certain size. This simply stems from the fact that large files take longer to review, scan, or monitor. EDRs do not want to impact performance by slowing down the user's productivity. Mangle inflates files by creating a padding of Null bytes (Zeros) at the end of the file. This ensures that nothing inside the file is impacted. To inflate an executable, use the `-S` command-line option along with the number of bytes you want to add to the file. Large payloads are really not an issue anymore with how fast Internet speeds are, that being said, it's not recommended to make a 2 gig file.



Based on test cases across numerous userland and kernel EDRs, it is recommended to increase the size by either 95-100 megabytes. Because vendors do not check large files, the activity goes unnoticed, resulting in the successful execution of shellcode.

### Example: 
<img src="Screenshots/Demo.gif"/>



## Certificate


Mangle also contains the ability to take the full chain and all attributes from a legitimate code-signing certificate from a file and copy it onto another file. This includes the signing date, counter signatures, and other measurable attributes.

While this feature may sound similar to another tool I developed, [Limelighter](https://github.com/Tylous/Limelighter), the major difference between the two is that Limelighter makes a fake certificate based off a domain and signs it with the current date and time, versus using valid attributes where the timestamp is taken from when the original file. This option can use DLL or .exe files to copy using the `-C` command-line option, along with the path to the file you want to copy the certificate from.


<p align="center"> <img src=Screenshots/Cert_Copy.png border="2px solid #555">

## Credit
* Special thanks to Jessica of SuperNovasStore for creating the logo.
* Special thanks to Binject for his [repo](https://github.com/Binject/debug)
