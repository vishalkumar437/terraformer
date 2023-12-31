package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

const filePrefix = "provider_cmd_"
const fileSuffix = ".go"
const packageCmdPath = "cmd"

func main() {
	// provider := os.Args[1]
	allProviders := []string{}
	files, err := os.ReadDir(packageCmdPath)
	if err != nil {
		log.Println(err)
	}
	for _, f := range files {
		if strings.HasPrefix(f.Name(), filePrefix) {
			providerName := strings.ReplaceAll(f.Name(), filePrefix, "")
			providerName = strings.ReplaceAll(providerName, fileSuffix, "")
			allProviders = append(allProviders, providerName)
		}
	}
	for _, arch := range []string{"amd64", "arm64"} {
		for _, OS := range []string{"linux", "windows", "mac"} {
			for _, provider := range allProviders {
				GOOS := ""
				binaryName := ""
				switch OS {
				case "linux":
					GOOS = "linux"
					binaryName = "terraformer-" + provider + "-linux-" + arch
				case "windows":
					GOOS = "windows"
					binaryName = "terraformer-" + provider + "-windows-" + arch + ".exe"
				case "mac":
					GOOS = "darwin"
					binaryName = "terraformer-" + provider + "-darwin-" + arch
				}
				log.Println("Build terraformer with "+provider+" provider...", "GOOS=", GOOS, " for GOARCH=", arch)
				deletedProvider := []string{}
				for _, f := range files {
					if strings.HasPrefix(f.Name(), filePrefix) {
						if !strings.HasPrefix(f.Name(), filePrefix+provider+fileSuffix) {
							providerName := strings.ReplaceAll(f.Name(), filePrefix, "")
							providerName = strings.ReplaceAll(providerName, fileSuffix, "")
							deletedProvider = append(deletedProvider, providerName)
						}
					}
				}
				// move files for deleted providers
				err := os.MkdirAll(packageCmdPath+"/tmp", os.ModePerm)
				if err != nil {
					log.Fatal("err:", err)
				}
				for _, provider := range deletedProvider {
					err := os.Rename(packageCmdPath+"/"+filePrefix+provider+fileSuffix, packageCmdPath+"/tmp/"+filePrefix+provider+fileSuffix)
					if err != nil {
						log.Println(err)
					}
				}

				// comment deleted providers in code
				rootCode, err := os.ReadFile(packageCmdPath + "/root.go")
				if err != nil {
					log.Fatal("err:", err)
				}
				lines := strings.Split(string(rootCode), "\n")
				newRootCodeLines := make([]string, len(lines))
				for i, line := range lines {
					for _, provider := range deletedProvider {
						if strings.Contains(strings.ToLower(line), "newcmd"+provider+"importer") {
							line = "// " + line
						}
						if strings.Contains(strings.ToLower(line), "new"+provider+"provider") {
							line = "// " + line
						}
					}
					newRootCodeLines[i] = line
				}
				newRootCode := strings.Join(newRootCodeLines, "\n")
				err = os.WriteFile(packageCmdPath+"/root.go", []byte(newRootCode), os.ModePerm)
				if err != nil {
					log.Fatal("err:", err)
				}

				// build....
				cmd := exec.Command("go", "build", "-v", "-o", binaryName)
				cmd.Env = os.Environ()
				cmd.Env = append(cmd.Env, "GOOS="+GOOS)
				cmd.Env = append(cmd.Env, "GOARCH="+arch)
				var outb, errb bytes.Buffer
				cmd.Stdout = &outb
				cmd.Stderr = &errb
				err = cmd.Run()
				if err != nil {
					log.Fatal("err:", errb.String())
				}
				fmt.Println(outb.String())

				// revert code and files
				err = os.WriteFile(packageCmdPath+"/root.go", rootCode, os.ModePerm)
				if err != nil {
					log.Fatal("err:", err)
				}
				for _, provider := range deletedProvider {
					err := os.Rename(packageCmdPath+"/tmp/"+filePrefix+provider+fileSuffix, "cmd/"+filePrefix+provider+fileSuffix)
					if err != nil {
						log.Println(err)
					}
				}
			}
		}
	}
}
