package sshclient

import (
	"io/ioutil"
	"os"
	"testing"
	"time"
)

var sshClient = &Config{
	Server:   "127.0.0.1",
	Port:     "2227",
	User:     "root",
	Password: "root",
	Timeout:  30 * time.Second,
	//Keypath: "/Users/test/.ssh/id_rsa",
}

func TestStream(t *testing.T) {
	t.Parallel()

	commands := [][]string{
		{"echo 123456", "123456"},
		{`for i in $(seq 1 5); do echo "$i"; done`, "12345"},
	}

	for _, command := range commands {
		stdOutChan, stdErrChan, done, err := sshClient.Stream(command[0])
		if err != nil {
			t.Error(err)
		}

		stdOut := ""
		stdErr := ""

		running := true
		for running {
			select {
			case line := <-stdOutChan:
				stdOut += line
			case line := <-stdErrChan:
				stdErr += line
			case <-done:
				running = false
			}
		}

		if stdOut != command[1] {
			t.Errorf("Command %s did not meet expected output %s", command[0], command[1])
		}
	}
}

func TestRun(t *testing.T) {
	t.Parallel()

	commands := [][]string{
		{"echo 12345", "12345"},
		{`for i in $(seq 1 5); do echo "$i"; done`, "12345"},
	}

	for _, command := range commands {
		stdOut, stdErr, err := sshClient.Run(command[0])
		if err != nil {
			t.Error(err)
		}

		if stdOut != command[1] {
			t.Errorf("Command %s did not meet expected output %s", command[0], command[1])
		}

		if len(stdErr) > 0 {
			t.Errorf("stderr content was found: %s (%s)", stdErr, command[0])
		}
	}
}

func TestCopy(t *testing.T) {
	t.Parallel()

	fileContent := []byte("example file content;--~@")
	sourceFile := "/tmp/test-copy-src"
	etargetFile := "/tmp/test-copy-dest"

	ioutil.WriteFile(sourceFile, fileContent, 0644)

	err := sshClient.Copy(sourceFile, etargetFile)
	if err != nil {
		t.Error(err)
	}

	err = os.Remove(sourceFile)
	if err != nil {
		t.Error(err)
	}

	stdOut, stdErr, err := sshClient.Run("cat " + etargetFile)
	if err != nil {
		t.Error(err)
	}

	if stdOut != string(fileContent) {
		t.Errorf("File content does not match: %s should be %s", stdOut, string(etargetFile))
	}

	if len(stdErr) > 0 {
		t.Errorf("stderr content was found: %s", stdErr)
	}
}
