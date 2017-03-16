package sshclient

import (
	"bufio"
	"fmt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"time"
)

type Config struct {
	Server   string
	Port     string
	User     string
	Keypath  string
	Password string
	Timeout  time.Duration
}

func (c *Config) getKey() (pubkey ssh.Signer, err error) {
	buf, err := ioutil.ReadFile(c.Keypath)
	if err != nil {
		return nil, err
	}

	pubkey, err = ssh.ParsePrivateKey(buf)
	if err != nil {
		return nil, err
	}

	return pubkey, nil
}

func (c *Config) getAuthMethods() (auths []ssh.AuthMethod) {
	if len(c.Password) > 0 {
		auths = append(auths, ssh.Password(c.Password))
	}

	sshAgent, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err == nil {
		auths = append(auths, ssh.PublicKeysCallback(agent.NewClient(sshAgent).Signers))
	}

	if pkey, err := c.getKey(); err == nil {
		auths = append(auths, ssh.PublicKeys(pkey))
	}

	return
}

func (c *Config) serverAddress() string {
	return c.Server + ":" + c.Port
}

func (c *Config) connect() (conn *ssh.Client, session *ssh.Session, err error) {
	config := &ssh.ClientConfig{
		User:    c.User,
		Auth:    c.getAuthMethods(),
		Timeout: c.Timeout,
	}

	conn, err = ssh.Dial("tcp", c.serverAddress(), config)
	if err != nil {
		return nil, nil, err
	}

	session, err = conn.NewSession()
	if err != nil {
		return nil, nil, err
	}

	return
}

func (c *Config) Stream(command string) (stdOutChan chan string, stdErrChan chan string, done chan bool, err error) {
	conn, session, err := c.connect()
	if err != nil {
		return stdOutChan, stdErrChan, done, err
	}

	stdOutPipe, err := session.StdoutPipe()
	if err != nil {
		return stdOutChan, stdErrChan, done, err
	}

	stdErrPipe, err := session.StderrPipe()
	if err != nil {
		return stdOutChan, stdErrChan, done, err
	}

	err = session.Start(command)
	if err != nil {
		return stdOutChan, stdErrChan, done, err
	}

	stdOutBuffer := bufio.NewScanner(stdOutPipe)
	stdErrBuffer := bufio.NewScanner(stdErrPipe)
	stdOutChan = make(chan string)
	stdErrChan = make(chan string)
	done = make(chan bool)

	go func(stdOutBuffer *bufio.Scanner, stdErrBuffer *bufio.Scanner, stdOutChan chan string, stdErr chan string, done chan bool) {
		for stdOutBuffer.Scan() {
			stdOutChan <- stdOutBuffer.Text()
		}
		for stdErrBuffer.Scan() {
			stdErrChan <- stdErrBuffer.Text()
		}

		done <- true

		conn.Close()
		session.Close()

		close(stdOutChan)
		close(stdErrChan)
		close(done)
	}(stdOutBuffer, stdErrBuffer, stdOutChan, stdErrChan, done)

	return
}

func (c *Config) Run(command string) (stdOut string, stdErr string, err error) {
	stdOutChan, stdErrChan, done, err := c.Stream(command)
	if err != nil {
		return stdOut, stdErr, err
	}

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

	return
}

// Scp uploads sourceFile to remote machine like native scp console app.
func (c *Config) Copy(sourceFile string, etargetFile string) error {
	conn, session, err := c.connect()
	if err != nil {
		return err
	}

	targetFile := filepath.Base(etargetFile)

	src, srcErr := os.Open(sourceFile)
	if srcErr != nil {
		return srcErr
	}

	srcStat, statErr := src.Stat()
	if statErr != nil {
		return statErr
	}

	go func() {
		w, _ := session.StdinPipe()
		fmt.Fprintln(w, "C0644", srcStat.Size(), targetFile)

		if srcStat.Size() > 0 {
			io.Copy(w, src)
			fmt.Fprint(w, "\x00")
			w.Close()
		} else {
			fmt.Fprint(w, "\x00")
			w.Close()
		}
	}()

	if err := session.Run(fmt.Sprintf("scp -tr %s", etargetFile)); err != nil {
		return err
	}

	session.Close()
	conn.Close()
	return nil
}
