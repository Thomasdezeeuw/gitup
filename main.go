package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/Thomasdezeeuw/ini"
)

const (
	urlPrefix       = "/update"
	eventTypeHeader = "X-GitHub-Event"
	signatureHeader = "X-Hub-Signature"
	signaturePrefix = "sha1="
	pushEventType   = "push"

	okBody = "OK"
)

var errInvalidSignature = errors.New("invalid signature header")

func main() {
	// todo: make port configurable.
	// todo: add flag to overwrite.
	configPath := "./config.ini"
	address := ":8080"

	conf, err := parseConfig(configPath)
	if err != nil {
		// todo: check if the error makes sense...
		exit(err)
	}

	gitPath, err := getGitPath(conf[ini.Global]["bin"])
	if err != nil {
		// todo: check if the error makes sense...
		exit(err)
	}

	repos, err := createRepos(conf, configPath, gitPath)
	if err != nil {
		// todo: check if the error makes sense...
		exit(err)
	}

	h := update(repos)
	http.ListenAndServe(address, h)
}

func exit(err error) {
	os.Stderr.WriteString(err.Error())
	os.Exit(1)
}

func parseConfig(path string) (ini.Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return ini.Config{}, err
	}
	defer f.Close()

	return ini.Parse(f)
}

func getGitPath(gitCommand string) (string, error) {
	if gitCommand == "" {
		gitCommand = "git"
	}

	return exec.LookPath(gitCommand)
}

func createRepos(conf ini.Config, path, gitPath string) (Repos, error) {
	dir := filepath.Dir(path)
	repos := Repos{}

	for name, cnf := range conf {
		if name == ini.Global {
			continue
		}

		repo, err := createRepo(cnf, dir, gitPath)
		if err != nil {
			return Repos{}, err
		}

		repos[name] = repo
	}

	return repos, nil
}

func createRepo(conf map[string]string, dir, gitPath string) (*Repo, error) {
	path := filepath.Join(dir, conf["path"])
	path, err := filepath.Abs(path)
	if err != nil {
		return &Repo{}, err
	}

	repo := Repo{
		Name:    conf["name"],
		Path:    path,
		Secret:  conf["secret"],
		GitPath: gitPath,
	}

	return &repo, nil
}

func update(repos Repos) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		URL := strings.TrimSuffix(r.URL.String(), "/")

		// Most be a post request to update/:username/:repo.
		if r.Method != "POST" ||
			!strings.HasPrefix(URL, urlPrefix) || strings.Count(URL, "/") != 3 {
			http.NotFound(w, r)
			return
		}

		repoName := strings.TrimPrefix(URL, urlPrefix+"/")
		repo := repos.FindRepo(repoName)
		if repo == nil {
			http.NotFound(w, r)
			return
		}

		// Ignore events other then push and ping.
		if eventType := r.Header.Get(eventTypeHeader); eventType != pushEventType {
			w.Write([]byte(okBody))
			return
		}

		signature := r.Header.Get(signatureHeader)
		if !isValidSignature(signature, repo.Secret, r.Body) {
			http.Error(w, errInvalidSignature.Error(), http.StatusForbidden)
			return
		}

		if err := repo.Update(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Write([]byte(okBody))
	})
}

func isValidSignature(signature, secret string, r io.Reader) bool {
	actual, err := decodeSignatureHeader(signature)
	if err != nil {
		return false
	}

	mac := hmac.New(sha1.New, []byte(secret))
	io.Copy(mac, r)
	expected := mac.Sum(nil)

	return hmac.Equal(expected, actual)
}

func decodeSignatureHeader(signature string) ([]byte, error) {
	if !strings.HasPrefix(signature, signaturePrefix) {
		return []byte{}, errInvalidSignature
	}
	signature = signature[len(signaturePrefix):]

	var actual = make([]byte, 50)
	n, err := hex.Decode(actual, []byte(signature))
	if err != nil {
		return []byte{}, errInvalidSignature
	}
	actual = actual[:n]

	return actual, nil
}
