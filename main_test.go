package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Thomasdezeeuw/ini"
)

func TestParseFlags(t *testing.T) {
	oldArgs := os.Args
	defer func() {
		os.Args = oldArgs
	}()

	tests := []struct {
		args       []string
		configPath string
		address    string
	}{
		{[]string{oldArgs[0]}, "./config.ini", ":8080"},
		{[]string{oldArgs[0], "path/to/config.ini"}, "path/to/config.ini", ":8080"},
		{[]string{oldArgs[0], "-p", "80"}, "./config.ini", ":80"},
		{[]string{oldArgs[0], "--port", "80"}, "./config.ini", ":80"},
		{[]string{oldArgs[0], "path/to/config.ini", "-p", "80"}, "path/to/config.ini", ":80"},
		{[]string{oldArgs[0], "path/to/config.ini", "--port", "80"}, "path/to/config.ini", ":80"},
	}

	for _, test := range tests {
		os.Args = test.args
		configPath, address := pareseFlags()

		if configPath != test.configPath {
			t.Fatalf("Expected config path to be %s, but got %s",
				test.configPath, configPath)
		}

		if address != test.address {
			t.Fatalf("Expected address to be %s, but got %s",
				test.address, address)
		}
	}
}

func TestParseConfig(t *testing.T) {
	got, err := parseConfig("./testdata/config.ini")
	if err != nil {
		t.Fatalf("Unexpected error parsing config: %s", err.Error())
	}

	expected := ini.Config{
		"": {
			"bin": "git",
		},
		"example.com": {
			"name":   "username/repo",
			"path":   "./repo",
			"secret": "my-secret",
		},
	}

	if !reflect.DeepEqual(expected, got) {
		t.Fatalf("Expected config to be %#v, but got %#v", expected, got)
	}
}

func TestGetGitPath(t *testing.T) {
	got, err := getGitPath("")
	if err != nil {
		t.Fatalf("Unexpected error: %s", err.Error())
	}

	expected, err := exec.LookPath("git")
	if err != nil {
		t.Fatalf("Unexpected error getting git path: %s", err.Error())
	}

	if expected != got {
		t.Fatalf("Expected git path to be %s, but got %s", got, expected)
	}
}

func TestCreateRepos(t *testing.T) {
	input := ini.Config{
		"": {
			"bin": "git",
		},
		"example.com": {
			"name":   "username/repo",
			"path":   "./repo",
			"secret": "my-secret",
		},
	}

	gitPath := "git"
	path, err := filepath.Abs("./")
	if err != nil {
		t.Fatalf("Unexpected error ")
	}

	got, err := createRepos(input, path+"/config.ini", gitPath)
	if err != nil {
		t.Fatalf("Unexpected error creating repos: %s", err.Error())
	}

	expected := Repos{
		"example.com": {
			Name:    "username/repo",
			Path:    filepath.Join(path, "repo"),
			Secret:  "my-secret",
			GitPath: gitPath,
		},
	}

	if !reflect.DeepEqual(expected, got) {
		t.Fatalf("Expected repos to be %#v, but got %#v", expected, got)
	}
}

func TestCreateRepoAbsolutePath(t *testing.T) {
	conf := map[string]string{
		"name":   "username/repo",
		"path":   "/repo",
		"secret": "my-secret",
	}

	gitPath := "git"

	repo, err := createRepo(conf, "./", gitPath)
	if err != nil {
		t.Fatalf("Unexpected erro creating repo: %s", err.Error())
	}

	expected := Repo{
		Name:    "username/repo",
		Path:    "/repo",
		Secret:  "my-secret",
		GitPath: gitPath,
	}

	if reflect.DeepEqual(repo, expected) {
		t.Fatalf("Expected repo to be %#v, but got %#v", repo, expected)
	}
}

func TestUpdateHandler(t *testing.T) {
	repoPath, err := filepath.Abs("./")
	if err != nil {
		t.Fatalf("Unexpected error creating an absolute path: %s", err.Error())
	}
	repoPath = filepath.Join(repoPath, "testdata", "repo")

	repos := Repos{
		"example.com": {
			Name:    "username/repo",
			Path:    repoPath,
			Secret:  "my-secret",
			GitPath: "git",
		},
	}

	h := update(repos)
	srv := httptest.NewServer(h)
	defer srv.Close()

	URL := srv.URL + path.Join(urlPrefix, repos["example.com"].Name)
	req, err := createUpdateRequest(URL, "", repos["example.com"].Secret)
	if err != nil {
		t.Fatalf("Unexpected error creating a request: %s", err.Error())
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Unexpected error executing request: %s", err.Error())
	}

	// todo: create a working repo with a working origin.
	expected := "exit status 1: fatal: No remote repository specified.  Please, specify either a URL or a\nremote name from which new revisions should be fetched.\n\n"
	err = checkBody(res, http.StatusInternalServerError, expected)
	if err != nil {
		t.Fatal(err.Error())
	}
}

func TestInvalidSignature(t *testing.T) {
	repos := Repos{
		"example.com": {
			Name:    "username/repo",
			Path:    filepath.Join("./", "git-repo"),
			Secret:  "my-secret",
			GitPath: "git",
		},
	}

	h := update(repos)
	srv := httptest.NewServer(h)
	defer srv.Close()

	URL := srv.URL + path.Join(urlPrefix, "username", "repo")
	req, err := createUpdateRequest(URL, "", "invalid")
	if err != nil {
		t.Fatalf("Unexpected error creating a request: %s", err.Error())
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Unexpected error executing request: %s", err.Error())
	}

	err = checkBody(res, http.StatusForbidden, errInvalidSignature.Error()+"\n")
	if err != nil {
		t.Fatal(err.Error())
	}
}

func createUpdateRequest(URL, body, secret string) (*http.Request, error) {
	req, err := http.NewRequest("POST", URL, strings.NewReader(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("X-Github-Event", pushEventType)
	req.Header.Set("X-Hub-Signature", createSignature(body, secret))

	return req, nil
}

func createSignature(body, secret string) string {
	c := hmac.New(sha1.New, []byte(secret))
	c.Write([]byte(body))
	q := c.Sum(nil)

	return signaturePrefix + hex.EncodeToString(q)
}

func checkBody(res *http.Response, statusCode int, body string) error {
	if got := res.StatusCode; got != statusCode {
		return fmt.Errorf("Expected status code to be %d, but got %d", statusCode, got)
	}

	gotBody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("Unexpected error reading response body: %s", err.Error())
	}
	res.Body.Close()

	if got := string(gotBody); got != body {
		return fmt.Errorf("Expected the body to be %q, but got %q", body, got)
	}

	return nil
}
