package main

import (
	"bytes"
	"errors"
	"os/exec"
	"sync"
)

type Repos map[string]*Repo

func (r Repos) FindRepo(name string) *Repo {
	for _, repo := range r {
		if repo.Name == name {
			return repo
		}
	}
	return nil
}

type Repo struct {
	Name    string     // Name of the repo on GitHub, so Thomasdezeeuw/gitup.
	Path    string     // Full path to git repo.
	Secret  string     // Optional secrect from GitHub.
	GitPath string     // Full path to the git command.
	mu      sync.Mutex // Protects the git update command.
}

// todo: add a custom command and run it.
func (r *Repo) Update() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	var buf bytes.Buffer
	cmd := exec.Command(r.GitPath, "pull", "--force")
	cmd.Stdout = &buf
	cmd.Stderr = &buf

	err := cmd.Run()
	if err == nil {
		return nil
	}
	return errors.New(err.Error() + ": " + buf.String())
}
