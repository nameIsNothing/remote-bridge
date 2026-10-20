package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSSHRecoveryOwnsImageUsesExactInstanceAndExecutable(t *testing.T) {
	root := filepath.Clean(t.TempDir())
	owned := []string{
		filepath.Join(root, "openssh", "sshd.exe"),
		filepath.Join(root, "openssh", "sshd-session.exe"),
		filepath.Join(root, "openssh", "sshd-auth.exe"),
		filepath.Join(root, "bridge-service.exe"),
	}
	for _, image := range owned {
		if !sshRecoveryOwnsImage(root, image) {
			t.Errorf("instance image should be owned: %q", image)
		}
	}
	if runtime.GOOS == "windows" {
		for _, image := range []string{
			strings.ToUpper(owned[0]),
			strings.ReplaceAll(owned[1], `\`, "/"),
		} {
			if !sshRecoveryOwnsImage(root, image) {
				t.Errorf("Windows path spelling should still identify owned image: %q", image)
			}
		}
	}

	outside := filepath.Join(filepath.Dir(root), filepath.Base(root)+"-other", "openssh", "sshd-session.exe")
	bad := []string{
		filepath.Join(filepath.Dir(root), "openssh", "sshd.exe"), // same name, outside instance
		outside, // adjacent root prefix
		filepath.Join(root, "openssh", "ssh.exe"),
		filepath.Join(root, "bridge-service.exe", "sshd.exe"),
		filepath.Join(root, "openssh", "..", "outside", "sshd-auth.exe"),
		"relative\\openssh\\sshd.exe",
		filepath.Join(root, "openssh", "sshd.exe."),
		filepath.Join(root, "openssh", "sshd-session.exe "),
		filepath.Join(root, "openssh", "sshd.exe\nextra"),
	}
	for _, image := range bad {
		if sshRecoveryOwnsImage(root, image) {
			t.Errorf("unowned image was accepted: %q", image)
		}
	}
}

func TestRecoverSSHProcessesHandlesOrphanWithoutPersistedParent(t *testing.T) {
	root := filepath.Clean(t.TempDir())
	image := filepath.Join(root, "openssh", "sshd-session.exe")
	ops := newFakeSSHRecoveryOperations([]sshRecoveryCandidate{{pid: 16496, name: "sshd-session.exe"}})
	ops.processes[16496] = []*fakeSSHRecoveryProcess{{image: image}, {image: image}}

	if err := recoverSSHProcesses(context.Background(), "ssh-test", root, ops); err != nil {
		t.Fatalf("orphan candidate recovery failed: %v", err)
	}
	if got := ops.terminateRequests(); got != 1 {
		t.Fatalf("expected one verified termination request, got %d", got)
	}
	if got := ops.candidateCalls; got != 2 {
		t.Fatalf("expected a clean rescan after recovery, got %d snapshots", got)
	}
	assertFakeHandlesClosed(t, ops)
}

func TestRecoverSSHProcessesDoesNotRequestTerminationForUnownedImage(t *testing.T) {
	root := filepath.Clean(t.TempDir())
	ops := newFakeSSHRecoveryOperations([]sshRecoveryCandidate{{pid: 41, name: "sshd.exe"}})
	ops.processes[41] = []*fakeSSHRecoveryProcess{{image: filepath.Join(root+"-neighbor", "openssh", "sshd.exe")}}

	if err := recoverSSHProcesses(context.Background(), "ssh-test", root, ops); err != nil {
		t.Fatalf("unowned process should be ignored: %v", err)
	}
	if got := ops.terminateRequests(); got != 0 {
		t.Fatalf("unowned process requested termination access %d times", got)
	}
	if got := ops.openRequests; len(got) != 1 || got[0].terminate {
		t.Fatalf("unowned process should only be opened for image query: %+v", got)
	}
	assertFakeHandlesClosed(t, ops)
}

func TestRecoverSSHProcessesRechecksImageOnTerminationHandle(t *testing.T) {
	root := filepath.Clean(t.TempDir())
	ops := newFakeSSHRecoveryOperations([]sshRecoveryCandidate{{pid: 52, name: "sshd-auth.exe"}})
	ops.processes[52] = []*fakeSSHRecoveryProcess{
		{image: filepath.Join(root, "openssh", "sshd-auth.exe")},
		{image: filepath.Join(root+"-neighbor", "openssh", "sshd-auth.exe")},
	}

	err := recoverSSHProcesses(context.Background(), "ssh-test", root, ops)
	if err == nil {
		t.Fatalf("changed image should fail closed, got %v", err)
	}
	if got := ops.allProcesses[1].terminated; got != 0 {
		t.Fatalf("changed image was terminated %d times", got)
	}
	assertFakeHandlesClosed(t, ops)
}

func TestRecoverSSHProcessesReturnsErrorsAndClosesHandles(t *testing.T) {
	root := filepath.Clean(t.TempDir())
	ownedImage := filepath.Join(root, "openssh", "sshd.exe")
	candidate := sshRecoveryCandidate{pid: 63, name: "sshd.exe"}
	tests := []struct {
		name  string
		setup func(*fakeSSHRecoveryOperations)
	}{
		{name: "snapshot", setup: func(ops *fakeSSHRecoveryOperations) { ops.candidateErr = errors.New("snapshot failed") }},
		{name: "query open", setup: func(ops *fakeSSHRecoveryOperations) { ops.openErrors[63] = []error{errors.New("query open failed")} }},
		{name: "query image", setup: func(ops *fakeSSHRecoveryOperations) {
			ops.processes[63] = []*fakeSSHRecoveryProcess{{imageErr: errors.New("query image failed")}}
		}},
		{name: "terminate open", setup: func(ops *fakeSSHRecoveryOperations) {
			ops.processes[63] = []*fakeSSHRecoveryProcess{{image: ownedImage}}
			ops.openErrors[63] = []error{nil, errors.New("terminate open failed")}
		}},
		{name: "terminate image", setup: func(ops *fakeSSHRecoveryOperations) {
			ops.processes[63] = []*fakeSSHRecoveryProcess{{image: ownedImage}, {imageErr: errors.New("terminate image failed")}}
		}},
		{name: "terminate", setup: func(ops *fakeSSHRecoveryOperations) {
			ops.processes[63] = []*fakeSSHRecoveryProcess{{image: ownedImage}, {image: ownedImage, terminateErr: errors.New("terminate failed")}}
		}},
		{name: "wait", setup: func(ops *fakeSSHRecoveryOperations) {
			ops.processes[63] = []*fakeSSHRecoveryProcess{{image: ownedImage}, {image: ownedImage, waitErr: errors.New("wait failed")}}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ops := newFakeSSHRecoveryOperations([]sshRecoveryCandidate{candidate})
			tt.setup(ops)
			if err := recoverSSHProcesses(context.Background(), "ssh-test", root, ops); err == nil {
				t.Fatal("recovery failure was hidden")
			}
			assertFakeHandlesClosed(t, ops)
		})
	}
}

func TestRecoverSSHProcessesRescansAndBoundsNewChildren(t *testing.T) {
	root := filepath.Clean(t.TempDir())
	image := filepath.Join(root, "openssh", "sshd-session.exe")
	child := sshRecoveryCandidate{pid: 74, name: "sshd-session.exe"}

	t.Run("rescan after child exits", func(t *testing.T) {
		ops := newFakeSSHRecoveryOperations([]sshRecoveryCandidate{child}, nil)
		ops.processes[74] = []*fakeSSHRecoveryProcess{{image: image}, {image: image}}
		if err := recoverSSHProcesses(context.Background(), "ssh-test", root, ops); err != nil {
			t.Fatalf("recovery failed: %v", err)
		}
		if ops.candidateCalls != 2 {
			t.Fatalf("expected empty follow-up snapshot, got %d calls", ops.candidateCalls)
		}
		assertFakeHandlesClosed(t, ops)
	})

	t.Run("fail after four nonempty passes", func(t *testing.T) {
		ops := newFakeSSHRecoveryOperations([]sshRecoveryCandidate{child})
		ops.repeatLast = true
		for i := 0; i < 4; i++ {
			ops.processes[74] = append(ops.processes[74], &fakeSSHRecoveryProcess{image: image}, &fakeSSHRecoveryProcess{image: image})
		}
		if err := recoverSSHProcesses(context.Background(), "ssh-test", root, ops); err == nil {
			t.Fatal("recovery should fail while each rescan finds a new child")
		}
		if ops.candidateCalls != 4 {
			t.Fatalf("expected four bounded passes, got %d", ops.candidateCalls)
		}
		assertFakeHandlesClosed(t, ops)
	})
}

func TestRecoverSSHProcessesCancellationPreventsTermination(t *testing.T) {
	root := filepath.Clean(t.TempDir())
	ctx, cancel := context.WithCancel(context.Background())
	image := filepath.Join(root, "openssh", "sshd.exe")
	ops := newFakeSSHRecoveryOperations([]sshRecoveryCandidate{{pid: 85, name: "sshd.exe"}})
	ops.processes[85] = []*fakeSSHRecoveryProcess{{image: image, afterImage: cancel}}

	err := recoverSSHProcesses(ctx, "ssh-test", root, ops)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
	if got := ops.terminateRequests(); got != 0 {
		t.Fatalf("canceled recovery requested termination %d times", got)
	}
	assertFakeHandlesClosed(t, ops)
}

type fakeSSHRecoveryOpen struct {
	pid       uint32
	terminate bool
}

type fakeSSHRecoveryOperations struct {
	snapshots      [][]sshRecoveryCandidate
	candidateErr   error
	candidateCalls int
	repeatLast     bool
	openRequests   []fakeSSHRecoveryOpen
	openErrors     map[uint32][]error
	openCounts     map[uint32]int
	processes      map[uint32][]*fakeSSHRecoveryProcess
	allProcesses   []*fakeSSHRecoveryProcess
}

func newFakeSSHRecoveryOperations(snapshots ...[]sshRecoveryCandidate) *fakeSSHRecoveryOperations {
	return &fakeSSHRecoveryOperations{
		snapshots:  snapshots,
		openErrors: make(map[uint32][]error),
		openCounts: make(map[uint32]int),
		processes:  make(map[uint32][]*fakeSSHRecoveryProcess),
	}
}

func (f *fakeSSHRecoveryOperations) Candidates() ([]sshRecoveryCandidate, error) {
	f.candidateCalls++
	if f.candidateErr != nil {
		return nil, f.candidateErr
	}
	index := f.candidateCalls - 1
	if index >= len(f.snapshots) {
		if !f.repeatLast || len(f.snapshots) == 0 {
			return nil, nil
		}
		index = len(f.snapshots) - 1
	}
	return append([]sshRecoveryCandidate(nil), f.snapshots[index]...), nil
}

func (f *fakeSSHRecoveryOperations) Open(pid uint32, terminate bool) (sshRecoveryProcess, error) {
	f.openRequests = append(f.openRequests, fakeSSHRecoveryOpen{pid: pid, terminate: terminate})
	index := f.openCounts[pid]
	f.openCounts[pid] = index + 1
	if failures := f.openErrors[pid]; index < len(failures) && failures[index] != nil {
		return nil, failures[index]
	}
	processes := f.processes[pid]
	if index >= len(processes) {
		return nil, os.ErrProcessDone
	}
	process := processes[index]
	f.allProcesses = append(f.allProcesses, process)
	return process, nil
}

func (f *fakeSSHRecoveryOperations) terminateRequests() int {
	count := 0
	for _, request := range f.openRequests {
		if request.terminate {
			count++
		}
	}
	return count
}

type fakeSSHRecoveryProcess struct {
	image        string
	imageErr     error
	terminateErr error
	waitErr      error
	afterImage   func()
	closed       int
	terminated   int
}

func (p *fakeSSHRecoveryProcess) Image() (string, error) {
	if p.afterImage != nil {
		p.afterImage()
	}
	return p.image, p.imageErr
}

func (p *fakeSSHRecoveryProcess) Terminate() error {
	p.terminated++
	return p.terminateErr
}

func (p *fakeSSHRecoveryProcess) Wait(context.Context) error { return p.waitErr }
func (p *fakeSSHRecoveryProcess) Close()                     { p.closed++ }

func assertFakeHandlesClosed(t *testing.T, ops *fakeSSHRecoveryOperations) {
	t.Helper()
	for index, process := range ops.allProcesses {
		if process.closed != 1 {
			t.Errorf("opened process handle %d closed %d times, want exactly once", index, process.closed)
		}
	}
}
