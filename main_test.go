//go:build windows

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// message builds an ssh-agent message with its length prefix.
func message(payload ...byte) []byte {
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(payload))), payload...)
}

// roundTrip writes a request and reads back a single framed response.
func roundTrip(t *testing.T, conn net.Conn, request []byte) []byte {
	t.Helper()

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(request); err != nil {
		t.Fatalf("write: %v", err)
	}

	var lenBuf [4]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		t.Fatalf("read length: %v", err)
	}
	payload := make([]byte, binary.BigEndian.Uint32(lenBuf[:]))
	if _, err := io.ReadFull(conn, payload); err != nil {
		t.Fatalf("read payload: %v", err)
	}

	return append(lenBuf[:], payload...)
}

// echoAgent answers every request with the request itself.
func echoAgent(request []byte) ([]byte, error) {
	return bytes.Clone(request), nil
}

// startHandler runs handleConnection on one end of a TCP connection and
// returns the client end.
func startHandler(t *testing.T, query queryFunc) net.Conn {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		handleConnection(conn, query)
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		client.Close()
		<-done
	})

	return client
}

func TestHandleConnection(t *testing.T) {
	t.Run("several requests on one connection", func(t *testing.T) {
		conn := startHandler(t, echoAgent)

		for _, request := range [][]byte{message(11), message(), message(13, 1, 2, 3)} {
			if got := roundTrip(t, conn, request); !bytes.Equal(got, request) {
				t.Errorf("got % x, want % x", got, request)
			}
		}
	})

	t.Run("request split across writes", func(t *testing.T) {
		conn := startHandler(t, echoAgent)

		request := message(11, 1, 2, 3)
		if _, err := conn.Write(request[:2]); err != nil {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
		if got := roundTrip(t, conn, request[2:]); !bytes.Equal(got, request) {
			t.Errorf("got % x, want % x", got, request)
		}
	})

	t.Run("largest request", func(t *testing.T) {
		conn := startHandler(t, echoAgent)

		request := message(make([]byte, agentMaxMessageLength-4)...)
		if got := roundTrip(t, conn, request); !bytes.Equal(got, request) {
			t.Errorf("got %d bytes, want the %d byte request echoed", len(got), len(request))
		}
	})

	t.Run("agent error becomes a failure response", func(t *testing.T) {
		conn := startHandler(t, func([]byte) ([]byte, error) {
			return nil, errors.New("no agent")
		})

		for range 2 {
			if got := roundTrip(t, conn, message(11)); !bytes.Equal(got, failureMessage[:]) {
				t.Errorf("got % x, want % x", got, failureMessage)
			}
		}
	})

	t.Run("oversized request fails without reaching the agent", func(t *testing.T) {
		conn := startHandler(t, func([]byte) ([]byte, error) {
			t.Error("agent was queried")
			return nil, errors.New("unexpected")
		})

		request := message(make([]byte, agentMaxMessageLength-3)...)
		if got := roundTrip(t, conn, request); !bytes.Equal(got, failureMessage[:]) {
			t.Errorf("got % x, want % x", got, failureMessage)
		}
	})

	t.Run("connection stays usable after an oversized request", func(t *testing.T) {
		conn := startHandler(t, echoAgent)

		roundTrip(t, conn, message(make([]byte, 2*agentMaxMessageLength)...))
		request := message(11)
		if got := roundTrip(t, conn, request); !bytes.Equal(got, request) {
			t.Errorf("got % x, want % x", got, request)
		}
	})

	t.Run("garbage length disconnects the client", func(t *testing.T) {
		conn := startHandler(t, echoAgent)

		// What a client that is not speaking the agent protocol looks like,
		// "GET " is a 1.2GB length prefix.
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write([]byte("GET / HTTP/1.1\r\n")); err != nil {
			t.Fatal(err)
		}
		if n, err := conn.Read(make([]byte, 16)); err == nil {
			t.Errorf("read %d bytes, want the connection closed", n)
		} else if errors.Is(err, os.ErrDeadlineExceeded) {
			t.Error("connection was left open")
		}
	})
}

// Win32 plumbing for the fake Pageant window

var (
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procRegisterClassExW = user32.NewProc("RegisterClassExW")
	procUnregisterClassW = user32.NewProc("UnregisterClassW")
	procCreateWindowExW  = user32.NewProc("CreateWindowExW")
	procDefWindowProcW   = user32.NewProc("DefWindowProcW")
	procGetMessageW      = user32.NewProc("GetMessageW")
	procDispatchMessageW = user32.NewProc("DispatchMessageW")
	procPostMessageW     = user32.NewProc("PostMessageW")
	procPostQuitMessage  = user32.NewProc("PostQuitMessage")
	procOpenFileMappingA = kernel32.NewProc("OpenFileMappingA")
)

const (
	wmDestroy = 0x0002
	wmClose   = 0x0010
)

type wndClassEx struct {
	size       uint32
	style      uint32
	wndProc    uintptr
	clsExtra   int32
	wndExtra   int32
	instance   windows.Handle
	icon       windows.Handle
	cursor     windows.Handle
	background windows.Handle
	menuName   *uint16
	className  *uint16
	iconSm     windows.Handle
}

type winMsg struct {
	hwnd    windows.HWND
	message uint32
	wParam  uintptr
	lParam  uintptr
	time    uint32
	pt      struct{ x, y int32 }
	private uint32
}

// fakePageantSeq keeps window class names unique within the test process.
var fakePageantSeq struct {
	sync.Mutex
	n int
}

// startFakePageant creates a hidden window that speaks Pageant's WM_COPYDATA
// protocol, answering requests with agent, and points queryPageant at it. A
// nil agent makes the window reject every message.
func startFakePageant(t *testing.T, agent queryFunc) {
	t.Helper()

	fakePageantSeq.Lock()
	fakePageantSeq.n++
	name := fmt.Sprintf("FakePageant-%d-%d", os.Getpid(), fakePageantSeq.n)
	fakePageantSeq.Unlock()

	old := pageantWindowName
	pageantWindowName = name
	t.Cleanup(func() { pageantWindowName = old })

	serve := func(cds *copyDataStruct) error {
		if cds.dwData != agentCopyDataID {
			return fmt.Errorf("dwData is %#x", cds.dwData)
		}
		mapName := unsafe.Slice(cds.lpData, cds.cbData)
		if len(mapName) == 0 || mapName[len(mapName)-1] != 0 {
			return errors.New("mapping name is not NUL terminated")
		}

		fileMap, _, err := procOpenFileMappingA.Call(windows.FILE_MAP_WRITE, 0, uintptr(unsafe.Pointer(cds.lpData)))
		if fileMap == 0 {
			return fmt.Errorf("OpenFileMapping %q: %w", mapName[:len(mapName)-1], err)
		}
		defer windows.CloseHandle(windows.Handle(fileMap))

		addr, err := windows.MapViewOfFile(windows.Handle(fileMap), windows.FILE_MAP_WRITE, 0, 0, 0)
		if err != nil {
			return fmt.Errorf("MapViewOfFile: %w", err)
		}
		defer windows.UnmapViewOfFile(addr)

		shared := unsafe.Slice(ptrFromAddr[byte](addr), agentMaxMessageLength)
		requestLen := binary.BigEndian.Uint32(shared[:4])
		if requestLen > agentMaxMessageLength-4 {
			return fmt.Errorf("request length is %d", requestLen)
		}

		response, err := agent(bytes.Clone(shared[:4+requestLen]))
		if err != nil {
			return err
		}
		copy(shared, response)
		return nil
	}

	wndProc := windows.NewCallback(func(hwnd windows.HWND, msg uint32, wParam, lParam uintptr) uintptr {
		switch msg {
		case wmCopyData:
			if agent == nil {
				return 0
			}
			if err := serve(ptrFromAddr[copyDataStruct](lParam)); err != nil {
				t.Errorf("fake Pageant: %v", err)
				return 0
			}
			return 1
		case wmDestroy:
			procPostQuitMessage.Call(0)
			return 0
		}
		ret, _, _ := procDefWindowProcW.Call(uintptr(hwnd), uintptr(msg), wParam, lParam)
		return ret
	})

	ready := make(chan windows.HWND)
	done := make(chan struct{})
	go func() {
		defer close(done)

		// A window belongs to the thread that created it, which must also
		// pump its messages
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		namePtr, _ := windows.UTF16PtrFromString(name)
		class := wndClassEx{wndProc: wndProc, className: namePtr}
		class.size = uint32(unsafe.Sizeof(class))
		if atom, _, err := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&class))); atom == 0 {
			t.Errorf("RegisterClassEx: %v", err)
			close(ready)
			return
		}
		defer procUnregisterClassW.Call(uintptr(unsafe.Pointer(namePtr)), 0)

		hwnd, _, err := procCreateWindowExW.Call(0, uintptr(unsafe.Pointer(namePtr)), uintptr(unsafe.Pointer(namePtr)), 0, 0, 0, 0, 0, 0, 0, 0, 0)
		if hwnd == 0 {
			t.Errorf("CreateWindowEx: %v", err)
			close(ready)
			return
		}
		ready <- windows.HWND(hwnd)

		var msg winMsg
		for {
			ret, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
			if int32(ret) <= 0 {
				return
			}
			procDispatchMessageW.Call(uintptr(unsafe.Pointer(&msg)))
		}
	}()

	hwnd, ok := <-ready
	if !ok {
		t.FailNow()
	}
	t.Cleanup(func() {
		procPostMessageW.Call(uintptr(hwnd), wmClose, 0, 0)
		<-done
	})
}

func TestQueryPageant(t *testing.T) {
	t.Run("round trip", func(t *testing.T) {
		response := message(12, 0, 0, 0, 0)
		var got []byte
		startFakePageant(t, func(request []byte) ([]byte, error) {
			got = request
			return response, nil
		})

		request := message(11)
		result, err := queryPageant(request)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, request) {
			t.Errorf("Pageant received % x, want % x", got, request)
		}
		if !bytes.Equal(result, response) {
			t.Errorf("got % x, want % x", result, response)
		}
	})

	t.Run("largest message", func(t *testing.T) {
		startFakePageant(t, echoAgent)

		request := message(make([]byte, agentMaxMessageLength-4)...)
		result, err := queryPageant(request)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(result, request) {
			t.Errorf("got %d bytes, want the %d byte request echoed", len(result), len(request))
		}
	})

	t.Run("concurrent queries are serialised", func(t *testing.T) {
		startFakePageant(t, echoAgent)

		var wg sync.WaitGroup
		for i := range 16 {
			wg.Go(func() {
				request := message(11, byte(i))
				result, err := queryPageant(request)
				if err != nil {
					t.Errorf("query %d: %v", i, err)
				} else if !bytes.Equal(result, request) {
					t.Errorf("query %d: got % x, want % x", i, result, request)
				}
			})
		}
		wg.Wait()
	})

	t.Run("request too long", func(t *testing.T) {
		startFakePageant(t, func([]byte) ([]byte, error) {
			t.Error("Pageant was queried")
			return nil, errors.New("unexpected")
		})

		if _, err := queryPageant(make([]byte, agentMaxMessageLength+1)); err == nil {
			t.Error("expected an error")
		}
	})

	t.Run("response length out of range", func(t *testing.T) {
		for _, length := range []uint32{agentMaxMessageLength - 3, 0xffffffff} {
			startFakePageant(t, func([]byte) ([]byte, error) {
				return binary.BigEndian.AppendUint32(nil, length), nil
			})

			if result, err := queryPageant(message(11)); err == nil {
				t.Errorf("length %#x: got a %d byte result, want an error", length, len(result))
			}
		}
	})

	t.Run("Pageant rejects the message", func(t *testing.T) {
		startFakePageant(t, nil)

		_, err := queryPageant(message(11))
		if err == nil {
			t.Fatal("expected an error")
		}
		// The fake runs as us, so there must be no hint about another user
		if err.Error() != "WM_COPYDATA failed" {
			t.Errorf("got %q", err)
		}
	})

	t.Run("Pageant not running", func(t *testing.T) {
		old := pageantWindowName
		pageantWindowName = fmt.Sprintf("NoSuchPageant-%d", os.Getpid())
		defer func() { pageantWindowName = old }()

		if _, err := queryPageant(message(11)); err == nil {
			t.Error("expected an error")
		}
	})
}

// socketPath returns a path for a socket in a fresh temporary directory.
// t.TempDir includes the test name, which easily pushes the path past the
// length limit for Unix sockets.
func socketPath(t *testing.T) string {
	t.Helper()

	dir, err := os.MkdirTemp("", "wsp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	return filepath.Join(dir, "agent.sock")
}

// staleSocket leaves behind a socket file that nothing is listening on, as a
// crash would.
func staleSocket(t *testing.T, path string) {
	t.Helper()

	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	ln.Close()

	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("stale socket was not left behind: %v", err)
	}
}

func TestListenUnix(t *testing.T) {
	// Checks that the listener at path is serving connections
	check := func(t *testing.T, ln net.Listener, path string) {
		t.Helper()

		go listenLoop(context.Background(), ln, echoAgent)
		conn, err := net.Dial("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()

		request := message(11)
		if got := roundTrip(t, conn, request); !bytes.Equal(got, request) {
			t.Errorf("got % x, want % x", got, request)
		}
	}

	t.Run("new socket is removed on close", func(t *testing.T) {
		path := socketPath(t)

		ln, err := listenUnix(path, false)
		if err != nil {
			t.Fatal(err)
		}
		check(t, ln, path)

		ln.Close()
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("socket still exists after close (Lstat error: %v)", err)
		}
	})

	t.Run("stale socket is replaced", func(t *testing.T) {
		path := socketPath(t)
		staleSocket(t, path)

		ln, err := listenUnix(path, false)
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		check(t, ln, path)
	})

	t.Run("live socket is left alone", func(t *testing.T) {
		path := socketPath(t)

		live, err := listenUnix(path, false)
		if err != nil {
			t.Fatal(err)
		}
		defer live.Close()

		if ln, err := listenUnix(path, false); err == nil {
			ln.Close()
			t.Fatal("second listener took over a socket that is in use")
		} else if !strings.Contains(err.Error(), "already in use") {
			t.Errorf("unexpected error: %v", err)
		}
		check(t, live, path)
	})

	t.Run("live socket is replaced when forced", func(t *testing.T) {
		path := socketPath(t)

		live, err := listenUnix(path, false)
		if err != nil {
			t.Fatal(err)
		}
		defer live.Close()

		ln, err := listenUnix(path, true)
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		check(t, ln, path)
	})

	t.Run("path too long", func(t *testing.T) {
		path := filepath.Join(filepath.Dir(socketPath(t)), strings.Repeat("a", maxUnixSocketPath)+".sock")

		if ln, err := listenUnix(path, false); err == nil {
			ln.Close()
			t.Error("expected an error")
		} else if !strings.Contains(err.Error(), "too long") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("regular file is left alone", func(t *testing.T) {
		path := socketPath(t)
		if err := os.WriteFile(path, []byte("precious"), 0o600); err != nil {
			t.Fatal(err)
		}

		if ln, err := listenUnix(path, false); err == nil {
			ln.Close()
			t.Error("listener replaced a regular file")
		}
		if data, err := os.ReadFile(path); err != nil || string(data) != "precious" {
			t.Errorf("file was modified: %q, %v", data, err)
		}
	})

	t.Run("regular file is replaced when forced", func(t *testing.T) {
		path := socketPath(t)
		if err := os.WriteFile(path, []byte("junk"), 0o600); err != nil {
			t.Fatal(err)
		}

		ln, err := listenUnix(path, true)
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		check(t, ln, path)
	})
}

// TestEndToEnd drives a client through each kind of listener all the way to
// a fake Pageant window.
func TestEndToEnd(t *testing.T) {
	// SSH_AGENTC_REQUEST_IDENTITIES answered with SSH_AGENT_IDENTITIES_ANSWER
	request := message(11)
	response := message(12, 0, 0, 0, 0)
	startFakePageant(t, func(got []byte) ([]byte, error) {
		if !bytes.Equal(got, request) {
			return nil, fmt.Errorf("received % x, want % x", got, request)
		}
		return response, nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	t.Run("unix socket", func(t *testing.T) {
		path := socketPath(t)
		ln, err := listenUnix(path, false)
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		go listenLoop(ctx, ln, queryPageant)

		conn, err := net.Dial("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()

		for range 3 {
			if got := roundTrip(t, conn, request); !bytes.Equal(got, response) {
				t.Errorf("got % x, want % x", got, response)
			}
		}
	})

	t.Run("named pipe", func(t *testing.T) {
		name := fmt.Sprintf(`\\.\pipe\wsl-ssh-pageant-test-%d`, os.Getpid())
		ln, err := winio.ListenPipe(name, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		go listenLoop(ctx, ln, queryPageant)

		conn, err := winio.DialPipeContext(ctx, name)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()

		for range 3 {
			if got := roundTrip(t, conn, request); !bytes.Equal(got, response) {
				t.Errorf("got % x, want % x", got, response)
			}
		}
	})
}
