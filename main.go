//go:build windows

package main

import (
	"context"
	_ "embed"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"os"
	"os/signal"
	"os/user"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"github.com/apenwarr/fixconsole"
	"github.com/getlantern/systray"
	"golang.org/x/sys/windows"
)

var (
	unixSocket  = flag.String("wsl", "", "Path to Unix socket for passthrough to WSL")
	namedPipe   = flag.String("winssh", "", "Named pipe for use with Win32 OpenSSH")
	verbose     = flag.Bool("verbose", false, "Enable verbose logging")
	systrayFlag = flag.Bool("systray", false, "Enable systray integration")
	force       = flag.Bool("force", false, "Replace the Unix socket even if it is in use or is not a socket (stale sockets are always replaced)")
)

//go:embed assets/icon.ico
var icon []byte

const (
	// ssh-agent/Pageant constants
	agentMaxMessageLength = 8192
	agentCopyDataID       = 0x804e50ba

	// Requests larger than Pageant can handle are answered with a failure, but
	// beyond this size the client is not speaking the agent protocol at all
	// and is simply disconnected.
	maxDiscardLength = 256 * 1024

	// Size of sockaddr_un.sun_path
	maxUnixSocketPath = 108

	wmCopyData = 0x004A
)

var (
	user32           = windows.NewLazySystemDLL("user32.dll")
	procFindWindowW  = user32.NewProc("FindWindowW")
	procSendMessageW = user32.NewProc("SendMessageW")
)

// copyDataStruct is used to pass data in the WM_COPYDATA message.
// We directly pass a pointer to our copyDataStruct type, we need to be
// careful that it matches the Windows COPYDATASTRUCT type exactly
type copyDataStruct struct {
	dwData uintptr
	cbData uint32
	lpData *byte
}

// failureMessage is the SSH_AGENT_FAILURE response
var failureMessage = [...]byte{0, 0, 0, 1, 5}

var queryPageantMutex sync.Mutex

// pageantWindowName is both the class and the title of Pageant's hidden
// window. It is a variable so tests can stand in a fake Pageant.
var pageantWindowName = "Pageant"

// queryFunc sends a single ssh-agent request (including the 4 byte length
// prefix) to an agent and returns the response (also including the prefix).
type queryFunc func(request []byte) ([]byte, error)

// ptrFromAddr converts the address of memory that is not managed by Go into
// a pointer. The indirection through &addr keeps go vet's unsafeptr check,
// which guards against the GC moving Go objects, quiet.
func ptrFromAddr[T any](addr uintptr) *T {
	return *(**T)(unsafe.Pointer(&addr))
}

func debugf(format string, args ...any) {
	if *verbose {
		log.Printf(format, args...)
	}
}

// makeInheritSaWithSid returns security attributes for the shared file
// mapping that are owned by the current user, Pageant refuses to use a
// mapping that is not owned by the user it is running as.
func makeInheritSaWithSid() *windows.SecurityAttributes {
	sa := &windows.SecurityAttributes{InheritHandle: 1}
	sa.Length = uint32(unsafe.Sizeof(*sa))

	if u, err := user.Current(); err == nil {
		if sd, err := windows.SecurityDescriptorFromString("O:" + u.Uid); err == nil {
			sa.SecurityDescriptor = sd
		}
	}

	return sa
}

func findPageantWindow() (windows.HWND, error) {
	name, err := windows.UTF16PtrFromString(pageantWindowName)
	if err != nil {
		return 0, err
	}

	hwnd, _, _ := procFindWindowW.Call(uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(name)))
	if hwnd == 0 {
		return 0, errors.New("could not find Pageant window")
	}

	return windows.HWND(hwnd), nil
}

// pageantAccessHint explains the most common reason for Pageant rejecting a
// message: it is running as another user, or elevated when we are not, in
// which case Windows does not deliver WM_COPYDATA to it.
func pageantAccessHint(hwnd windows.HWND) string {
	const cannotInspect = "; Pageant may be running as a different user or as Administrator"

	var pid uint32
	if _, err := windows.GetWindowThreadProcessId(hwnd, &pid); err != nil || pid == 0 {
		return ""
	}

	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return cannotInspect
	}
	defer windows.CloseHandle(process)

	var token windows.Token
	if err := windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token); err != nil {
		return cannotInspect
	}
	defer token.Close()

	self := windows.GetCurrentProcessToken()
	pageantUser, err := token.GetTokenUser()
	if err != nil {
		return cannotInspect
	}
	selfUser, err := self.GetTokenUser()
	if err != nil {
		return ""
	}

	if !pageantUser.User.Sid.Equals(selfUser.User.Sid) {
		return fmt.Sprintf("; Pageant (pid %d) is running as a different user (%s)", pid, pageantUser.User.Sid)
	}
	if token.IsElevated() && !self.IsElevated() {
		return fmt.Sprintf("; Pageant (pid %d) is running as Administrator but wsl-ssh-pageant is not", pid)
	}

	return ""
}

// queryPageant is the queryFunc for Pageant (or a compatible agent such as
// gpg-agent with enable-putty-support).
func queryPageant(buf []byte) ([]byte, error) {
	if len(buf) > agentMaxMessageLength {
		return nil, errors.New("message too long")
	}

	hwnd, err := findPageantWindow()
	if err != nil {
		return nil, err
	}

	// Pageant clients typically make the mapping name unique with their thread
	// ID, but a goroutine has no stable thread. Instead we use the process ID
	// and serialise calls to queryPageant.
	queryPageantMutex.Lock()
	defer queryPageantMutex.Unlock()

	mapName := fmt.Sprintf("WSLPageantRequest%08x", windows.GetCurrentProcessId())
	mapNamePtr, err := windows.UTF16PtrFromString(mapName)
	if err != nil {
		return nil, err
	}

	fileMap, err := windows.CreateFileMapping(windows.InvalidHandle, makeInheritSaWithSid(), windows.PAGE_READWRITE, 0, agentMaxMessageLength, mapNamePtr)
	if err != nil {
		return nil, fmt.Errorf("CreateFileMapping: %w", err)
	}
	defer windows.CloseHandle(fileMap)

	addr, err := windows.MapViewOfFile(fileMap, windows.FILE_MAP_WRITE, 0, 0, 0)
	if err != nil {
		return nil, fmt.Errorf("MapViewOfFile: %w", err)
	}
	defer windows.UnmapViewOfFile(addr)

	sharedMemory := unsafe.Slice(ptrFromAddr[byte](addr), agentMaxMessageLength)
	copy(sharedMemory, buf)

	// Pageant expects the NUL terminated ANSI name of the file mapping
	mapNameZ := append([]byte(mapName), 0)
	cds := copyDataStruct{
		dwData: agentCopyDataID,
		cbData: uint32(len(mapNameZ)),
		lpData: &mapNameZ[0],
	}

	ret, _, _ := procSendMessageW.Call(uintptr(hwnd), wmCopyData, 0, uintptr(unsafe.Pointer(&cds)))
	if ret == 0 {
		return nil, errors.New("WM_COPYDATA failed" + pageantAccessHint(hwnd))
	}

	respLen := binary.BigEndian.Uint32(sharedMemory[:4])
	if respLen > agentMaxMessageLength-4 {
		return nil, errors.New("return message too long")
	}

	return append([]byte(nil), sharedMemory[:respLen+4]...), nil
}

func handleConnection(conn net.Conn, query queryFunc) {
	defer conn.Close()

	for {
		var lenBuf [4]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			if !errors.Is(err, io.EOF) {
				debugf("Read error '%s'", err)
			}
			return
		}

		// Pageant can't handle anything larger than the shared mapping, so
		// don't let a client make us buffer more than that.
		msgLen := binary.BigEndian.Uint32(lenBuf[:])
		var result []byte
		if msgLen > agentMaxMessageLength-4 {
			debugf("Request too long (%d bytes)", msgLen)
			if msgLen > maxDiscardLength {
				return
			}
			if _, err := io.CopyN(io.Discard, conn, int64(msgLen)); err != nil {
				debugf("Read error '%s'", err)
				return
			}
			result = failureMessage[:]
		} else {
			buf := make([]byte, 4+msgLen)
			copy(buf, lenBuf[:])
			if _, err := io.ReadFull(conn, buf[4:]); err != nil {
				debugf("Read error '%s'", err)
				return
			}

			var err error
			result, err = query(buf)
			if err != nil {
				// If for some reason talking to Pageant fails we fall back to
				// sending an agent error to the client
				debugf("Pageant query error '%s'", err)
				result = failureMessage[:]
			}
		}

		if _, err := conn.Write(result); err != nil {
			debugf("Write error '%s'", err)
			return
		}
	}
}

// listenLoop accepts connections until the listener fails or is closed.
func listenLoop(ctx context.Context, ln net.Listener, query queryFunc) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			// An error after cancellation is just the listener being closed
			if ctx.Err() == nil {
				log.Printf("Accept error '%s'", err)
			}
			return
		}

		debugf("New connection on %s", ln.Addr())

		go handleConnection(conn, query)
	}
}

// removeExistingSocket clears the way for a new listener at path. A socket
// that nothing is listening on any more (left behind by a crash, or by
// Windows shutting down) is removed, a live one is only removed when force
// is set, as is anything that is not a socket at all.
func removeExistingSocket(path string, force bool) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}

	if !force {
		if err != nil {
			return fmt.Errorf("could not inspect %s: %w, delete it manually or use the --force option", path, err)
		}
		if fi.Mode()&fs.ModeSocket == 0 {
			return fmt.Errorf("%s already exists and is not a socket, delete it manually or use the --force option", path)
		}

		if conn, err := net.DialTimeout("unix", path, time.Second); err == nil {
			conn.Close()
			return fmt.Errorf("socket %s is already in use, is another wsl-ssh-pageant running? Use the --force option to replace it", path)
		}
		debugf("Removing stale socket %s", path)
	}

	if err := os.Remove(path); err != nil {
		return fmt.Errorf("failed to unlink socket %s: %w", path, err)
	}

	return nil
}

func listenUnix(path string, force bool) (net.Listener, error) {
	// sockaddr_un has room for 108 bytes including the terminating NUL, past
	// that bind fails with an unhelpful "invalid argument"
	if len(path) >= maxUnixSocketPath {
		return nil, fmt.Errorf("socket path %s is too long (%d characters, the limit is %d)", path, len(path), maxUnixSocketPath-1)
	}

	if err := removeExistingSocket(path, force); err != nil {
		return nil, err
	}

	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("could not open socket %s: %w", path, err)
	}

	return ln, nil
}

func run() error {
	// Cancelled on Ctrl+C, or when a listener breaks
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	serve := func(ln net.Listener) {
		go func() {
			listenLoop(ctx, ln, queryPageant)

			// If for some reason our listener breaks, kill the program
			cancel()
		}()
	}

	if *unixSocket != "" {
		ln, err := listenUnix(*unixSocket, *force)
		if err != nil {
			return err
		}
		defer ln.Close()

		log.Printf("Listening on Unix socket: %s", *unixSocket)
		serve(ln)
	}

	if *namedPipe != "" {
		name := `\\.\pipe\` + *namedPipe
		ln, err := winio.ListenPipe(name, nil)
		if err != nil {
			return fmt.Errorf("could not open named pipe %s: %w", name, err)
		}
		defer ln.Close()

		log.Printf("Listening on named pipe: %s", name)
		serve(ln)
	}

	if *systrayFlag {
		go func() {
			<-ctx.Done()
			systray.Quit()
		}()

		// Blocks until systray.Quit is called
		systray.Run(onSystrayReady, nil)
	} else {
		<-ctx.Done()
	}

	log.Print("Exiting...")
	return nil
}

func main() {
	fixconsole.FixConsoleIfNeeded()
	flag.Parse()

	if *namedPipe == "" && *unixSocket == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	if err := run(); err != nil {
		log.Fatalf("Error: %s", err)
	}
}

func onSystrayReady() {
	systray.SetTitle("WSL-SSH-Pageant")
	systray.SetTooltip("WSL-SSH-Pageant")
	systray.SetIcon(icon)

	quit := systray.AddMenuItem("Quit", "Quits this app")

	go func() {
		<-quit.ClickedCh
		systray.Quit()
	}()
}
