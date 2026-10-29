package updater

import (
	"archive/tar"
	"bufio"
	"bytes"
	"cmp"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

// The .deb ar archive contains the file system payload in a member
// named `data.tar` suffixed with the compression used, if any.
const dataTARPrefix = "data.tar"

var (
	errARHeader    = errors.New("invalid ar archive header")
	errTARNotFound = errors.New("tar archive not found in deb archive")
	errTARNoData   = errors.New("tar archive has no data")
	// errStopIteration is returned by an [eachARAMember] callback to stop
	// the iteration without erroring out.
	errStopIteration = errors.New("stop ar archive members iteration")
)

// extractFilesFromDeb streams through a PureVPN .deb file (an ar archive)
// and returns the content of the given paths found in the Electron
// application archive it contains, keyed by path. Paths not found are
// absent from the returned map.
// Only the requested files are kept in memory, the archives being streamed
// through (the deb file is about 100 MB and unpacks to about 1 GB).
func extractFilesFromDeb(debContent io.Reader, paths ...string) (files map[string][]byte, err error) {
	// Path of the Electron application archive inside the data.tar member.
	const appASARPath = "opt/PureVPN/resources/app.asar"

	var memberNames []string
	err = eachARAMember(bufio.NewReader(debContent),
		func(name string, size int64, content io.Reader) error {
			memberNames = append(memberNames, name)
			switch {
			case !strings.HasPrefix(name, dataTARPrefix):
				return nil
			case size == 0:
				return errTARNoData
			}
			err := withDecompressedTAR(name, content,
				func(tarContent io.Reader) error {
					return withTARFile(tarContent, appASARPath,
						func(appASAR io.Reader, asarSize int64) (err error) {
							files, err = extractFilesFromASAR(appASAR, asarSize, paths...)
							return err
						})
				})
			if err != nil {
				return err
			}
			// The data.tar member is unique, no need to read further.
			return errStopIteration
		})
	if err != nil {
		return nil, err
	}
	if files == nil {
		return nil, fmt.Errorf("%w: members found are %s",
			errTARNotFound, strings.Join(memberNames, ", "))
	}
	return files, nil
}

// eachARAMember iterates over the members of an ar archive,
// calling fn with the member name, its size in bytes and a reader
// restricted to its content.
// Any content not read by fn is skipped before the next member is read.
// Returning [errStopIteration] from fn stops the iteration and
// eachARAMember returns a nil error.
func eachARAMember(reader *bufio.Reader, fn func(name string, size int64, content io.Reader) error) error {
	const (
		globalHeader = "!<arch>\n"
		headerLength = 60
		nameEnd      = 16
		sizeStart    = 48
		sizeEnd      = 58
	)

	global := make([]byte, len(globalHeader))
	if _, err := io.ReadFull(reader, global); err != nil {
		return fmt.Errorf("reading ar archive header: %w", err)
	}
	if string(global) != globalHeader {
		return errARHeader
	}

	for {
		header := make([]byte, headerLength)
		read, err := io.ReadFull(reader, header)
		if err != nil {
			// Tolerate a trailing padding of the ar archive.
			if isEOF(err) && strings.TrimSpace(string(header[:read])) == "" {
				return nil
			}
			return fmt.Errorf("reading ar member header: %w", err)
		}

		name := strings.TrimSuffix(strings.TrimSpace(string(header[:nameEnd])), "/")
		sizeString := strings.TrimSpace(string(header[sizeStart:sizeEnd]))
		size, err := strconv.ParseInt(sizeString, 10, 64)
		if err != nil {
			return fmt.Errorf("parsing size %q of ar member %q: %w", sizeString, name, err)
		}
		if size < 0 {
			return fmt.Errorf("negative size %d for ar member %q", size, name)
		}

		content := io.LimitReader(reader, size)
		if err := fn(name, size, content); err != nil {
			if errors.Is(err, errStopIteration) {
				return nil
			}
			return err
		}

		if _, err := io.Copy(io.Discard, content); err != nil {
			return fmt.Errorf("skipping ar member %q: %w", name, err)
		}
		if size%2 == 1 {
			// Members are aligned on 2 bytes.
			if _, err := reader.Discard(1); err != nil {
				return fmt.Errorf("skipping padding of ar member %q: %w", name, err)
			}
		}
	}
}

// withDecompressedTAR decompresses a data.tar member based on its file name
// suffix (`.xz`, `.gz`, `.zst` or none) and calls fn with the tar content.
func withDecompressedTAR(fileName string, content io.Reader, fn func(tarContent io.Reader) error) error {
	switch suffix := strings.ToLower(strings.TrimPrefix(fileName, dataTARPrefix)); suffix {
	case ".xz":
		reader, err := xz.NewReader(content)
		if err != nil {
			return fmt.Errorf("creating xz reader: %w", err)
		}
		return fn(reader)
	case ".gz":
		reader, err := gzip.NewReader(content)
		if err != nil {
			return fmt.Errorf("creating gzip reader: %w", err)
		}
		defer reader.Close()
		return fn(reader)
	case ".zst":
		decoder, err := zstd.NewReader(content)
		if err != nil {
			return fmt.Errorf("creating zstd reader: %w", err)
		}
		defer decoder.Close()
		return fn(decoder)
	default:
		return fn(content)
	}
}

// withTARFile looks up a file in a tar archive and calls fn with its content
// and its size in bytes.
// The file name is tolerated to be prefixed with `./`.
// The content reader must not be used after fn returns.
func withTARFile(tarContent io.Reader, filePath string, fn func(content io.Reader, size int64) error) error {
	tarReader := tar.NewReader(tarContent)
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("reading tar archive: %w", err)
		}
		if strings.TrimPrefix(header.Name, "./") != filePath {
			continue
		}
		if err := fn(tarReader, header.Size); err != nil {
			return err
		}
		return nil
	}
	return fmt.Errorf("file %q not found in tar archive", filePath)
}

// asarNumber is a byte count or an offset in bytes.
// The asar tooling writes the offset as a JSON string and the size
// as a JSON number, this type accepts both forms.
type asarNumber uint64

func (n *asarNumber) UnmarshalJSON(data []byte) (err error) {
	// Limited to 63 bits so the value always fits in an int64.
	value, err := strconv.ParseUint(string(bytes.Trim(data, `"`)), 10, 63)
	if err != nil {
		return fmt.Errorf("decoding asar number: %w", err)
	}
	*n = asarNumber(value)
	return nil
}

type asarNode struct {
	Files  map[string]*asarNode `json:"files,omitempty"`
	Offset asarNumber           `json:"offset,omitempty"`
	Size   asarNumber           `json:"size,omitempty"`
}

// extractFilesFromASAR reads an Electron asar archive of the given size
// in bytes from the given reader and returns the content of the paths
// found in it, keyed by path.
// The archive is only read up to the last requested file.
func extractFilesFromASAR(appASAR io.Reader, asarSize int64, paths ...string) (
	files map[string][]byte, err error,
) {
	const (
		// The first 4 uint32 values of an asar archive, the last one being
		// the length in bytes of the JSON header string following them.
		prefixLength = 16
		// The PureVPN 2.9.0 archive is 320 MiB with a 12 MiB JSON header.
		// Both are capped with margin to bound the memory and the reading
		// done on a corrupted or malicious archive.
		maxASARSize         = 1024 * 1024 * 1024
		maxJSONHeaderLength = 32 * 1024 * 1024
		// Only JavaScript files of a few hundred KBs are extracted, so any
		// bigger size means a corrupted or malicious archive.
		maxFileSize = 8 * 1024 * 1024
	)

	if asarSize > maxASARSize {
		return nil, fmt.Errorf("asar archive size %d exceeds maximum of %d",
			asarSize, maxASARSize)
	}

	prefix := make([]byte, prefixLength)
	if _, err := io.ReadFull(appASAR, prefix); err != nil {
		return nil, fmt.Errorf("reading asar archive prefix: %w", err)
	}
	jsonHeaderLength := int64(binary.LittleEndian.Uint32(prefix[prefixLength-4:]))
	switch {
	case jsonHeaderLength == 0:
		return nil, fmt.Errorf("invalid asar header length %d", jsonHeaderLength)
	case jsonHeaderLength > maxJSONHeaderLength:
		return nil, fmt.Errorf("asar header length %d exceeds maximum of %d",
			jsonHeaderLength, maxJSONHeaderLength)
	case jsonHeaderLength > asarSize-prefixLength:
		return nil, fmt.Errorf("asar header length %d exceeds archive size %d",
			jsonHeaderLength, asarSize)
	}
	// Non negative given the header length checks above.
	dataSize := asarNumber(asarSize - prefixLength - jsonHeaderLength) //nolint:gosec

	headerContent := make([]byte, jsonHeaderLength)
	if _, err := io.ReadFull(appASAR, headerContent); err != nil {
		return nil, fmt.Errorf("reading asar archive header: %w", err)
	}

	var rootNode asarNode
	if err := json.Unmarshal(headerContent, &rootNode); err != nil {
		return nil, fmt.Errorf("json decoding asar header: %w", err)
	}

	// Reading the files in offset order, the archive only being readable
	// forward when coming from a compressed stream.
	type fileTarget struct {
		path   string
		offset asarNumber
		size   asarNumber
	}
	targets := make([]fileTarget, 0, len(paths))
	for _, path := range paths {
		node, err := asarNodeAt(rootNode.Files, path)
		if err != nil {
			continue
		}
		switch {
		case node.Size == 0:
			return nil, fmt.Errorf("asar file %q has no data", path)
		case node.Size > maxFileSize:
			return nil, fmt.Errorf("asar file %q has size %d greater than maximum of %d",
				path, node.Size, maxFileSize)
		case node.Offset+node.Size > dataSize:
			return nil, fmt.Errorf("asar file %q ends at offset %d beyond the archive data size %d",
				path, node.Offset+node.Size, dataSize)
		}
		targets = append(targets, fileTarget{path: path, offset: node.Offset, size: node.Size})
	}
	slices.SortFunc(targets, func(a, b fileTarget) int {
		return cmp.Compare(a.offset, b.offset)
	})

	files = make(map[string][]byte, len(targets))
	// Offset in the files data area, which starts right after the JSON header.
	var position asarNumber
	for _, target := range targets {
		if target.offset < position {
			return nil, fmt.Errorf("asar file %q overlaps a previously read file", target.path)
		}
		toSkip := target.offset - position
		if toSkip > 0 {
			// The offset is decoded with a 63 bits maximum, it fits in an int64.
			if _, err := io.CopyN(io.Discard, appASAR, int64(toSkip)); err != nil { //nolint:gosec
				return nil, fmt.Errorf("skipping to asar file %q: %w", target.path, err)
			}
		}
		content := make([]byte, target.size)
		if _, err := io.ReadFull(appASAR, content); err != nil {
			return nil, fmt.Errorf("reading asar file %q: %w", target.path, err)
		}
		files[target.path] = content
		position = target.offset + target.size
	}

	return files, nil
}

// asarNodeAt returns the asar node at the given slash separated path,
// or an error mentioning the first segment not found.
func asarNodeAt(files map[string]*asarNode, path string) (node *asarNode, err error) {
	segments := strings.Split(path, "/")
	for i, segment := range segments {
		var ok bool
		node, ok = files[segment]
		if !ok {
			return nil, fmt.Errorf("asar archive has no segment %q in path %q", segment, path)
		}
		if i == len(segments)-1 {
			return node, nil
		}
		files = node.Files
	}
	return nil, fmt.Errorf("asar archive has no file at path %q", path)
}

func isEOF(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}
