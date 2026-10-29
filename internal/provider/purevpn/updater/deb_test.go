package updater

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ulikunitz/xz"
)

func Test_extractFilesFromDeb(t *testing.T) {
	t.Parallel()

	const (
		firstPath  = "node_modules/atom-sdk/lib/offline-data/local-data.js"
		secondPath = "node_modules/atom-sdk/node_modules/utils/lib/constants/end-points.js"
	)
	firstContent := []byte(`module.exports={body:{reseller_id:1}}`)
	secondContent := []byte(`(0,_defineProperty2["default"])(S3, "BASE_URL_BPC", "https://example.com");`)
	asarContent := newASARArchive(t, map[string][]byte{
		firstPath:                    firstContent,
		secondPath:                   secondContent,
		"package.json":               []byte(`{"name":"purevpn"}`),
		"node_modules/other/file.js": []byte(`// not requested`),
	})

	testCases := map[string]struct {
		debContent []byte
		paths      []string
		files      map[string][]byte
		errMessage string
	}{
		"gzip tar archive": {
			debContent: newDebArchive(t, asarContent, ".gz"),
			paths:      []string{firstPath, secondPath},
			files: map[string][]byte{
				firstPath:  firstContent,
				secondPath: secondContent,
			},
		},
		"xz tar archive": {
			debContent: newDebArchive(t, asarContent, ".xz"),
			paths:      []string{firstPath},
			files:      map[string][]byte{firstPath: firstContent},
		},
		"uncompressed tar archive": {
			debContent: newDebArchive(t, asarContent, ""),
			paths:      []string{secondPath},
			files:      map[string][]byte{secondPath: secondContent},
		},
		"path not in asar archive": {
			debContent: newDebArchive(t, asarContent, ".gz"),
			paths:      []string{"node_modules/atom-sdk/missing.js"},
			files:      map[string][]byte{},
		},
		"no tar archive member": {
			debContent: newARArchive(t,
				arTestMember{name: "debian-binary", content: []byte("2.0\n")},
				arTestMember{name: "control.tar.gz/", content: []byte("not empty")},
			),
			paths:      []string{firstPath},
			errMessage: "tar archive not found in deb archive: members found are debian-binary, control.tar.gz",
		},
		"tar archive with no data": {
			debContent: newARArchive(t,
				arTestMember{name: "data.tar.xz/", content: nil},
			),
			paths:      []string{firstPath},
			errMessage: "tar archive has no data",
		},
		"no app.asar file in tar archive": {
			debContent: newDebArchiveContent(t, "data.tar.gz/", gzipBytes(t,
				newTARArchive(t, map[string][]byte{"opt/PureVPN/resources/other.asar": []byte("content")})),
			),
			paths:      []string{firstPath},
			errMessage: `file "opt/PureVPN/resources/app.asar" not found in tar archive`,
		},
		"invalid ar archive": {
			debContent: []byte("not an ar archive"),
			paths:      []string{firstPath},
			errMessage: "invalid ar archive header",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			files, err := extractFilesFromDeb(bytes.NewReader(testCase.debContent), testCase.paths...)

			if testCase.errMessage != "" {
				assert.ErrorContains(t, err, testCase.errMessage)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, testCase.files, files)
		})
	}
}

func Test_extractFilesFromASAR(t *testing.T) {
	t.Parallel()

	const path = "node_modules/atom-sdk/lib/offline-data/local-data.js"
	fileContent := []byte(`module.exports={body:{reseller_id:1}}`)
	validASAR := newASARArchive(t, map[string][]byte{path: fileContent})
	beyondHeader := []byte(`{"files":{"file.js":{"offset":"1000000000","size":10}}}`)
	beyondPayload := []byte("0123456789")
	//nolint:gosec // the JSON header of a test archive cannot exceed 4 GiB
	beyondASAR := newRawASARArchive(uint32(len(beyondHeader)), beyondHeader, beyondPayload)

	testCases := map[string]struct {
		asarContent []byte
		asarSize    int64
		paths       []string
		files       map[string][]byte
		errMessage  string
		unreadBytes int
	}{
		"valid_archive": {
			asarContent: validASAR,
			asarSize:    int64(len(validASAR)),
			paths:       []string{path},
			files:       map[string][]byte{path: fileContent},
		},
		"archive_size_exceeding_maximum": {
			asarContent: validASAR,
			asarSize:    1024*1024*1024 + 1,
			paths:       []string{path},
			errMessage:  "asar archive size 1073741825 exceeds maximum of 1073741824",
			unreadBytes: len(validASAR),
		},
		"header_length_exceeding_maximum": {
			asarContent: newRawASARArchive(32*1024*1024+1, nil, nil),
			asarSize:    64 * 1024 * 1024,
			paths:       []string{path},
			errMessage:  "asar header length 33554433 exceeds maximum of 33554432",
		},
		"header_length_exceeding_archive_size": {
			asarContent: newRawASARArchive(1000, []byte(`{}`), nil),
			asarSize:    18,
			paths:       []string{path},
			errMessage:  "asar header length 1000 exceeds archive size 18",
			unreadBytes: 2,
		},
		"file_ending_beyond_archive_data": {
			asarContent: beyondASAR,
			asarSize:    int64(len(beyondASAR)),
			paths:       []string{"file.js"},
			errMessage:  `asar file "file.js" ends at offset 1000000010 beyond the archive data size 10`,
			unreadBytes: len(beyondPayload),
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			reader := bytes.NewReader(testCase.asarContent)

			files, err := extractFilesFromASAR(reader, testCase.asarSize, testCase.paths...)

			if testCase.errMessage != "" {
				assert.ErrorContains(t, err, testCase.errMessage)
				assert.Equal(t, testCase.unreadBytes, reader.Len())
				return
			}
			require.NoError(t, err)
			assert.Equal(t, testCase.files, files)
		})
	}
}

type arTestMember struct {
	name    string
	content []byte
}

// newARArchive returns an ar archive containing the given members.
func newARArchive(t *testing.T, members ...arTestMember) (content []byte) {
	t.Helper()

	buffer := bytes.NewBufferString("!<arch>\n")
	for _, member := range members {
		header := fmt.Sprintf("%-16s%-12d%-6d%-6d%-8o%-10d`\n",
			member.name, 0, 0, 0, 0o644, len(member.content))
		require.Len(t, header, 60)
		buffer.WriteString(header)
		buffer.Write(member.content)
		if len(member.content)%2 == 1 {
			buffer.WriteByte('\n')
		}
	}
	return buffer.Bytes()
}

// newTARArchive returns a tar archive containing the given files.
func newTARArchive(t *testing.T, files map[string][]byte) (content []byte) {
	t.Helper()

	buffer := bytes.NewBuffer(nil)
	writer := tar.NewWriter(buffer)
	for _, path := range slices.Sorted(maps.Keys(files)) {
		fileContent := files[path]
		err := writer.WriteHeader(&tar.Header{
			Name: "./" + path,
			Mode: 0o644,
			Size: int64(len(fileContent)),
		})
		require.NoError(t, err)
		_, err = writer.Write(fileContent)
		require.NoError(t, err)
	}
	require.NoError(t, writer.Close())
	return buffer.Bytes()
}

func gzipBytes(t *testing.T, content []byte) []byte {
	t.Helper()

	buffer := bytes.NewBuffer(nil)
	writer := gzip.NewWriter(buffer)
	_, err := writer.Write(content)
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	return buffer.Bytes()
}

func xzBytes(t *testing.T, content []byte) []byte {
	t.Helper()

	buffer := bytes.NewBuffer(nil)
	writer, err := xz.NewWriter(buffer)
	require.NoError(t, err)
	_, err = writer.Write(content)
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	return buffer.Bytes()
}

// newDebArchive returns a .deb (ar) archive containing the app.asar content
// in a data.tar archive compressed with the given suffix (`.gz`, `.xz` or none).
func newDebArchive(t *testing.T, asarContent []byte, suffix string) []byte {
	t.Helper()

	const appASARPath = "opt/PureVPN/resources/app.asar"
	tarContent := newTARArchive(t, map[string][]byte{appASARPath: asarContent})
	var compressedContent []byte
	switch suffix {
	case ".gz":
		compressedContent = gzipBytes(t, tarContent)
	case ".xz":
		compressedContent = xzBytes(t, tarContent)
	case "":
		compressedContent = tarContent
	default:
		t.Fatalf("unsupported suffix %q", suffix)
	}
	return newDebArchiveContent(t, dataTARPrefix+suffix+"/", compressedContent)
}

func newDebArchiveContent(t *testing.T, tarName string, tarContent []byte) []byte {
	t.Helper()

	return newARArchive(t,
		arTestMember{name: "debian-binary", content: []byte("2.0\n")},
		arTestMember{name: tarName, content: tarContent},
	)
}

// newASARArchive returns an asar archive containing the given files,
// mimicking the Electron asar format: a 16 bytes prefix, a JSON header
// describing the files and then the file contents, one after another.
func newASARArchive(t *testing.T, files map[string][]byte) (content []byte) {
	t.Helper()

	type node struct {
		Files  map[string]*node `json:"files,omitempty"`
		Offset string           `json:"offset,omitempty"`
		Size   uint             `json:"size,omitempty"`
	}

	root := &node{Files: make(map[string]*node)}
	var payload []byte
	for _, path := range slices.Sorted(maps.Keys(files)) {
		fileContent := files[path]
		currentNode := root
		segments := strings.Split(path, "/")
		for i, segment := range segments {
			if i == len(segments)-1 {
				currentNode.Files[segment] = &node{
					Offset: fmt.Sprintf("%d", len(payload)),
					Size:   uint(len(fileContent)),
				}
				continue
			}
			childNode, ok := currentNode.Files[segment]
			if !ok {
				childNode = &node{Files: make(map[string]*node)}
				currentNode.Files[segment] = childNode
			}
			currentNode = childNode
		}
		payload = append(payload, fileContent...)
	}

	headerContent, err := json.Marshal(root)
	require.NoError(t, err)

	//nolint:gosec // the JSON header of a test archive cannot exceed 4 GiB
	return newRawASARArchive(uint32(len(headerContent)), headerContent, payload)
}

// newRawASARArchive returns an asar archive made of the 16 bytes prefix
// declaring the given JSON header length, the JSON header and the payload.
func newRawASARArchive(headerLength uint32, headerContent, payload []byte) (content []byte) {
	buffer := bytes.NewBuffer(nil)
	prefix := make([]byte, 16)
	binary.LittleEndian.PutUint32(prefix[12:16], headerLength)
	buffer.Write(prefix)
	buffer.Write(headerContent)
	buffer.Write(payload)
	return buffer.Bytes()
}
