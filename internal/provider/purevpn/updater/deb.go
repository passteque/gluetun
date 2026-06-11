package updater

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

const pureVPNAsarPath = "opt/PureVPN/resources/app.asar"

type debEntry struct {
	name string
	data []byte
}

func extractAsarFromDeb(debBytes []byte) (asarContent []byte, err error) {
	entries, err := parseArArchive(debBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing .deb ar archive: %w", err)
	}

	var dataTarName string
	var dataTarCompressed []byte
	for _, entry := range entries {
		if strings.HasPrefix(entry.name, "data.tar") {
			dataTarName = entry.name
			dataTarCompressed = entry.data
			break
		}
	}
	if len(dataTarCompressed) == 0 {
		return nil, fmt.Errorf("data.tar archive not found in .deb")
	}

	dataTar, err := decompressDataTar(dataTarName, dataTarCompressed)
	if err != nil {
		return nil, fmt.Errorf("decompressing %s: %w", dataTarName, err)
	}

	asarContent, err = extractFileFromTar(dataTar, pureVPNAsarPath)
	if err != nil {
		return nil, fmt.Errorf("extracting %s from tar: %w", pureVPNAsarPath, err)
	}

	return asarContent, nil
}

func parseArArchive(content []byte) (entries []debEntry, err error) {
	const (
		globalHeader = "!<arch>\n"
		headerLen    = 60
	)

	if len(content) < len(globalHeader) || string(content[:len(globalHeader)]) != globalHeader {
		return nil, fmt.Errorf("invalid ar archive header")
	}

	offset := len(globalHeader)
	for offset+headerLen <= len(content) {
		header := content[offset : offset+headerLen]
		offset += headerLen

		name := strings.TrimSpace(string(header[0:16]))
		name = strings.TrimSuffix(name, "/")

		sizeString := strings.TrimSpace(string(header[48:58]))
		size, parseErr := strconv.Atoi(sizeString)
		if parseErr != nil {
			return nil, fmt.Errorf("parsing ar member %q size %q: %w", name, sizeString, parseErr)
		}
		if size < 0 {
			return nil, fmt.Errorf("negative size for ar member %q", name)
		}

		if offset+size > len(content) {
			return nil, fmt.Errorf("ar member %q overflows archive content", name)
		}
		data := make([]byte, size)
		copy(data, content[offset:offset+size])
		offset += size
		if size%2 == 1 {
			offset++
		}

		entries = append(entries, debEntry{name: name, data: data})
	}

	if len(entries) == 0 {
		return nil, fmt.Errorf("no members found in ar archive")
	}

	return entries, nil
}

func decompressDataTar(fileName string, content []byte) (dataTar []byte, err error) {
	lowerFileName := strings.ToLower(fileName)

	switch {
	case strings.HasSuffix(lowerFileName, ".xz"):
		reader, err := xz.NewReader(bytes.NewReader(content))
		if err != nil {
			return nil, err
		}
		return io.ReadAll(reader)
	case strings.HasSuffix(lowerFileName, ".gz"):
		gzipReader, err := gzip.NewReader(bytes.NewReader(content))
		if err != nil {
			return nil, err
		}
		defer gzipReader.Close()
		return io.ReadAll(gzipReader)
	case strings.HasSuffix(lowerFileName, ".zst"):
		decoder, err := zstd.NewReader(bytes.NewReader(content))
		if err != nil {
			return nil, err
		}
		defer decoder.Close()
		return io.ReadAll(decoder)
	default:
		return content, nil
	}
}

func extractFileFromTar(tarContent []byte, expectedPath string) (fileContent []byte, err error) {
	tarReader := tar.NewReader(bytes.NewReader(tarContent))

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading tar: %w", err)
		}

		name := strings.TrimPrefix(header.Name, "./")
		if name != expectedPath {
			continue
		}

		fileContent, err = io.ReadAll(tarReader)
		if err != nil {
			return nil, fmt.Errorf("reading %s from tar: %w", expectedPath, err)
		}
		return fileContent, nil
	}

	return nil, fmt.Errorf("path %q not found in tar", expectedPath)
}

type asarNode struct {
	Files  map[string]*asarNode `json:"files,omitempty"`
	Offset string               `json:"offset,omitempty"`
	Size   int                  `json:"size,omitempty"`
}

type asarHeader struct {
	Files map[string]*asarNode `json:"files"`
}

func extractFileFromAsar(asarContent []byte, targetPath string) (fileContent []byte, err error) {
	if len(asarContent) < 16 {
		return nil, fmt.Errorf("asar content too short: %d", len(asarContent))
	}

	headerLength := int(binary.LittleEndian.Uint32(asarContent[12:16]))
	if headerLength <= 0 {
		return nil, fmt.Errorf("invalid asar header length: %d", headerLength)
	}
	if 16+headerLength > len(asarContent) {
		return nil, fmt.Errorf("asar header length exceeds content length")
	}

	headerContent := asarContent[16 : 16+headerLength]
	var header asarHeader
	if err := json.Unmarshal(headerContent, &header); err != nil {
		return nil, fmt.Errorf("unmarshalling asar header: %w", err)
	}

	node, err := asarGetNode(header.Files, targetPath)
	if err != nil {
		return nil, err
	}

	offset, err := strconv.Atoi(node.Offset)
	if err != nil {
		return nil, fmt.Errorf("parsing asar file offset %q for %q: %w", node.Offset, targetPath, err)
	}
	if node.Size < 0 {
		return nil, fmt.Errorf("negative asar file size %d for %q", node.Size, targetPath)
	}

	dataOffset := 16 + headerLength + offset
	dataEnd := dataOffset + node.Size
	if dataOffset < 0 || dataEnd > len(asarContent) {
		return nil, fmt.Errorf("asar file %q exceeds content boundaries", targetPath)
	}

	content := make([]byte, node.Size)
	copy(content, asarContent[dataOffset:dataEnd])
	return content, nil
}

func asarGetNode(files map[string]*asarNode, targetPath string) (node *asarNode, err error) {
	segments := strings.Split(targetPath, "/")
	currentFiles := files

	for i, segment := range segments {
		node = currentFiles[segment]
		if node == nil {
			return nil, fmt.Errorf("path %q not found in asar", targetPath)
		}
		if i == len(segments)-1 {
			return node, nil
		}
		currentFiles = node.Files
	}

	return nil, fmt.Errorf("path %q not found in asar", targetPath)
}
