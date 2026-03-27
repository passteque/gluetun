package command

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

var (
	errCommandEmpty            = errors.New("command is empty")
	errSingleQuoteUnterminated = errors.New("unterminated single-quoted string")
	errDoubleQuoteUnterminated = errors.New("unterminated double-quoted string")
	errEscapeUnterminated      = errors.New("unterminated backslash-escape")
)

// split splits a command string into a slice of arguments.
// This is especially important for commands such as:
// /bin/sh -c "echo hello"
// which should be split into: ["/bin/sh", "-c", "echo hello"]
// It supports backslash-escapes, single-quotes and double-quotes.
// It does not support:
// - the $" quoting style.
// - expansion (brace, shell or pathname).
func split(command string) (words []string, err error) {
	if command == "" {
		return nil, fmt.Errorf("%w", errCommandEmpty)
	}

	const bufferSize = 1024
	buffer := bytes.NewBuffer(make([]byte, bufferSize))

	startIndex := 0

	for startIndex < len(command) {
		// skip any split characters at the start
		character, runeSize := utf8.DecodeRuneInString(command[startIndex:])
		switch {
		case strings.ContainsRune(" \n\t", character):
			startIndex += runeSize
		case character == '\\':
			// Look ahead to eventually skip an escaped newline
			if command[startIndex+runeSize:] == "" {
				return nil, fmt.Errorf("%w: %q", errEscapeUnterminated, command)
			}
			character, runeSize := utf8.DecodeRuneInString(command[startIndex+runeSize:])
			if character == '\n' {
				startIndex += runeSize + runeSize // backslash and newline
			}
		default:
			var word string
			buffer.Reset()
			word, startIndex, err = splitWord(command, startIndex, buffer)
			if err != nil {
				return nil, fmt.Errorf("splitting word in %q: %w", command, err)
			}
			words = append(words, word)
		}
	}
	return words, nil
}

// WARNING: buffer must be cleared before calling this function.
func splitWord(input string, startIndex int, buffer *bytes.Buffer) (
	word string, newStartIndex int, err error,
) {
	cursor := startIndex
	for cursor < len(input) {
		character, runeLength := utf8.DecodeRuneInString(input[cursor:])
		cursor += runeLength
		if character == '"' ||
			character == '\'' ||
			character == '\\' ||
			character == ' ' ||
			character == '\n' ||
			character == '\t' {
			buffer.WriteString(input[startIndex : cursor-runeLength])
		}

		switch {
		case strings.ContainsRune(" \n\t", character): // spacing character
			return buffer.String(), cursor, nil
		case character == '"':
			return handleDoubleQuoted(input, cursor, buffer)
		case character == '\'':
			return handleSingleQuoted(input, cursor, buffer)
		case character == '\\':
			return handleEscaped(input, cursor, buffer)
		}
	}

	buffer.WriteString(input[startIndex:])
	return buffer.String(), len(input), nil
}

func handleDoubleQuoted(input string, startIndex int, buffer *bytes.Buffer) (
	word string, newStartIndex int, err error,
) {
	cursor := startIndex
	for cursor < len(input) {
		nextCharacter, nextRuneLength := utf8.DecodeRuneInString(input[cursor:])
		cursor += nextRuneLength
		switch nextCharacter {
		case '"': // end of the double quoted string
			buffer.WriteString(input[startIndex : cursor-nextRuneLength])
			return splitWord(input, cursor, buffer)
		case '\\': // escaped character
			escapedCharacter, escapedRuneLength := utf8.DecodeRuneInString(input[cursor:])
			cursor += escapedRuneLength
			if !strings.ContainsRune("$`\"\n\\", escapedCharacter) {
				break
			}
			buffer.WriteString(input[startIndex : cursor-nextRuneLength-escapedRuneLength])
			if escapedCharacter != '\n' {
				// skip backslash entirely for the newline character
				buffer.WriteRune(escapedCharacter)
			}
			startIndex = cursor
		}
	}
	return "", 0, fmt.Errorf("%w", errDoubleQuoteUnterminated)
}

func handleSingleQuoted(input string, startIndex int, buffer *bytes.Buffer) (
	word string, newStartIndex int, err error,
) {
	closingQuoteIndex := strings.IndexRune(input[startIndex:], '\'')
	if closingQuoteIndex == -1 {
		return "", 0, fmt.Errorf("%w", errSingleQuoteUnterminated)
	}
	buffer.WriteString(input[startIndex : startIndex+closingQuoteIndex])
	const singleQuoteRuneLength = 1
	startIndex += closingQuoteIndex + singleQuoteRuneLength
	return splitWord(input, startIndex, buffer)
}

func handleEscaped(input string, startIndex int, buffer *bytes.Buffer) (
	word string, newStartIndex int, err error,
) {
	if input[startIndex:] == "" {
		return "", 0, fmt.Errorf("%w", errEscapeUnterminated)
	}
	character, runeLength := utf8.DecodeRuneInString(input[startIndex:])
	if character != '\n' { // backslash-escaped newline is ignored
		buffer.WriteString(input[startIndex : startIndex+runeLength])
	}
	startIndex += runeLength
	return splitWord(input, startIndex, buffer)
}
