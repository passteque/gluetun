package command

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_split(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		command    string
		words      []string
		errWrapped error
		errMessage string
	}{
		"empty": {
			command:    "",
			errWrapped: errCommandEmpty,
			errMessage: "command is empty",
		},
		"concrete_sh_command": {
			command: `/bin/sh -c "echo 123"`,
			words:   []string{"/bin/sh", "-c", "echo 123"},
		},
		"single_word": {
			command: "word1",
			words:   []string{"word1"},
		},
		"two_words_single_space": {
			command: "word1 word2",
			words:   []string{"word1", "word2"},
		},
		"two_words_multiple_space": {
			command: "word1    word2",
			words:   []string{"word1", "word2"},
		},
		"two_words_no_expansion": {
			command: "word1*    word2?",
			words:   []string{"word1*", "word2?"},
		},
		"escaped_single quote": {
			command: "ain\\'t good",
			words:   []string{"ain't", "good"},
		},
		"escaped_single_quote_all_single_quoted": {
			command: "'ain'\\''t good'",
			words:   []string{"ain't good"},
		},
		"empty_single_quoted": {
			command: "word1 ''  word2",
			words:   []string{"word1", "", "word2"},
		},
		"escaped_newline": {
			command: "word1\\\nword2",
			words:   []string{"word1word2"},
		},
		"quoted_newline": {
			command: "text \"with\na\" quoted newline",
			words:   []string{"text", "with\na", "quoted", "newline"},
		},
		"quoted_escaped_newline": {
			command: "\"word1\\d\\\\\\\" word2\\\nword3 word4\"",
			words:   []string{"word1\\d\\\" word2word3 word4"},
		},
		"escaped_separated_newline": {
			command: "word1 \\\n word2",
			words:   []string{"word1", "word2"},
		},
		"double_quotes_no_spacing": {
			command: "word1\"word2\"word3",
			words:   []string{"word1word2word3"},
		},
		"unterminated_single_quote": {
			command:    "'abc'\\''def",
			errWrapped: errSingleQuoteUnterminated,
			errMessage: `splitting word in "'abc'\\''def": unterminated single-quoted string`,
		},
		"unterminated_double_quote": {
			command:    "\"abc'def",
			errWrapped: errDoubleQuoteUnterminated,
			errMessage: `splitting word in "\"abc'def": unterminated double-quoted string`,
		},
		"unterminated_escape": {
			command:    "abc\\",
			errWrapped: errEscapeUnterminated,
			errMessage: `splitting word in "abc\\": unterminated backslash-escape`,
		},
		"unterminated_escape_only": {
			command:    "   \\",
			errWrapped: errEscapeUnterminated,
			errMessage: `unterminated backslash-escape: "   \\"`,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			words, err := split(testCase.command)

			assert.Equal(t, testCase.words, words)
			assert.ErrorIs(t, err, testCase.errWrapped)
			if testCase.errWrapped != nil {
				assert.EqualError(t, err, testCase.errMessage)
			}
		})
	}
}
