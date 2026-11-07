package alpine

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Alpine_CreateUser(t *testing.T) {
	t.Parallel()

	const initialPasswd = "root:x:0:0:root:/root:/bin/sh\n" //nolint:gosec

	testCases := map[string]struct {
		lookupID        func(uid string) (*user.User, error)
		lookup          func(username string) (*user.User, error)
		createdUsername string
		errMessage      string
		expectedPasswd  string
	}{
		"lookup_id_error": {
			lookupID: func(string) (*user.User, error) {
				return nil, errors.New("test error")
			},
			errMessage:     "test error",
			expectedPasswd: initialPasswd,
		},
		"existing_user_with_same_username": {
			lookupID: func(string) (*user.User, error) {
				return &user.User{Uid: "1000", Username: "nonrootuser"}, nil
			},
			createdUsername: "nonrootuser",
			expectedPasswd:  initialPasswd,
		},
		"existing_user_with_different_username": {
			lookupID: func(string) (*user.User, error) {
				return &user.User{Uid: "1000", Username: "gluetun"}, nil
			},
			createdUsername: "gluetun",
			expectedPasswd:  initialPasswd,
		},
		"username_taken_by_different_uid": {
			lookupID: func(string) (*user.User, error) {
				return nil, user.UnknownUserIdError(1000)
			},
			lookup: func(string) (*user.User, error) {
				return &user.User{Uid: "1001", Username: "nonrootuser"}, nil
			},
			errMessage:     "user already exists: with name nonrootuser for ID 1001 instead of 1000",
			expectedPasswd: initialPasswd,
		},
		"new_user": {
			lookupID: func(string) (*user.User, error) {
				return nil, user.UnknownUserIdError(1000)
			},
			lookup: func(username string) (*user.User, error) {
				return nil, user.UnknownUserError(username)
			},
			createdUsername: "nonrootuser",
			expectedPasswd:  initialPasswd + "nonrootuser:x:1000:1001::/dev/null:/sbin/nologin\n",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			passwdPath := filepath.Join(t.TempDir(), "passwd")
			err := os.WriteFile(passwdPath, []byte(initialPasswd), 0o600)
			require.NoError(t, err)

			alpine := &Alpine{
				passwdPath: passwdPath,
				lookupID:   testCase.lookupID,
				lookup:     testCase.lookup,
			}

			createdUsername, err := alpine.CreateUser("nonrootuser", 1000, 1001)

			if testCase.errMessage != "" {
				assert.ErrorContains(t, err, testCase.errMessage)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, testCase.createdUsername, createdUsername)

			passwd, err := os.ReadFile(passwdPath)
			require.NoError(t, err)
			assert.Equal(t, testCase.expectedPasswd, string(passwd))
		})
	}
}
