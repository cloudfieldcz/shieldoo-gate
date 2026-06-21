package config

import (
	"reflect"
	"testing"

	"github.com/go-viper/mapstructure/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpstreamSet_DefaultOr_EmptyReturnsFallback(t *testing.T) {
	var u UpstreamSet
	assert.Equal(t, "https://pypi.org", u.DefaultOr("https://pypi.org"))
}

func TestUpstreamSet_DefaultOr_SetReturnsDefault(t *testing.T) {
	u := UpstreamSet{Default: "https://mirror.example.com"}
	assert.Equal(t, "https://mirror.example.com", u.DefaultOr("https://pypi.org"))
}

func TestStringToUpstreamSetHook_BareStringDecodesToDefault(t *testing.T) {
	var out UpstreamSet
	dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook: stringToUpstreamSetHookFunc(),
		Result:     &out,
	})
	require.NoError(t, err)
	require.NoError(t, dec.Decode("https://pypi.org"))
	assert.Equal(t, "https://pypi.org", out.Default)
	assert.Empty(t, out.ExtraIndexes)
}

func TestStringToUpstreamSetHook_StructDecodesUnchanged(t *testing.T) {
	in := map[string]interface{}{
		"default": "https://pypi.org",
		"extra_indexes": []interface{}{
			map[string]interface{}{
				"name":     "corp",
				"url":      "https://pkgs.internal.example.com/simple/",
				"packages": []interface{}{"mycompany-*"},
				"auth": map[string]interface{}{
					"type":      "basic",
					"token_env": "SGW_CORP_INDEX_TOKEN",
				},
			},
		},
	}
	var out UpstreamSet
	dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook: stringToUpstreamSetHookFunc(),
		Result:     &out,
	})
	require.NoError(t, err)
	require.NoError(t, dec.Decode(in))
	assert.Equal(t, "https://pypi.org", out.Default)
	require.Len(t, out.ExtraIndexes, 1)
	assert.Equal(t, "corp", out.ExtraIndexes[0].Name)
	assert.Equal(t, []string{"mycompany-*"}, out.ExtraIndexes[0].Packages)
	require.NotNil(t, out.ExtraIndexes[0].Auth)
	assert.Equal(t, "basic", out.ExtraIndexes[0].Auth.Type)
	assert.Equal(t, "SGW_CORP_INDEX_TOKEN", out.ExtraIndexes[0].Auth.TokenEnv)
}

func TestStringToUpstreamSetHook_NonUpstreamTargetUntouched(t *testing.T) {
	// The hook must only fire for UpstreamSet targets, leaving e.g. plain strings alone.
	hook := stringToUpstreamSetHookFunc().(func(reflect.Type, reflect.Type, interface{}) (interface{}, error))
	out, err := hook(reflect.TypeOf(""), reflect.TypeOf(""), "hello")
	require.NoError(t, err)
	assert.Equal(t, "hello", out)
}

func TestValidateUpstreamSet_DefaultOnly_OK(t *testing.T) {
	require.NoError(t, validateUpstreamSet("pypi", UpstreamSet{Default: "https://pypi.org"}))
}

func TestValidateUpstreamSet_HTTPIndexURL_Rejected(t *testing.T) {
	err := validateUpstreamSet("pypi", UpstreamSet{
		ExtraIndexes: []UpstreamIndex{{Name: "corp", URL: "http://insecure.example.com/"}},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "https")
}

func TestValidateUpstreamSet_UserinfoURL_Rejected(t *testing.T) {
	err := validateUpstreamSet("pypi", UpstreamSet{
		ExtraIndexes: []UpstreamIndex{{Name: "corp", URL: "https://user:pass@example.com/"}},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "userinfo")
}

func TestValidateUpstreamSet_BadName_Rejected(t *testing.T) {
	err := validateUpstreamSet("pypi", UpstreamSet{
		ExtraIndexes: []UpstreamIndex{{Name: "Corp_Index", URL: "https://example.com/"}},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "name")
}

func TestValidateUpstreamSet_DuplicateName_Rejected(t *testing.T) {
	err := validateUpstreamSet("pypi", UpstreamSet{
		ExtraIndexes: []UpstreamIndex{
			{Name: "corp", URL: "https://a.example.com/"},
			{Name: "corp", URL: "https://b.example.com/"},
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate")
}

func TestValidateUpstreamSet_StarOnlyPattern_Rejected(t *testing.T) {
	err := validateUpstreamSet("pypi", UpstreamSet{
		ExtraIndexes: []UpstreamIndex{{Name: "corp", URL: "https://example.com/", Packages: []string{"*"}}},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pattern")
}

func TestValidateUpstreamSet_DoubleStarPattern_Rejected(t *testing.T) {
	err := validateUpstreamSet("pypi", UpstreamSet{
		ExtraIndexes: []UpstreamIndex{{Name: "corp", URL: "https://example.com/", Packages: []string{"**"}}},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pattern")
}

func TestValidateUpstreamSet_BadAuthType_Rejected(t *testing.T) {
	err := validateUpstreamSet("pypi", UpstreamSet{
		ExtraIndexes: []UpstreamIndex{{
			Name: "corp", URL: "https://example.com/",
			Packages: []string{"corp-*"},
			Auth:     &UpstreamAuth{Type: "token", TokenEnv: "X"},
		}},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "auth")
}

func TestValidateUpstreamSet_AuthMissingTokenEnv_Rejected(t *testing.T) {
	err := validateUpstreamSet("pypi", UpstreamSet{
		ExtraIndexes: []UpstreamIndex{{
			Name: "corp", URL: "https://example.com/",
			Packages: []string{"corp-*"},
			Auth:     &UpstreamAuth{Type: "bearer", TokenEnv: ""},
		}},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token_env")
}

func TestValidateUpstreamSet_ValidScopedAuthIndex_OK(t *testing.T) {
	require.NoError(t, validateUpstreamSet("pypi", UpstreamSet{
		Default: "https://pypi.org",
		ExtraIndexes: []UpstreamIndex{{
			Name: "corp", URL: "https://pkgs.internal.example.com/simple/",
			FilesHost: "https://files.internal.example.com/",
			Packages:  []string{"mycompany-*", "acme-*"},
			Auth:      &UpstreamAuth{Type: "basic", TokenEnv: "SGW_CORP_INDEX_TOKEN"},
		}},
	}))
}

func TestValidateUpstreamSet_FilesHostHTTP_Rejected(t *testing.T) {
	err := validateUpstreamSet("pypi", UpstreamSet{
		ExtraIndexes: []UpstreamIndex{{Name: "corp", URL: "https://example.com/", FilesHost: "http://files.example.com/"}},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "files_host")
}
