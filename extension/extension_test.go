package extension_test

import (
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/extension"
)

func TestExtensionInfoValidate(t *testing.T) {
	valid := extension.ExtensionInfo{Kind: extension.ExtensionKindStorage, Name: "store.a", Version: "1.0"}
	if err := valid.Validate(); err != nil {
		t.Fatalf("合法扩展元数据被拒绝: %v", err)
	}
	for _, invalid := range []extension.ExtensionInfo{
		{Kind: extension.ExtensionKind("bogus"), Name: "x"},
		{Kind: extension.ExtensionKindStorage, Name: ""},
		{Kind: extension.ExtensionKindAuthentication, Name: "auth", Version: ""},
	} {
		if err := invalid.Validate(); err == nil {
			t.Fatalf("非法扩展元数据应拒绝: %+v", invalid)
		}
	}
}
