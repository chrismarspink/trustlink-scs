package main

import (
	"encoding/json"
	"testing"
)

func TestMergeSBOMs(t *testing.T) {
	a := `{"bomFormat":"CycloneDX","metadata":{"component":{"type":"file","name":"/tmp/x/a.tar.gz"}},
		"components":[{"bom-ref":"1","name":"log4j-core"},{"bom-ref":"2","name":"jackson"}],
		"dependencies":[{"ref":"1","dependsOn":["2"]}]}`
	b := `{"bomFormat":"CycloneDX","metadata":{},
		"components":[{"bom-ref":"2","name":"jackson"},{"bom-ref":"3","name":"x/net"}],
		"dependencies":[{"ref":"1","dependsOn":["2"]},{"ref":"3"}]}`
	out, n, err := mergeSBOMs([][]byte{[]byte(a), []byte(b)}, "innopouch", "7.0")
	if err != nil || n != 3 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	var doc struct {
		Metadata struct {
			Component struct{ Name, Version string }
		}
		Components   []any
		Dependencies []any
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Metadata.Component.Name != "innopouch" || doc.Metadata.Component.Version != "7.0" {
		t.Errorf("metadata.component = %+v", doc.Metadata.Component)
	}
	if len(doc.Components) != 3 || len(doc.Dependencies) != 2 {
		t.Errorf("components=%d dependencies=%d", len(doc.Components), len(doc.Dependencies))
	}

	if _, n, _ := mergeSBOMs([][]byte{[]byte(`{"metadata":{}}`)}, "p", "1"); n != 0 {
		t.Errorf("empty scan should report 0 components, got %d", n)
	}
}
