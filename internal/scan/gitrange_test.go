package scan

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"osv.dev/bindings/go/api"
)

const getter = "github.com/hashicorp/go-getter"

// gitFixture serves a module proxy (host proxy.test) and the OSV API (host
// api.osv.dev) from maps, recording what was asked.
type gitFixture struct {
	versions   []string            // the proxy's @v/list
	hashes     map[string]string   // version -> origin commit
	subdir     map[string]string   // version -> origin subdir
	status     map[string]int      // proxy path suffix -> forced status
	commitHits map[string][]string // commit -> advisory IDs
	pkgHits    map[string][]string // "module@version" -> advisory IDs
	records    map[string]*osvschema.Vulnerability
	mu         sync.Mutex
	commitQs   int
	proxyGets  int
}

func (f *gitFixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch r.URL.Host {
	case "proxy.test":
		f.proxyGets++
		for suffix, code := range f.status {
			if strings.HasSuffix(r.URL.Path, suffix) {
				w.WriteHeader(code)
				return
			}
		}
		path := strings.TrimPrefix(r.URL.Path, "/"+getter+"/@v/")
		if path == "list" {
			_, _ = io.WriteString(w, strings.Join(f.versions, "\n"))
			return
		}
		version := strings.TrimSuffix(path, ".info")
		hash, ok := f.hashes[version]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = fmt.Fprintf(w, `{"Version":%q,"Origin":{"VCS":"git","Hash":%q,"Subdir":%q}}`, version, hash, f.subdir[version])
	case "api.osv.dev":
		if after, ok := strings.CutPrefix(r.URL.Path, "/v1/vulns/"); ok {
			record, ok := f.records[after]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			writeProto(w, record)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var batch api.BatchQuery
		if err := protojson.Unmarshal(body, &batch); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		resp := &api.BatchVulnerabilityList{}
		for _, q := range batch.GetQueries() {
			var ids []string
			if commit := q.GetCommit(); commit != "" {
				f.commitQs++
				ids = f.commitHits[commit]
			} else {
				ids = f.pkgHits[q.GetPackage().GetName()+"@"+q.GetVersion()]
			}
			list := &api.VulnerabilityList{}
			for _, id := range ids {
				list.Vulns = append(list.Vulns, &osvschema.Vulnerability{Id: id})
			}
			resp.Results = append(resp.Results, list)
		}
		writeProto(w, resp)
	default:
		w.WriteHeader(http.StatusTeapot)
	}
}

// gitRecord is a CNA-style record: GIT ranges only, no Go package.
func gitRecord(id, fixedCommit string, aliases ...string) *osvschema.Vulnerability {
	return &osvschema.Vulnerability{
		Id:      id,
		Aliases: aliases,
		Summary: "git-range " + id,
		Affected: []*osvschema.Affected{{Ranges: []*osvschema.Range{{
			Type:   osvschema.Range_GIT,
			Repo:   "https://github.com/hashicorp/go-getter",
			Events: []*osvschema.Event{{Introduced: "aaaa"}, {Fixed: fixedCommit}},
		}}}},
	}
}

func newGetterFixture() *gitFixture {
	f := &gitFixture{
		versions: []string{"v1.8.5", "v1.8.6", "v1.8.7", "v1.8.8", "v1.8.9", "v1.8.10", "v1.9.0-rc.1", "v2.0.0"},
		hashes:   map[string]string{},
		subdir:   map[string]string{},
		status:   map[string]int{},
		records:  map[string]*osvschema.Vulnerability{},
		pkgHits:  map[string][]string{},
	}
	for _, v := range f.versions {
		f.hashes[v] = "hash-" + v
	}
	f.commitHits = map[string][]string{"hash-v1.8.6": {"CVE-A", "CVE-B"}}
	f.records["CVE-A"] = gitRecord("CVE-A", "hash-v1.8.10")
	f.records["CVE-B"] = gitRecord("CVE-B", "hash-v1.8.9")
	return f
}

func (f *gitFixture) scan(t *testing.T, mutate func(*VulnerabilityScanner)) (*ScanResult, error) {
	t.Helper()
	vs := newTestScanner(newMockHTTPClient(f))
	vs.proxyURL = "https://proxy.test"
	if mutate != nil {
		mutate(vs)
	}
	return vs.ScanPackages(t.Context(), []Package{{Name: getter, Version: "v1.8.6", Ecosystem: "Go"}})
}

func TestGitRange_RootModuleFixedAtTaggedCommit(t *testing.T) {
	f := newGetterFixture()
	result, err := f.scan(t, nil)
	require.NoError(t, err)

	fixed := map[string]string{}
	for _, v := range result.Vulnerabilities {
		fixed[v.ID] = v.FixedVersion
		assert.Empty(t, v.VulnerableImports, "a git-range advisory applies to the whole module")
		assert.Equal(t, gitRangeSource, v.DatabaseSpecific.(map[string]any)["source"])
	}
	assert.Equal(t, map[string]string{"CVE-A": "v1.8.10", "CVE-B": "v1.8.9"}, fixed)
	require.Len(t, result.SecurityBumps, 1)
	assert.Equal(t, getter, result.SecurityBumps[0].Name)
	assert.Equal(t, "v1.8.10", result.SecurityBumps[0].FixedVersion)
	assert.Equal(t, []string{"CVE-A", "CVE-B"}, result.SecurityBumps[0].VulnIDs)
}

func TestGitRange_SubdirModuleSkipped(t *testing.T) {
	f := newGetterFixture()
	f.subdir["v1.8.6"] = "sub"
	result, err := f.scan(t, nil)
	require.NoError(t, err)
	assert.Empty(t, result.Vulnerabilities)
	assert.Zero(t, f.commitQs, "a module below the repo root never reaches the commit query")
}

func TestGitRange_PackageScopedRecordWinsByAlias(t *testing.T) {
	f := newGetterFixture()
	// The Go-scoped GO- record names CVE-A as an alias: it covers it.
	f.pkgHits[getter+"@1.8.6"] = []string{"GO-1"}
	f.records["GO-1"] = &osvschema.Vulnerability{
		Id: "GO-1", Aliases: []string{"CVE-A"},
		Affected: []*osvschema.Affected{{
			Package: &osvschema.Package{Ecosystem: "Go", Name: getter},
			Ranges:  []*osvschema.Range{{Type: osvschema.Range_SEMVER, Events: []*osvschema.Event{{Introduced: "0"}, {Fixed: "1.8.9"}}}},
		}},
	}
	result, err := f.scan(t, nil)
	require.NoError(t, err)

	var ids []string
	for _, v := range result.Vulnerabilities {
		ids = append(ids, v.ID)
	}
	assert.ElementsMatch(t, []string{"CVE-A", "CVE-B"}, ids, "CVE-A once (from GO-1), CVE-B by git range")
	for _, v := range result.Vulnerabilities {
		if v.ID == "CVE-A" {
			assert.Nil(t, v.DatabaseSpecific.(map[string]any)["source"], "CVE-A comes from the package-scoped record")
			assert.Equal(t, "v1.8.9", v.FixedVersion)
		}
	}
}

func TestGitRange_RecordWithGoPackageIgnored(t *testing.T) {
	f := newGetterFixture()
	f.records["CVE-A"].Affected = append(f.records["CVE-A"].Affected, &osvschema.Affected{
		Package: &osvschema.Package{Ecosystem: "Go", Name: getter},
	})
	result, err := f.scan(t, nil)
	require.NoError(t, err)
	require.Len(t, result.Vulnerabilities, 1)
	assert.Equal(t, "CVE-B", result.Vulnerabilities[0].ID)
}

func TestGitRange_FallsBackToFirstUnmatchedCommit(t *testing.T) {
	f := newGetterFixture()
	f.records["CVE-A"] = gitRecord("CVE-A", "not-a-release-commit")
	f.commitHits = map[string][]string{
		"hash-v1.8.6": {"CVE-A"},
		"hash-v1.8.7": {"CVE-A"},
	} // v1.8.8 is the first version OSV no longer matches
	result, err := f.scan(t, nil)
	require.NoError(t, err)
	require.Len(t, result.Vulnerabilities, 1)
	assert.Equal(t, "v1.8.8", result.Vulnerabilities[0].FixedVersion)
}

func TestGitRange_NoFixIsReportedWithoutBump(t *testing.T) {
	f := newGetterFixture()
	f.records["CVE-A"] = gitRecord("CVE-A", "not-a-release-commit")
	f.commitHits = map[string][]string{}
	for _, v := range f.versions {
		f.commitHits["hash-"+v] = []string{"CVE-A"} // every release still matches
	}
	result, err := f.scan(t, nil)
	require.NoError(t, err)
	require.Len(t, result.Vulnerabilities, 1)
	assert.Empty(t, result.Vulnerabilities[0].FixedVersion)
	assert.Empty(t, result.SecurityBumps)
}

func TestGitRange_PrivateModuleNeverLeavesTheMachine(t *testing.T) {
	f := newGetterFixture()
	result, err := f.scan(t, func(vs *VulnerabilityScanner) { vs.privatePatterns = "github.com/hashicorp/*" })
	require.NoError(t, err)
	assert.Empty(t, result.Vulnerabilities)
	assert.Zero(t, f.proxyGets)
	assert.Zero(t, f.commitQs)
}

func TestGitRange_ProxyDisabledSkips(t *testing.T) {
	f := newGetterFixture()
	result, err := f.scan(t, func(vs *VulnerabilityScanner) { vs.proxyURL = "" })
	require.NoError(t, err)
	assert.Empty(t, result.Vulnerabilities)
	assert.Zero(t, f.proxyGets)
}

func TestGitRange_Proxy4xxSkipsModule(t *testing.T) {
	for _, code := range []int{http.StatusNotFound, http.StatusGone, http.StatusUnauthorized} {
		f := newGetterFixture()
		f.status["v1.8.6.info"] = code
		result, err := f.scan(t, nil)
		require.NoError(t, err, "status %d", code)
		assert.Empty(t, result.Vulnerabilities, "status %d", code)
	}
}

func TestGitRange_ProxyServerErrorFailsClosed(t *testing.T) {
	f := newGetterFixture()
	f.status["v1.8.6.info"] = http.StatusBadGateway
	_, err := f.scan(t, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "module proxy")
}

func TestGitRange_ResultsAreCached(t *testing.T) {
	f := newGetterFixture()
	vs := newTestScanner(newMockHTTPClient(f))
	vs.proxyURL = "https://proxy.test"
	pkgs := []Package{{Name: getter, Version: "v1.8.6", Ecosystem: "Go"}}
	_, err := vs.ScanPackages(t.Context(), pkgs)
	require.NoError(t, err)
	gets, qs := f.proxyGets, f.commitQs
	_, err = vs.ScanPackages(t.Context(), pkgs)
	require.NoError(t, err)
	assert.Equal(t, gets, f.proxyGets, "a rescan of the same module@version repeats no proxy request")
	assert.Equal(t, qs, f.commitQs, "...nor commit query")
}
