package db

import (
	"fmt"
	"testing"
	"time"
)

// HostsForTask is what scopes the traffic tools: a run may read captures for the
// hosts its own task may target. It must therefore include BOTH the hosts the
// task discovered itself (task_ids) and the hosts that belong to its declared
// scope but were discovered elsewhere — a company / root_domain scope authorizes
// the whole tree, and a capture taken on api.example.com is in scope even when
// no scan has re-upserted that asset row under this task's id.
//
// The second half is the part that is easy to lose: restricting to task_ids
// alone still passes a naive "my own assets are visible" test, while silently
// hiding traffic the operator explicitly authorized.
func TestHostsForTaskUnionsAssetsAndDeclaredScope(t *testing.T) {
	d, assets, _ := testSetup(t)
	t.Cleanup(func() { d.Close() })

	task, err := d.CreateTask("capture scope", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	stamp := time.Now().UnixNano()
	ownDomain := fmt.Sprintf("own%d.invalid", stamp)   // discovered by this task
	ownURL := "https://api." + ownDomain + "/v1/login" // URL → hostname only
	ownIP := fmt.Sprintf("10.%d.%d.1", stamp%200, stamp%250)
	scopedDomain := fmt.Sprintf("scoped%d.invalid", stamp) // discovered by ANOTHER task, in our scope
	outDomain := fmt.Sprintf("out%d.invalid", stamp)       // neither ours nor in scope
	foreignTask := stamp + 991

	// Declared scope: the root domain admits every subdomain of scopedDomain.
	if err := assets.upsertTaskScope(TaskScope{TaskID: task.ID, Kind: "root_domain", Domain: scopedDomain}); err != nil {
		t.Fatalf("seed scope: %v", err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM task_scope WHERE task_id=$1`, task.ID) })

	insert := func(typ, domain, rootDom, url, ip string, taskIDs []int64) int64 {
		t.Helper()
		var id int64
		if err := d.QueryRow(`INSERT INTO assets(type,domain,root_domain,url,ip,task_ids,last_seen)
			VALUES ($1,NULLIF($2,''),NULLIF($3,''),NULLIF($4,''),NULLIF($5,''),$6::bigint[],now()) RETURNING id`,
			typ, domain, rootDom, url, ip, taskIDs).Scan(&id); err != nil {
			t.Fatalf("insert %s: %v", domain, err)
		}
		return id
	}
	ownID := insert("subdomain", ownDomain, ownDomain, "", "", []int64{task.ID})
	urlID := insert("endpoint", "api."+ownDomain, ownDomain, ownURL, "", []int64{task.ID})
	ipID := insert("ip", "", "", "", ownIP, []int64{task.ID})
	scopedID := insert("subdomain", "www."+scopedDomain, scopedDomain, "", "", []int64{foreignTask})
	outID := insert("subdomain", outDomain, outDomain, "", "", []int64{foreignTask})
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM assets WHERE id=ANY($1::bigint[])`,
			[]int64{ownID, urlID, ipID, scopedID, outID})
	})

	hosts, err := assets.HostsForTask(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, h := range hosts {
		got[h] = true
	}

	for _, want := range []string{
		ownDomain,             // own asset domain
		"api." + ownDomain,    // hostname extracted from the URL
		ownIP,                 // own IP asset
		"www." + scopedDomain, // in declared scope, discovered by another task
	} {
		if !got[want] {
			t.Errorf("HostsForTask missing %q; got %v", want, hosts)
		}
	}
	if got[outDomain] {
		t.Errorf("HostsForTask leaked out-of-scope host %q", outDomain)
	}
	// The full URL must not appear: the traffic index keys on URL.Hostname().
	if got[ownURL] {
		t.Errorf("HostsForTask returned a full URL %q instead of its hostname", ownURL)
	}

	// taskID<=0 means "no task context" — the caller treats the empty result as
	// "nothing in scope", so it must be empty rather than everything.
	if hosts, err := assets.HostsForTask(0); err != nil || len(hosts) != 0 {
		t.Fatalf("HostsForTask(0) = %v, %v; want empty", hosts, err)
	}
}
