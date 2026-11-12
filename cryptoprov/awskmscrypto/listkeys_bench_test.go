package awskmscrypto_test

import (
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/effective-security/xpki/v2/cryptoprov"
)

// benchDescribeLatency stands in for the KMS round trip of a DescribeKey.
const benchDescribeLatency = 200 * time.Microsecond

// BenchmarkListKeys lists the signing keys of accounts of growing size, a
// tenth of whose keys have the "p_" label prefix and an alias, over a fake
// client whose DescribeKey takes benchDescribeLatency. It is the successor
// of the v1 BenchmarkEnumKeys, whose EnumKeys described every key of the
// account on every listing (XPKI-032), and reports the same metrics: the
// ListKeys, ListAliases and DescribeKey calls, the listed keys and the peak
// concurrent DescribeKey calls per listing.
//
// The listings are "ids" (no filter, no fields), "sign" (the usage filter
// with the label of each key, the v1 listing), "prefix" (the label prefix
// through the alias index), "label" (one exact label) and "scan" (the label
// prefix with LabelSearch=scan, which describes every key as v1 did). A
// provider is created once per sub-benchmark, so "sign" pays the first
// listing of the immutable metadata once and b.N-1 listings from the cache.
func BenchmarkListKeys(b *testing.B) {
	for _, total := range []int{100, 1000, 5000} {
		client := newFakeKMS()
		client.describeDelay = benchDescribeLatency
		for i := range total {
			label := "k_" + strconv.Itoa(i)
			if i%10 == 0 {
				label = "p_" + strconv.Itoa(i)
			}
			id, err := client.addKey(label, types.KeySpecEccNistP256, types.KeyUsageTypeSignVerify)
			if err != nil {
				b.Fatal(err)
			}
			client.setAlias("alias/"+label, id)
		}
		v1Listing := cryptoprov.KeyFilter{Usage: cryptoprov.KeyUsageSign}
		prefix := cryptoprov.KeyFilter{LabelPrefix: "p_"}
		for _, bc := range []struct {
			name       string
			attributes string
			req        cryptoprov.ListKeysRequest
		}{
			{
				name: "ids",
			},
			{
				name: "sign",
				req: cryptoprov.ListKeysRequest{
					Filter: v1Listing,
					Fields: cryptoprov.KeyFieldMetadata,
				},
			},
			{
				name: "sign_ids",
				req:  cryptoprov.ListKeysRequest{Filter: v1Listing},
			},
			{
				name: "prefix",
				req: cryptoprov.ListKeysRequest{
					Filter: prefix,
					Fields: cryptoprov.KeyFieldMetadata,
				},
			},
			{
				name: "label",
				req: cryptoprov.ListKeysRequest{
					Filter: cryptoprov.KeyFilter{Label: "p_0"},
					Fields: cryptoprov.KeyFieldMetadata,
				},
			},
			{
				name:       "scan",
				attributes: "LabelSearch=scan",
				req: cryptoprov.ListKeysRequest{
					Filter: prefix,
					Fields: cryptoprov.KeyFieldMetadata,
				},
			},
		} {
			b.Run(fmt.Sprintf("keys=%d/%s", total, bc.name), func(b *testing.B) {
				provider := providerWith(client, nil, bc.attributes)
				before := counts(client)
				client.peak.Store(0)
				listed := 0

				b.ReportAllocs()
				for b.Loop() {
					listed = 0
					for _, err := range cryptoprov.AllKeys(b.Context(), provider, &bc.req) {
						if err != nil {
							b.Fatal(err)
						}
						listed++
					}
				}

				calls := before.since(client)
				b.ReportMetric(float64(calls["ListKeys"])/float64(b.N), "ListKeys/op")
				b.ReportMetric(float64(calls["ListAliases"])/float64(b.N), "ListAliases/op")
				b.ReportMetric(float64(calls["DescribeKey"])/float64(b.N), "DescribeKey/op")
				b.ReportMetric(float64(listed), "keys/op")
				b.ReportMetric(float64(client.peak.Load()), "peak_concurrency")
			})
		}
	}
}
