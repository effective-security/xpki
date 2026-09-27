package awskmscrypto_test

import (
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// benchDescribeLatency stands in for the KMS round trip of a DescribeKey.
const benchDescribeLatency = 200 * time.Microsecond

// BenchmarkEnumKeys lists accounts of growing size over a fake client whose
// DescribeKey takes benchDescribeLatency, with a prefix that selects all,
// a tenth or none of the keys (XPKI-032). It reports the ListKeys and
// DescribeKey calls, the listed keys and the peak concurrent DescribeKey
// calls per listing.
func BenchmarkEnumKeys(b *testing.B) {
	for _, total := range []int{100, 1000, 5000} {
		client := newFakeKMS()
		client.describeDelay = benchDescribeLatency
		for i := range total {
			// a tenth of the keys have the "p_" prefix
			label := "k_" + strconv.Itoa(i)
			if i%10 == 0 {
				label = "p_" + strconv.Itoa(i)
			}
			if _, err := client.addKey(label, types.KeySpecEccNistP256, types.KeyUsageTypeSignVerify); err != nil {
				b.Fatal(err)
			}
		}
		for _, prefix := range []string{"", "p_", "none_"} {
			b.Run(fmt.Sprintf("keys=%d/prefix=%q", total, prefix), func(b *testing.B) {
				provider := newProvider(b, client)
				listKeys := client.CallCount("ListKeys")
				describeKeys := client.CallCount("DescribeKey")
				client.peak.Store(0)
				listed := 0

				b.ReportAllocs()
				for b.Loop() {
					keys, err := provider.EnumKeys(0, prefix)
					if err != nil {
						b.Fatal(err)
					}
					listed = len(keys)
				}

				b.ReportMetric(float64(client.CallCount("ListKeys")-listKeys)/float64(b.N), "ListKeys/op")
				b.ReportMetric(float64(client.CallCount("DescribeKey")-describeKeys)/float64(b.N), "DescribeKey/op")
				b.ReportMetric(float64(listed), "keys/op")
				b.ReportMetric(float64(client.peak.Load()), "peak_concurrency")
			})
		}
	}
}
