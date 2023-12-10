package metricskey

import "github.com/effective-security/metrics"

// Perf
var (
	// PerfCryptoOperation is perf metric
	PerfCryptoOperation = metrics.Describe{
		Type:         metrics.TypeSample,
		Name:         "perf_crypto",
		Help:         "perf_crypto provides the sample metrics of crypto operations",
		RequiredTags: []string{"provider", "action"},
	}

	// PerfCAOperation is perf metric
	PerfCAOperation = metrics.Describe{
		Type:         metrics.TypeSample,
		Name:         "perf_ca",
		Help:         "perf_ca provides the sample metrics of crypto operations",
		RequiredTags: []string{"issuer", "action"},
	}

	// PerfCASignRequest is perf metric
	PerfCASignRequest = metrics.Describe{
		Type:         metrics.TypeSample,
		Name:         "perf_ca_signreq",
		Help:         "perf_ca_signreq provides the sample metrics of crypto operations",
		RequiredTags: []string{"issuer", "profile"},
	}
)

// Metrics returns slice of metrics from this repo
var Metrics = []*metrics.Describe{
	&PerfCryptoOperation,
	&PerfCAOperation,
	&PerfCASignRequest,
}
