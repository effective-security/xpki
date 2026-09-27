package awskmscrypto_test

import (
	"fmt"
	"slices"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"
	"github.com/cockroachdb/errors"
	"github.com/effective-security/xpki/cryptoprov"
	"github.com/effective-security/xpki/cryptoprov/awskmscrypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// barrierTimeout bounds the wait of a test hook on other calls, so a broken
// implementation fails the test instead of hanging it.
const barrierTimeout = 10 * time.Second

// keyIDs returns the ids of keys.
func keyIDs(keys []cryptoprov.KeyInfo) []string {
	ids := make([]string, 0, len(keys))
	for _, key := range keys {
		ids = append(ids, key.ID)
	}
	return ids
}

// addSigningKeys adds total P-256 signing keys labelled "key_<n>" to client
// and returns their ids in listing order.
func addSigningKeys(t *testing.T, client *fakeKMS, total int) []string {
	t.Helper()
	ids := make([]string, 0, total)
	for i := range total {
		ids = append(ids, client.mustAddKey(t, "key_"+strconv.Itoa(i), types.KeySpecEccNistP256, types.KeyUsageTypeSignVerify))
	}
	return ids
}

// awaitBarrier waits for done to be closed and returns an error when it is
// not closed within barrierTimeout.
func awaitBarrier(done <-chan struct{}) error {
	select {
	case <-done:
		return nil
	case <-time.After(barrierTimeout):
		return errors.New("test barrier timed out")
	}
}

// TestEnumKeysPrefix checks that the listing has exactly the signing keys
// whose label starts with the prefix, in listing order, and that
// encryption keys and keys pending deletion are not listed (XPKI-032).
func TestEnumKeysPrefix(t *testing.T) {
	t.Parallel()

	client := newFakeKMS()
	provider := newProvider(t, client)
	rsaID := client.mustAddKey(t, "test_rsa", types.KeySpecRsa2048, types.KeyUsageTypeSignVerify)
	encryptID := client.mustAddKey(t, "test_encrypt", types.KeySpecRsa2048, types.KeyUsageTypeEncryptDecrypt)
	ecID := client.mustAddKey(t, "test_ec", types.KeySpecEccNistP256, types.KeyUsageTypeSignVerify)
	deletedID := client.mustAddKey(t, "test_deleted", types.KeySpecEccNistP256, types.KeyUsageTypeSignVerify)
	client.setState(deletedID, types.KeyStatePendingDeletion)
	disabledID := client.mustAddKey(t, "test_disabled", types.KeySpecEccNistP256, types.KeyUsageTypeSignVerify)
	client.setState(disabledID, types.KeyStateDisabled)
	otherID := client.mustAddKey(t, "other", types.KeySpecEccNistP384, types.KeyUsageTypeSignVerify)
	unlabelledID := client.mustAddKey(t, "", types.KeySpecEccNistP521, types.KeyUsageTypeSignVerify)
	allKeys := client.keyCount()

	cases := []struct {
		prefix string
		ids    []string
	}{
		{
			prefix: "",
			ids:    []string{rsaID, ecID, disabledID, otherID, unlabelledID},
		},
		{
			prefix: "test_",
			ids:    []string{rsaID, ecID, disabledID},
		},
		{
			prefix: "test_ec",
			ids:    []string{ecID},
		},
		{
			prefix: "test_encrypt",
			ids:    []string{},
		},
		{
			prefix: "test_deleted",
			ids:    []string{},
		},
		{
			prefix: "other",
			ids:    []string{otherID},
		},
		{
			prefix: "ther",
			ids:    []string{},
		},
		{
			prefix: "zzz",
			ids:    []string{},
		},
	}
	for _, tc := range cases {
		t.Run("prefix="+tc.prefix, func(t *testing.T) {
			keys, err := provider.EnumKeys(0, tc.prefix)
			require.NoError(t, err)
			assert.Equal(t, tc.ids, keyIDs(keys))
			assert.NotContains(t, keyIDs(keys), encryptID)
			assert.NotContains(t, keyIDs(keys), deletedID)
			for _, key := range keys {
				assert.Equal(t, key.Meta["description"], key.Label)
				assert.Equal(t, "SIGN_VERIFY", key.Meta["usage"])
				assert.NotNil(t, key.CreationTime)
			}
		})
	}

	keys, err := provider.EnumKeys(0, "test_")
	require.NoError(t, err)
	require.Len(t, keys, 3)
	assert.Equal(t, "test_rsa", keys[0].Label)
	assert.Equal(t, fmt.Sprintf("%v", rsaSigningAlgorithms), keys[0].Meta["algo"])
	assert.Equal(t, "test_disabled", keys[2].Label)
	assert.Equal(t, "false", keys[2].Meta["enabled"])
	assert.Equal(t, "Disabled", keys[2].Meta["state"])

	// every key is described once per listing, with the maximal page size
	listings := len(cases) + 1
	assert.Equal(t, listings, client.CallCount("ListKeys"))
	assert.Equal(t, listings*allKeys, client.CallCount("DescribeKey"))
}

// TestEnumKeysPagination checks that every page is listed, described and
// returned in order.
func TestEnumKeysPagination(t *testing.T) {
	t.Parallel()

	client := newFakeKMS()
	provider := newProvider(t, client)
	total := 2*awskmscrypto.ListKeysLimit + 5
	ids := addSigningKeys(t, client, total)

	keys, err := provider.EnumKeys(0, "key_")
	require.NoError(t, err)
	assert.Equal(t, ids, keyIDs(keys))
	assert.Equal(t, 3, client.CallCount("ListKeys"))
	assert.Equal(t, total, client.CallCount("DescribeKey"))

	keys, err = provider.EnumKeys(0, "key_1")
	require.NoError(t, err)
	assert.Len(t, keys, 1+10+100+1000, "key_1, key_1x, key_1xx, key_1xxx")
	assert.Equal(t, 2*total, client.CallCount("DescribeKey"))

	t.Run("empty account", func(t *testing.T) {
		keys, err := newProvider(t, newFakeKMS()).EnumKeys(0, "")
		require.NoError(t, err)
		assert.Empty(t, keys)
		assert.NotNil(t, keys)
	})
	t.Run("truncated without marker", func(t *testing.T) {
		client := newFakeKMS()
		id := client.mustAddKey(t, "key", types.KeySpecEccNistP256, types.KeyUsageTypeSignVerify)
		client.listKeys = func(*kms.ListKeysInput) (*kms.ListKeysOutput, error) {
			return &kms.ListKeysOutput{
				Keys:      []types.KeyListEntry{{KeyId: aws.String(id)}},
				Truncated: true,
			}, nil
		}
		keys, err := newProvider(t, client).EnumKeys(0, "")
		require.EqualError(t, err, "failed to list keys: page 1 is truncated without a marker")
		assert.Nil(t, keys, "no partial result")
		assert.Equal(t, 1, client.CallCount("ListKeys"))
	})
}

// TestEnumKeysErrors checks that a ListKeys or DescribeKey failure on any
// page and at any position fails the listing, with no partial result and
// with the service error identity kept, and that a key the caller may not
// describe is left out of the listing (XPKI-033).
func TestEnumKeysErrors(t *testing.T) {
	t.Parallel()

	total := awskmscrypto.ListKeysLimit + 10
	accessDenied := &smithy.GenericAPIError{
		Code:    "AccessDeniedException",
		Message: "not authorized",
		Fault:   smithy.FaultClient,
	}

	t.Run("list", func(t *testing.T) {
		t.Parallel()
		for _, failPage := range []int{1, 2} {
			client := newFakeKMS()
			addSigningKeys(t, client, total)
			client.listErr = func(page int) error {
				if page == failPage {
					return throttlingError()
				}
				return nil
			}

			keys, err := newProvider(t, client).EnumKeys(0, "")
			require.EqualError(t, err, "failed to list keys: api error ThrottlingException: Rate exceeded", "page %d", failPage)
			assert.Nil(t, keys)
			var apiErr smithy.APIError
			require.ErrorAs(t, err, &apiErr)
			assert.Equal(t, "ThrottlingException", apiErr.ErrorCode())
			assert.Equal(t, (failPage-1)*awskmscrypto.ListKeysLimit, client.CallCount("DescribeKey"), "keys of the pages before the failure are described")
		}
	})

	t.Run("describe", func(t *testing.T) {
		t.Parallel()
		for _, tc := range []struct {
			name string
			// index of the failing key in the listing
			index int
			err   error
			msg   string
		}{
			{
				name:  "first key throttled",
				index: 0,
				err:   throttlingError(),
				msg:   "api error ThrottlingException: Rate exceeded",
			},
			{
				name:  "middle key timed out",
				index: 500,
				err:   &types.DependencyTimeoutException{Message: aws.String("timed out")},
				msg:   "DependencyTimeoutException: timed out",
			},
			{
				name:  "last key of page 1",
				index: awskmscrypto.ListKeysLimit - 1,
				err:   &types.KMSInternalException{Message: aws.String("internal")},
				msg:   "KMSInternalException: internal",
			},
			{
				name:  "first key of page 2",
				index: awskmscrypto.ListKeysLimit,
				err:   &types.NotFoundException{Message: aws.String("gone")},
				msg:   "NotFoundException: gone",
			},
			{
				name:  "last key",
				index: total - 1,
				err:   errors.New("connection reset"),
				msg:   "connection reset",
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				client := newFakeKMS()
				ids := addSigningKeys(t, client, total)
				failID := ids[tc.index]
				client.describeErr = func(keyID string, _ int) error {
					if keyID == failID {
						return tc.err
					}
					return nil
				}
				provider := newProvider(t, client)
				// serial calls, so the number of calls is exact
				awskmscrypto.SetDescribeConcurrency(provider, 1)

				keys, err := provider.EnumKeys(0, "")
				require.EqualError(t, err, fmt.Sprintf("failed to describe key, id=%s, arn=%skey/%s: %s", failID, fakeArnBase, failID, tc.msg))
				assert.Nil(t, keys, "no partial result")
				require.ErrorIs(t, err, tc.err)
				assert.Equal(t, tc.index+1, client.CallCount("DescribeKey"), "the listing stops at the failure")
			})
		}
	})

	t.Run("access denied is not listed", func(t *testing.T) {
		t.Parallel()
		client := newFakeKMS()
		ids := addSigningKeys(t, client, total)
		denied := []string{ids[0], ids[7], ids[awskmscrypto.ListKeysLimit], ids[total-1]}
		client.describeErr = func(keyID string, _ int) error {
			if slices.Contains(denied, keyID) {
				return accessDenied
			}
			return nil
		}

		keys, err := newProvider(t, client).EnumKeys(0, "")
		require.NoError(t, err)
		expected := slices.DeleteFunc(slices.Clone(ids), func(id string) bool {
			return slices.Contains(denied, id)
		})
		assert.Equal(t, expected, keyIDs(keys), "the other keys are listed in order")
		assert.Equal(t, total, client.CallCount("DescribeKey"), "every key is described")
	})

	t.Run("describe concurrent", func(t *testing.T) {
		t.Parallel()
		client := newFakeKMS()
		ids := addSigningKeys(t, client, total)
		// the failing key waits until the ten keys before it were described,
		// so its failure is not the first event; the listing goes on meanwhile
		before := ids[:10]
		failID := ids[10]
		var described, callsAtFailure atomic.Int32
		allBefore := make(chan struct{})
		client.describeErr = func(keyID string, _ int) error {
			switch {
			case slices.Contains(before, keyID):
				if int(described.Add(1)) == len(before) {
					close(allBefore)
				}
			case keyID == failID:
				if err := awaitBarrier(allBefore); err != nil {
					return err
				}
				callsAtFailure.Store(int32(client.CallCount("DescribeKey")))
				return throttlingError()
			}
			return nil
		}
		// long enough that no slot turns over between the count and the
		// cancellation, so the bound below is exact
		client.describeDelay = 50 * time.Millisecond
		provider := newProvider(t, client)

		keys, err := provider.EnumKeys(0, "")
		require.ErrorContains(t, err, "failed to describe key, id="+failID)
		var apiErr smithy.APIError
		require.ErrorAs(t, err, &apiErr, "the failure is reported, not the cancellation of the other calls")
		assert.Equal(t, "ThrottlingException", apiErr.ErrorCode())
		assert.Nil(t, keys)
		calls := client.CallCount("DescribeKey")
		atFailure := int(callsAtFailure.Load())
		assert.GreaterOrEqual(t, atFailure, len(before)+1)
		assert.LessOrEqual(t, calls, atFailure+awskmscrypto.DescribeConcurrency-1, "calls in flight at the failure finish, no new one starts")
	})

	t.Run("empty responses", func(t *testing.T) {
		t.Parallel()
		client := newFakeKMS()
		ids := addSigningKeys(t, client, 3)
		provider := newProvider(t, client)

		client.listKeys = func(*kms.ListKeysInput) (*kms.ListKeysOutput, error) {
			return nil, nil
		}
		_, err := provider.EnumKeys(0, "")
		require.EqualError(t, err, "failed to list keys: empty response")
		client.listKeys = nil

		client.describeKey = func(*kms.DescribeKeyInput) (*kms.DescribeKeyOutput, error) {
			return &kms.DescribeKeyOutput{}, nil
		}
		awskmscrypto.SetDescribeConcurrency(provider, 1)
		_, err = provider.EnumKeys(0, "")
		require.EqualError(t, err, "failed to describe key, id="+ids[0]+": empty response")
	})
}

// TestEnumKeysConcurrency checks that DescribeKey calls run concurrently,
// bounded by the configured limit, and that the order of the listing does
// not depend on the order in which they complete.
func TestEnumKeysConcurrency(t *testing.T) {
	t.Parallel()

	total := 100
	for _, concurrency := range []int{1, 3, awskmscrypto.DescribeConcurrency} {
		t.Run("concurrency="+strconv.Itoa(concurrency), func(t *testing.T) {
			t.Parallel()
			client := newFakeKMS()
			ids := addSigningKeys(t, client, total)
			// the first calls wait for each other, so they are in flight
			// together and complete after later ones started
			var arrived atomic.Int32
			allArrived := make(chan struct{})
			client.describeErr = func(_ string, call int) error {
				if call > concurrency {
					return nil
				}
				if int(arrived.Add(1)) == concurrency {
					close(allArrived)
				}
				return awaitBarrier(allArrived)
			}
			client.describeDelay = time.Millisecond
			provider := newProvider(t, client)
			awskmscrypto.SetDescribeConcurrency(provider, concurrency)

			keys, err := provider.EnumKeys(0, "")
			require.NoError(t, err)
			assert.Equal(t, ids, keyIDs(keys))
			assert.Equal(t, total, client.CallCount("DescribeKey"))
			assert.Equal(t, int32(concurrency), client.peak.Load(), "peak concurrent DescribeKey calls")
		})
	}

	t.Run("zero concurrency is serial", func(t *testing.T) {
		t.Parallel()
		client := newFakeKMS()
		addSigningKeys(t, client, 2)
		client.describeDelay = time.Millisecond
		provider := newProvider(t, client)
		awskmscrypto.SetDescribeConcurrency(provider, 0)

		keys, err := provider.EnumKeys(0, "")
		require.NoError(t, err)
		assert.Len(t, keys, 2)
		assert.Equal(t, int32(1), client.peak.Load())
	})
}
