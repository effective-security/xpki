package awskmscrypto

import (
	"context"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi"
	tagtypes "github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi/types"
	"github.com/cockroachdb/errors"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/v2/certutil"
	"github.com/effective-security/xpki/v2/cryptoprov"
	"github.com/effective-security/xpki/v2/metricskey"
)

// The candidate sources of a listing. KMS has no search, so ListKeys picks
// the source that narrows the candidates most before it describes any key;
// the name is kept in the page token.
const (
	// sourceKeys is ListKeys: every key of the account and Region.
	sourceKeys = "keys"
	// sourceTags is GetResources with the tag filter of the request.
	sourceTags = "tags"
	// sourceAlias is DescribeKey on the alias of an exact label.
	sourceAlias = "alias"
	// sourceAliases is a ListAliases sweep for a label prefix.
	sourceAliases = "aliases"
	// sourceLabelTags is GetResources on the xpki-label tag. It follows an
	// alias source and adds the keys whose alias could not be created.
	sourceLabelTags = "labeltags"
)

// candidate is a key a source returned, with what is known about it so far.
type candidate struct {
	// index is the position in the page of the source, for the page token.
	index int
	id    string
	arn   string
	// alias is the alias sourceAliases found the key through.
	alias string
	// tags are the tags of the key; nil until they are known.
	tags map[string]string
	// meta is the metadata from a DescribeKey of this call; nil without
	// one.
	meta *types.KeyMetadata
	// imm is the immutable metadata, from meta or from the cache.
	imm *immutableMeta
	// skip marks a key that is not listed: the caller may not describe it,
	// it is gone, or another source of the listing returns it.
	skip bool
}

// candidatePage is one page of a source and the marker of the next one.
type candidatePage struct {
	items []*candidate
	next  string
}

// specTags is the key description the xpki tags carry.
type specTags struct {
	keyType string
	size    int
	usage   cryptoprov.KeyUsage
}

// specFromTags returns what the xpki-type, xpki-size and xpki-usage tags say
// about a key, and false when one is missing or malformed.
func specFromTags(tags map[string]string) (specTags, bool) {
	var spec specTags
	spec.keyType = tags[tagType]
	switch spec.keyType {
	case certutil.KeyTypeRSA, certutil.KeyTypeECDSA, certutil.KeyTypeMLDSA:
	default:
		return specTags{}, false
	}
	size, err := strconv.Atoi(tags[tagSize])
	if err != nil || size <= 0 {
		return specTags{}, false
	}
	spec.size = size
	usage, err := cryptoprov.ParseKeyUsage(tags[tagUsage])
	if err != nil || usage == 0 {
		return specTags{}, false
	}
	spec.usage = usage
	return spec, true
}

// keyIDFromArn returns the key id of a KMS key ARN, or "".
func keyIDFromArn(arn string) string {
	_, id, ok := strings.Cut(arn, keyArnResource)
	if !ok {
		return ""
	}
	return id
}

// listing is one ListKeys call.
type listing struct {
	p      *Provider
	req    *cryptoprov.ListKeysRequest
	source string
	limit  int

	// what the request needs for each returned key
	wantMeta  bool
	wantState bool
	wantTags  bool
	// what the filter reads
	filterSpec  bool
	filterLabel bool

	// aliasTargets caches, for sourceLabelTags, the key id an alias points
	// at ("" when there is none)
	aliasMu      sync.Mutex
	aliasTargets map[string]string
}

// sources returns the candidate sources of a listing with filter f, in the
// order the listing reads them.
func (p *Provider) sources(f *cryptoprov.KeyFilter) []string {
	hasLabel := f.Label != "" || f.LabelPrefix != ""
	switch {
	case len(f.Tags) > 0 && p.tagSearch():
		return []string{sourceTags}
	case hasLabel && !p.labelScan:
		first := sourceAliases
		if f.Label != "" {
			first = sourceAlias
		}
		// a label that is not a valid tag value has no xpki-label tag
		if p.tagSearch() && (f.Label == "" || validTagValue(f.Label)) {
			return []string{first, sourceLabelTags}
		}
		return []string{first}
	default:
		return []string{sourceKeys}
	}
}

// ListKeys returns one page of the keys of the account and Region.
//
// KMS has no search, so the call first picks a source of candidates:
//
//   - a tag filter with the TagSearch attribute: GetResources of the
//     Resource Groups Tagging API, 100 keys a page, each with its tags
//     (tag:GetResources);
//   - a label filter: DescribeKey on the alias of an exact label, or a
//     ListAliases sweep for a prefix (kms:ListAliases), followed with
//     TagSearch by the keys the xpki-label tag names. The label of a key is
//     its description, which every candidate is confirmed against, so a key
//     is found through the alias GenerateKey gave it; a key that has only a
//     matching description is not found unless the LabelSearch=scan
//     attribute makes the listing describe every key, as v1 did;
//   - otherwise ListKeys, 1000 ids a page (kms:ListKeys).
//
// It then makes only the requests the filter and req.Fields need, at most
// DescribeConcurrency at a time; the first failure cancels the rest and is
// returned wrapped, so errors.As still finds the service error, and there is
// no partial page (XPKI-033). A listing of ids without a filter makes none.
// Key spec, usage, creation date, origin and manager never change, so a
// filter on usage or type costs one DescribeKey the first time the provider
// sees a key and none afterwards (MetadataCacheSize). The label and the
// state can change and are read with DescribeKey (kms:DescribeKey) for the
// keys of the page; a key from the tagging API that has the xpki tags needs
// none for cryptoprov.KeyFieldMetadata, and is then listed without a
// creation time unless the provider described it before. Tags that the
// source did not return cost one ListResourceTags per key
// (kms:ListResourceTags). The xpki tags can be written by anyone with
// kms:TagResource: they feed listings only, never GetKey, KeyInfo or Sign.
//
// A call examines at most one page of its source, so a page can have fewer
// keys than req.PageSize, or none, and still a NextPageToken. A key the
// caller may not describe (AccessDeniedException), or that is gone, is not
// listed and is logged. Keys pending deletion are listed unless
// req.Filter.States excludes them.
func (p *Provider) ListKeys(ctx context.Context, req *cryptoprov.ListKeysRequest) (*cryptoprov.ListKeysResponse, error) {
	defer metricskey.PerfCryptoOperation.MeasureSince(time.Now(), ProviderName, "listkeys")

	if err := req.Validate(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.WithStack(err)
	}
	cursor, err := cryptoprov.ParsePageToken(req)
	if err != nil {
		return nil, err
	}

	sources := p.sources(&req.Filter)
	phase := 0
	if cursor.Source != "" {
		if phase = slices.Index(sources, cursor.Source); phase < 0 {
			return nil, errors.Wrapf(cryptoprov.ErrInvalidPageToken, "source %q", cursor.Source)
		}
	}

	filterFields := req.Filter.Fields()
	l := &listing{
		p:           p,
		req:         req,
		source:      sources[phase],
		limit:       req.Limit(listKeysLimit),
		wantMeta:    req.Fields.Has(cryptoprov.KeyFieldMetadata),
		wantState:   req.Fields.Has(cryptoprov.KeyFieldState) || filterFields.Has(cryptoprov.KeyFieldState),
		wantTags:    req.Fields.Has(cryptoprov.KeyFieldTags) || filterFields.Has(cryptoprov.KeyFieldTags),
		filterSpec:  req.Filter.Usage != 0 || len(req.Filter.Types) > 0,
		filterLabel: req.Filter.Label != "" || req.Filter.LabelPrefix != "",
	}
	logger.KV(xlog.DEBUG, "endpoint", p.endpoint, "source", l.source, "limit", l.limit)

	page, err := l.fetch(ctx, cursor.Marker)
	if err != nil {
		return nil, err
	}
	// the page may have lost candidates since the token was issued
	offset := min(cursor.Offset, len(page.items))
	keys, resume, err := l.evaluate(ctx, page.items[offset:])
	if err != nil {
		return nil, err
	}

	res := &cryptoprov.ListKeysResponse{Keys: keys}
	var next *cryptoprov.PageCursor
	switch {
	case resume >= 0:
		// the page has more candidates than the caller asked keys for
		next = &cryptoprov.PageCursor{
			Source: l.source,
			Marker: cursor.Marker,
			Offset: resume,
		}
	case page.next != "":
		next = &cryptoprov.PageCursor{
			Source: l.source,
			Marker: page.next,
		}
	case phase+1 < len(sources):
		next = &cryptoprov.PageCursor{
			Source: sources[phase+1],
		}
	}
	if next != nil {
		if res.NextPageToken, err = cryptoprov.NewPageToken(req, *next); err != nil {
			return nil, err
		}
	}
	logger.KV(xlog.DEBUG, "source", l.source, "candidates", len(page.items), "keys", len(keys))
	return res, nil
}

// fetch returns the page of the listing's source at marker.
func (l *listing) fetch(ctx context.Context, marker string) (*candidatePage, error) {
	switch l.source {
	case sourceTags:
		filters := make([]tagtypes.TagFilter, 0, len(l.req.Filter.Tags))
		for name, value := range l.req.Filter.Tags {
			filters = append(filters, tagtypes.TagFilter{
				Key:    aws.String(name),
				Values: []string{value},
			})
		}
		slices.SortFunc(filters, func(a, b tagtypes.TagFilter) int {
			return strings.Compare(aws.ToString(a.Key), aws.ToString(b.Key))
		})
		return l.fetchResources(ctx, marker, filters)
	case sourceLabelTags:
		filter := tagtypes.TagFilter{Key: aws.String(tagLabel)}
		if l.req.Filter.Label != "" {
			filter.Values = []string{l.req.Filter.Label}
		}
		return l.fetchResources(ctx, marker, []tagtypes.TagFilter{filter})
	case sourceAlias:
		return l.fetchAlias(ctx)
	case sourceAliases:
		return l.fetchAliases(ctx, marker)
	default:
		return l.fetchKeys(ctx, marker)
	}
}

// fetchKeys returns a ListKeys page. Without a filter every candidate is
// returned, so the page is as long as the caller's; with one it is the KMS
// maximum, always the same, so that a page token can point into it.
func (l *listing) fetchKeys(ctx context.Context, marker string) (*candidatePage, error) {
	limit := listKeysLimit
	if l.req.Filter.IsZero() {
		limit = l.limit
	}
	input := &kms.ListKeysInput{
		Limit: aws.Int32(int32(limit)),
	}
	if marker != "" {
		input.Marker = aws.String(marker)
	}
	out, err := l.p.kmsClient.ListKeys(ctx, input)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to list keys")
	}
	if out == nil {
		return nil, errors.Wrap(errEmptyResponse, "failed to list keys")
	}
	page := &candidatePage{
		items: make([]*candidate, 0, len(out.Keys)),
	}
	for _, key := range out.Keys {
		page.items = append(page.items, &candidate{
			id:  aws.ToString(key.KeyId),
			arn: aws.ToString(key.KeyArn),
		})
	}
	if out.Truncated {
		if page.next = aws.ToString(out.NextMarker); page.next == "" {
			return nil, errors.New("failed to list keys: the page is truncated without a marker")
		}
	}
	return page.indexed(), nil
}

// fetchResources returns a GetResources page of the KMS keys that pass the
// tag filters; each candidate has its tags.
func (l *listing) fetchResources(ctx context.Context, marker string, filters []tagtypes.TagFilter) (*candidatePage, error) {
	input := &resourcegroupstaggingapi.GetResourcesInput{
		ResourceTypeFilters: []string{kmsKeyResourceType},
		ResourcesPerPage:    aws.Int32(resourcesPerPage),
		TagFilters:          filters,
	}
	if marker != "" {
		input.PaginationToken = aws.String(marker)
	}
	out, err := l.p.tagClient.GetResources(ctx, input)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to get tagged keys")
	}
	if out == nil {
		return nil, errors.Wrap(errEmptyResponse, "failed to get tagged keys")
	}
	page := &candidatePage{
		items: make([]*candidate, 0, len(out.ResourceTagMappingList)),
		next:  aws.ToString(out.PaginationToken),
	}
	for _, mapping := range out.ResourceTagMappingList {
		arn := aws.ToString(mapping.ResourceARN)
		id := keyIDFromArn(arn)
		if id == "" {
			continue
		}
		tags := make(map[string]string, len(mapping.Tags))
		for _, tag := range mapping.Tags {
			tags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
		}
		page.items = append(page.items, &candidate{
			id:   id,
			arn:  arn,
			tags: tags,
		})
	}
	return page.indexed(), nil
}

// fetchAlias returns the key the alias of the exact label points at, if
// there is one the caller may describe.
func (l *listing) fetchAlias(ctx context.Context) (*candidatePage, error) {
	page := &candidatePage{}
	alias := aliasFromLabel(l.req.Filter.Label)
	if alias == aliasPrefix {
		return page, nil
	}
	meta, err := l.p.describeKey(ctx, alias)
	if err != nil {
		if errors.Is(err, cryptoprov.ErrKeyNotFound) {
			return page, nil
		}
		if isAccessDenied(err) {
			logger.KV(xlog.WARNING, "reason", "DescribeKey", "alias", alias, "err", err.Error())
			return page, nil
		}
		return nil, err
	}
	page.items = append(page.items, &candidate{
		id:   aws.ToString(meta.KeyId),
		arn:  aws.ToString(meta.Arn),
		meta: meta,
		imm:  immutableOf(meta),
	})
	return page.indexed(), nil
}

// fetchAliases returns the keys a ListAliases page points at through an
// alias that starts with the alias of the label prefix.
func (l *listing) fetchAliases(ctx context.Context, marker string) (*candidatePage, error) {
	input := &kms.ListAliasesInput{
		Limit: aws.Int32(listAliasesLimit),
	}
	if marker != "" {
		input.Marker = aws.String(marker)
	}
	out, err := l.p.kmsClient.ListAliases(ctx, input)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to list aliases")
	}
	if out == nil {
		return nil, errors.Wrap(errEmptyResponse, "failed to list aliases")
	}
	page := &candidatePage{}
	prefix := aliasFromLabel(l.req.Filter.LabelPrefix)
	for _, entry := range out.Aliases {
		name := aws.ToString(entry.AliasName)
		target := aws.ToString(entry.TargetKeyId)
		if target == "" || !strings.HasPrefix(name, prefix) {
			continue
		}
		page.items = append(page.items, &candidate{
			id:    target,
			alias: name,
		})
	}
	if out.Truncated {
		if page.next = aws.ToString(out.NextMarker); page.next == "" {
			return nil, errors.New("failed to list aliases: the page is truncated without a marker")
		}
	}
	return page.indexed(), nil
}

// indexed numbers the candidates of the page.
func (page *candidatePage) indexed() *candidatePage {
	for i, c := range page.items {
		c.index = i
	}
	return page
}

// evaluate turns candidates, in order, into the keys of the page: it drops
// those the filter rejects, makes the requests the rest need, and stops at
// the page limit. resume is the index of the first candidate it did not
// examine, or -1 when it examined them all.
//
// It works through the candidates in chunks, so that a page that fills early
// costs no request for the candidates after it. A filter on usage or type
// reads immutable metadata: the keys of a chunk that are neither in the
// cache nor described by xpki tags are described once. The survivors are
// then resolved, never more of them than keys still wanted.
func (l *listing) evaluate(ctx context.Context, cands []*candidate) (keys []cryptoprov.KeyInfo, resume int, err error) {
	f := &l.req.Filter

	// what is known without a request
	known := cands[:0:0]
	for _, c := range cands {
		if c.imm == nil {
			c.imm = l.p.metaCache.get(c.id)
		}
		if c.tags != nil && !tagsMatch(f.Tags, c.tags) {
			continue
		}
		if l.source == sourceLabelTags && !labelMatches(f, c.tags[tagLabel]) {
			continue
		}
		known = append(known, c)
	}
	cands = known

	keys = make([]cryptoprov.KeyInfo, 0, min(l.limit, len(cands)))
	// cands[:next] have passed or failed the usage and type conditions;
	// pending are those that passed and are not resolved yet
	next := 0
	var pending []*candidate
	for len(keys) < l.limit {
		wanted := l.limit - len(keys)
		for len(pending) < wanted && next < len(cands) {
			chunk := cands[next:min(next+max(wanted, l.p.describeConcurrency), len(cands))]
			next += len(chunk)
			if !l.filterSpec {
				pending = append(pending, chunk...)
				continue
			}
			passed, err := l.filterBySpec(ctx, chunk)
			if err != nil {
				return nil, 0, err
			}
			pending = append(pending, passed...)
		}
		if len(pending) == 0 {
			break
		}

		batch := pending[:min(wanted, len(pending))]
		pending = pending[len(batch):]
		if err := l.p.forEach(ctx, len(batch), func(ctx context.Context, i int) error {
			return l.resolve(ctx, batch[i])
		}); err != nil {
			return nil, 0, err
		}
		for _, c := range batch {
			if c.skip {
				continue
			}
			ki := c.keyInfo()
			if !f.Match(ki) {
				continue
			}
			// a key is listed through the alias its label gives it, so one
			// with several matching aliases is listed once
			if l.source == sourceAliases && aliasFromLabel(ki.Label) != c.alias {
				continue
			}
			keys = append(keys, *ki)
		}
	}
	switch {
	case len(pending) > 0:
		return keys, pending[0].index, nil
	case next < len(cands):
		return keys, cands[next].index, nil
	default:
		return keys, -1, nil
	}
}

// filterBySpec returns the candidates of chunk that pass the usage and type
// conditions of the filter, in order. The keys whose spec is not known are
// described first; one the caller may not describe is dropped.
func (l *listing) filterBySpec(ctx context.Context, chunk []*candidate) ([]*candidate, error) {
	var unknown []*candidate
	for _, c := range chunk {
		if _, ok := c.spec(); !ok {
			unknown = append(unknown, c)
		}
	}
	if err := l.p.forEach(ctx, len(unknown), func(ctx context.Context, i int) error {
		return l.describe(ctx, unknown[i])
	}); err != nil {
		return nil, err
	}
	passed := chunk[:0:0]
	for _, c := range chunk {
		spec, ok := c.spec()
		if c.skip || !ok || !specMatches(&l.req.Filter, spec) {
			continue
		}
		passed = append(passed, c)
	}
	return passed, nil
}

// resolve makes the requests the listing needs for c beyond what is already
// known, or marks it skipped.
func (l *listing) resolve(ctx context.Context, c *candidate) error {
	if l.source == sourceLabelTags {
		// the alias source of this listing returned the key its alias
		// points at
		target, err := l.aliasTarget(ctx, aliasFromLabel(c.tags[tagLabel]))
		if err != nil {
			return err
		}
		if target == c.id {
			c.skip = true
			return nil
		}
	}

	if c.meta == nil && l.needsDescribe(c) {
		if err := l.describe(ctx, c); err != nil || c.skip {
			return err
		}
	}
	if c.tags == nil && l.wantTags {
		tags, err := l.p.resourceTags(ctx, c.id)
		if err != nil {
			if !isAccessDenied(err) && !errors.Is(err, cryptoprov.ErrKeyNotFound) {
				return err
			}
			logger.KV(xlog.WARNING, "reason", "ListResourceTags", "id", c.id, "err", err.Error())
			c.skip = true
			return nil
		}
		c.tags = tags
	}
	return nil
}

// needsDescribe reports whether the listing needs a DescribeKey for c: for
// the state, for a label filter (the label is the description, which a tag
// only mirrors), for the label of the Metadata group when no xpki-label tag
// has it, and for the key spec when neither the cache nor the xpki tags
// have it.
func (l *listing) needsDescribe(c *candidate) bool {
	if l.wantState || l.filterLabel {
		return true
	}
	if !l.wantMeta {
		return false
	}
	if _, hasLabel := c.tags[tagLabel]; !hasLabel {
		return true
	}
	_, hasSpec := c.spec()
	return !hasSpec
}

// describe reads the metadata of c. A key the caller may not describe, or
// that is gone, is skipped and logged, as in v1.
func (l *listing) describe(ctx context.Context, c *candidate) error {
	resp, err := l.p.kmsClient.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String(c.id)})
	if err != nil {
		var notFound *types.NotFoundException
		if isAccessDenied(err) || errors.As(err, &notFound) {
			logger.KV(xlog.WARNING, "reason", "DescribeKey", "id", c.id, "arn", c.arn, "err", err.Error())
			c.skip = true
			return nil
		}
		return errors.WithMessagef(err, "failed to describe key, id=%s, arn=%s", c.id, c.arn)
	}
	if resp == nil || resp.KeyMetadata == nil {
		return errors.Wrapf(errEmptyResponse, "failed to describe key, id=%s", c.id)
	}
	c.meta = resp.KeyMetadata
	c.imm = immutableOf(c.meta)
	l.p.metaCache.put(c.id, c.imm)
	return nil
}

// aliasTarget returns the id of the key alias points at, or "" when there
// is none the caller may describe. A listing asks once per alias.
func (l *listing) aliasTarget(ctx context.Context, alias string) (string, error) {
	if alias == aliasPrefix {
		return "", nil
	}
	l.aliasMu.Lock()
	target, ok := l.aliasTargets[alias]
	l.aliasMu.Unlock()
	if ok {
		return target, nil
	}

	meta, err := l.p.describeKey(ctx, alias)
	switch {
	case err == nil:
		target = aws.ToString(meta.KeyId)
	case errors.Is(err, cryptoprov.ErrKeyNotFound), isAccessDenied(err):
	default:
		return "", err
	}

	l.aliasMu.Lock()
	if l.aliasTargets == nil {
		l.aliasTargets = make(map[string]string)
	}
	l.aliasTargets[alias] = target
	l.aliasMu.Unlock()
	return target, nil
}

// spec returns the type, size and usage of c from its metadata, or from the
// xpki tags when the provider has not described the key.
func (c *candidate) spec() (specTags, bool) {
	if c.imm != nil {
		info := keySpecs[c.imm.spec]
		return specTags{
			keyType: info.keyType,
			size:    info.size,
			usage:   keyUsage(c.imm.usage),
		}, true
	}
	return specFromTags(c.tags)
}

// keyInfo returns the KeyInfo of c with everything known about it.
func (c *candidate) keyInfo() *cryptoprov.KeyInfo {
	var ki *cryptoprov.KeyInfo
	switch {
	case c.meta != nil:
		ki = describedKeyInfo(c.meta)
	case c.imm != nil:
		ki = &cryptoprov.KeyInfo{
			ID:   c.id,
			Meta: c.imm.meta(),
		}
		c.imm.fill(ki)
	default:
		ki = &cryptoprov.KeyInfo{ID: c.id}
		if spec, ok := specFromTags(c.tags); ok {
			ki.Type = spec.keyType
			ki.Size = spec.size
			ki.Usage = spec.usage
		}
	}
	if c.meta == nil {
		ki.Label = c.tags[tagLabel]
	}
	if ki.Name == "" {
		ki.Name = c.arn
	}
	ki.Tags = c.tags
	return ki
}

// tagsMatch reports whether tags has every tag of want with its value.
func tagsMatch(want, tags map[string]string) bool {
	for name, value := range want {
		if got, ok := tags[name]; !ok || got != value {
			return false
		}
	}
	return true
}

// labelMatches reports whether label passes the label conditions of f.
func labelMatches(f *cryptoprov.KeyFilter, label string) bool {
	if f.Label != "" && label != f.Label {
		return false
	}
	return strings.HasPrefix(label, f.LabelPrefix)
}

// specMatches reports whether a key of spec passes the usage and type
// conditions of f.
func specMatches(f *cryptoprov.KeyFilter, spec specTags) bool {
	if f.Usage != 0 && spec.usage&f.Usage == 0 {
		return false
	}
	return len(f.Types) == 0 || slices.Contains(f.Types, spec.keyType)
}

// forEach calls fn for 0 to n-1, at most p.describeConcurrency calls at a
// time. The first failure cancels the context of the calls in flight, stops
// the remaining ones and is returned.
func (p *Provider) forEach(ctx context.Context, n int, fn func(ctx context.Context, i int) error) error {
	if n == 0 {
		return nil
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		once     sync.Once
		firstErr error
		wg       sync.WaitGroup
	)
	fail := func(err error) {
		once.Do(func() {
			firstErr = err
			cancel()
		})
	}

	sem := make(chan struct{}, max(p.describeConcurrency, 1))
	for i := range n {
		sem <- struct{}{}
		if ctx.Err() != nil {
			// a call failed, or the caller gave up, while waiting for a slot
			<-sem
			break
		}
		wg.Go(func() {
			defer func() { <-sem }()
			if ctx.Err() != nil {
				return
			}
			if err := fn(ctx, i); err != nil {
				fail(err)
			}
		})
	}
	wg.Wait()
	if firstErr != nil {
		return firstErr
	}
	// the caller's context ended without a call reporting it
	return errors.WithStack(ctx.Err())
}
