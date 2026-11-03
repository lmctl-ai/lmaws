// SPDX-License-Identifier: MIT

package aws

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/lmctl-ai/lmcloud/hostkit"
	"github.com/lmctl-ai/lmcloud/hostkit/safety"
)

const (
	attrPK           = "pk"
	attrSK           = "sk"
	attrVersion      = "__lmcloud_v"
	attrTypeManifest = "__lmt"
	floatTypeTag     = "number"
	metaTableName    = "lmcloudmeta"

	tableWaitTimeout  = 60 * time.Second
	tableWaitInterval = 50 * time.Millisecond
)

func newVersionToken() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err == nil {
		return hex.EncodeToString(b[:])
	}
	return safety.NewToken128()
}

func (r *remote) tableLayoutCacheKey(ctx context.Context, table string) string {
	return strings.TrimSpace(hostkit.EndpointFrom(ctx)) + "|" + table
}

func (r *remote) setTableLayout(ctx context.Context, table string, sorted bool) {
	r.mu.Lock()
	if r.tableLayouts == nil {
		r.tableLayouts = make(map[string]bool)
	}
	r.tableLayouts[r.tableLayoutCacheKey(ctx, table)] = sorted
	r.mu.Unlock()
}

func (r *remote) getTableLayout(ctx context.Context, table string) (bool, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.tableLayouts == nil {
		return false, false
	}
	s, ok := r.tableLayouts[r.tableLayoutCacheKey(ctx, table)]
	return s, ok
}

func (r *remote) deleteTableLayout(ctx context.Context, table string) {
	r.mu.Lock()
	if r.tableLayouts != nil {
		delete(r.tableLayouts, r.tableLayoutCacheKey(ctx, table))
	}
	r.mu.Unlock()
}

type ddbTableMeta struct {
	sorted           bool
	status           types.TableStatus
	arn              string
	incarnationToken string
}

func isTableSorted(ks []types.KeySchemaElement) bool {
	for _, k := range ks {
		if k.KeyType == types.KeyTypeRange && aws.ToString(k.AttributeName) == attrSK {
			return true
		}
	}
	return len(ks) > 1
}

func (r *remote) describeTableRaw(ctx context.Context, name string) (ddbTableMeta, error) {
	cli := r.ddbClient(ctx)
	var out *dynamodb.DescribeTableOutput
	err := r.doAWS(ctx, true, func(ctx context.Context) error {
		var dErr error
		out, dErr = cli.DescribeTable(ctx, &dynamodb.DescribeTableInput{
			TableName: aws.String(name),
		})
		return dErr
	})
	if err != nil {
		ce := classify(err, scopeTable)
		if ce.Code == hostkit.NotFound {
			return ddbTableMeta{}, ce.WithAbsent(hostkit.AbsentTable)
		}
		return ddbTableMeta{}, ce
	}
	if out == nil || out.Table == nil {
		return ddbTableMeta{}, hostkit.ProviderError(hostkit.NotFound, 400, "ResourceNotFoundException", "table not found").WithAbsent(hostkit.AbsentTable)
	}
	td := out.Table
	if td.TableStatus == types.TableStatusDeleting {
		return ddbTableMeta{}, hostkit.ProviderError(hostkit.NotFound, 400, "ResourceNotFoundException", "table is deleting").WithAbsent(hostkit.AbsentTable)
	}
	sorted := isTableSorted(td.KeySchema)
	r.setTableLayout(ctx, name, sorted)

	incTok := strings.TrimSpace(aws.ToString(td.TableId))
	if incTok == "" {
		incTok = strings.TrimSpace(aws.ToString(td.TableArn))
	}
	if incTok == "" && td.CreationDateTime != nil {
		incTok = strconv.FormatInt(td.CreationDateTime.UnixNano(), 10)
	}
	if incTok == "" {
		incTok = name
	}
	return ddbTableMeta{
		sorted:           sorted,
		status:           td.TableStatus,
		arn:              strings.TrimSpace(aws.ToString(td.TableArn)),
		incarnationToken: incTok,
	}, nil
}

func (r *remote) waitTableActive(ctx context.Context, name string, initialStatus types.TableStatus) error {
	if initialStatus == types.TableStatusActive {
		return nil
	}
	noHookCtx := hostkit.WithRetryHooks(ctx, hostkit.RetryHooks{})
	return hostkit.WaitLoop(noHookCtx, tableWaitTimeout, tableWaitInterval, time.Now, nil, func(ctx context.Context) (int, error) {
		meta, err := r.describeTableRaw(ctx, name)
		if err != nil {
			return 0, err
		}
		if meta.status == types.TableStatusActive {
			return 1, nil
		}
		return 0, nil
	})
}

func (r *remote) DescribeTable(ctx context.Context, name string) (hostkit.TableInfo, error) {
	r.recordCall("DescribeTable", false)
	meta, err := r.describeTableRaw(ctx, name)
	if err != nil {
		return hostkit.TableInfo{}, err
	}
	return hostkit.TableInfo{
		Sorted:      meta.sorted,
		CreateToken: meta.incarnationToken,
	}, nil
}

func (r *remote) TableCreateToken(ctx context.Context, name string) (string, error) {
	r.recordCall("TableCreateToken", false)
	noHookCtx := hostkit.WithRetryHooks(ctx, hostkit.RetryHooks{})
	meta, err := r.describeTableRaw(noHookCtx, name)
	if err != nil {
		return "", err
	}
	if meta.arn == "" {
		return "", nil
	}
	cli := r.ddbClient(noHookCtx)
	var out *dynamodb.ListTagsOfResourceOutput
	tErr := r.doAWS(noHookCtx, true, func(ctx context.Context) error {
		var callErr error
		out, callErr = cli.ListTagsOfResource(ctx, &dynamodb.ListTagsOfResourceInput{
			ResourceArn: aws.String(meta.arn),
		})
		return callErr
	})
	if tErr != nil {
		return "", classify(tErr, scopeTable)
	}
	if out == nil {
		return "", nil
	}
	for _, tag := range out.Tags {
		k := strings.TrimSpace(aws.ToString(tag.Key))
		if k == createTokenTagKey || k == safety.TagKeyCreateToken {
			return strings.TrimSpace(aws.ToString(tag.Value)), nil
		}
	}
	return "", nil
}

func (r *remote) CreateTable(ctx context.Context, name string, sorted bool) (bool, error) {
	r.recordCall("CreateTable", true)
	cli := r.ddbClient(ctx)

	attrDefs := []types.AttributeDefinition{
		{
			AttributeName: aws.String(attrPK),
			AttributeType: types.ScalarAttributeTypeS,
		},
	}
	keySchema := []types.KeySchemaElement{
		{
			AttributeName: aws.String(attrPK),
			KeyType:       types.KeyTypeHash,
		},
	}
	if sorted {
		attrDefs = append(attrDefs, types.AttributeDefinition{
			AttributeName: aws.String(attrSK),
			AttributeType: types.ScalarAttributeTypeS,
		})
		keySchema = append(keySchema, types.KeySchemaElement{
			AttributeName: aws.String(attrSK),
			KeyType:       types.KeyTypeRange,
		})
	}

	in := &dynamodb.CreateTableInput{
		TableName:            aws.String(name),
		AttributeDefinitions: attrDefs,
		KeySchema:            keySchema,
		BillingMode:          types.BillingModePayPerRequest,
	}
	tok := strings.TrimSpace(hostkit.CreateToken(ctx))
	if tok != "" {
		in.Tags = []types.Tag{
			{
				Key:   aws.String(createTokenTagKey),
				Value: aws.String(tok),
			},
		}
	}

	var out *dynamodb.CreateTableOutput
	err := r.doAWS(ctx, true, func(ctx context.Context) error {
		var cErr error
		out, cErr = cli.CreateTable(ctx, in)
		return cErr
	})
	if err == nil {
		r.setTableLayout(ctx, name, sorted)
		var status types.TableStatus
		if out != nil && out.TableDescription != nil {
			status = out.TableDescription.TableStatus
		}
		if wErr := r.waitTableActive(ctx, name, status); wErr != nil {
			return false, wErr
		}
		return true, nil
	}

	ce := classify(err, scopeTable)
	if ce.Code != hostkit.Conflict {
		return false, ce
	}

	noHookCtx := hostkit.WithRetryHooks(ctx, hostkit.RetryHooks{})
	meta, descErr := r.describeTableRaw(noHookCtx, name)
	if descErr != nil {
		var dce *hostkit.CloudError
		if errors.As(descErr, &dce) && (dce.Code == hostkit.PermissionDenied || dce.Code == hostkit.Unauthenticated) {
			return false, dce
		}
		return false, ce
	}
	if meta.sorted != sorted {
		return false, hostkit.ProviderError(
			hostkit.Conflict,
			ce.HTTPStatus,
			"ResourceInUseException",
			fmt.Sprintf("table %q already exists with a different key layout", name),
		)
	}
	if wErr := r.waitTableActive(noHookCtx, name, meta.status); wErr != nil {
		return false, wErr
	}
	if tok != "" {
		if gotTok, tErr := r.TableCreateToken(noHookCtx, name); tErr == nil && gotTok != "" && gotTok == tok {
			return true, nil
		}
	}
	return false, nil
}

func (r *remote) DeleteTable(ctx context.Context, name string) error {
	r.recordCall("DeleteTable", true)
	cli := r.ddbClient(ctx)
	err := r.doAWS(ctx, true, func(ctx context.Context) error {
		_, dErr := cli.DeleteTable(ctx, &dynamodb.DeleteTableInput{
			TableName: aws.String(name),
		})
		return dErr
	})
	r.deleteTableLayout(ctx, name)
	if err != nil {
		ce := classify(err, scopeTable)
		if ce.Code == hostkit.NotFound {
			return ce.WithAbsent(hostkit.AbsentTable)
		}
		return ce
	}
	return nil
}

func (r *remote) HeadTable(ctx context.Context, name string) error {
	r.recordCall("HeadTable", false)
	_, err := r.describeTableRaw(ctx, name)
	return err
}

func (r *remote) ListTables(ctx context.Context, token string) ([]string, string, error) {
	r.recordCall("ListTables", false)
	cli := r.ddbClient(ctx)
	in := &dynamodb.ListTablesInput{}
	if token != "" {
		in.ExclusiveStartTableName = aws.String(token)
	}
	var out *dynamodb.ListTablesOutput
	err := r.doAWS(ctx, true, func(ctx context.Context) error {
		var lErr error
		out, lErr = cli.ListTables(ctx, in)
		return lErr
	})
	if err != nil {
		return nil, "", classify(err, scopeTable)
	}
	names := make([]string, 0, len(out.TableNames))
	for _, n := range out.TableNames {
		if n == metaTableName {
			continue
		}
		names = append(names, n)
	}
	return names, aws.ToString(out.LastEvaluatedTableName), nil
}

func buildKeyAV(pk, sk string) map[string]types.AttributeValue {
	key := map[string]types.AttributeValue{
		attrPK: &types.AttributeValueMemberS{Value: pk},
	}
	if sk != "" {
		key[attrSK] = &types.AttributeValueMemberS{Value: sk}
	}
	return key
}

func attrToDDB(a hostkit.Attr) (types.AttributeValue, bool, *hostkit.CloudError) {
	switch {
	case a.S != nil:
		return &types.AttributeValueMemberS{Value: *a.S}, false, nil
	case a.I != nil:
		return &types.AttributeValueMemberN{Value: strconv.FormatInt(*a.I, 10)}, false, nil
	case a.N != nil:
		return &types.AttributeValueMemberN{Value: strconv.FormatFloat(*a.N, 'g', -1, 64)}, true, nil
	case a.B != nil:
		return &types.AttributeValueMemberBOOL{Value: *a.B}, false, nil
	default:
		return nil, false, hostkit.ProviderError(hostkit.InvalidArgument, 0, "InvalidAttributeValue", "attribute has no value")
	}
}

func encodeDDBItem(item hostkit.Item, version string) (map[string]types.AttributeValue, *hostkit.CloudError) {
	av := make(map[string]types.AttributeValue, len(item.Attrs)+4)
	av[attrPK] = &types.AttributeValueMemberS{Value: item.PK}
	if item.SK != "" {
		av[attrSK] = &types.AttributeValueMemberS{Value: item.SK}
	}
	av[attrVersion] = &types.AttributeValueMemberS{Value: version}

	lmt := make(map[string]types.AttributeValue)
	for k, a := range item.Attrs {
		v, isFloat, cerr := attrToDDB(a)
		if cerr != nil {
			return nil, cerr
		}
		av[k] = v
		if isFloat {
			lmt[k] = &types.AttributeValueMemberS{Value: floatTypeTag}
		}
	}
	// Always store __lmt as a Map (even when empty) so subsequent UpdateItem
	// expressions can atomically SET #lmt.#attr = :numtag or REMOVE #lmt.#attr
	// without failing on a missing intermediate document path.
	av[attrTypeManifest] = &types.AttributeValueMemberM{Value: lmt}
	return av, nil
}

func decodeDDBItem(av map[string]types.AttributeValue) (hostkit.Item, *hostkit.CloudError) {
	if len(av) == 0 {
		return hostkit.Item{}, nil
	}
	var out hostkit.Item
	out.Exists = true
	out.Attrs = make(map[string]hostkit.Attr)

	if pkAttr, ok := av[attrPK].(*types.AttributeValueMemberS); ok {
		out.PK = pkAttr.Value
	}
	if skAttr, ok := av[attrSK].(*types.AttributeValueMemberS); ok {
		out.SK = skAttr.Value
	}
	if vAttr, ok := av[attrVersion].(*types.AttributeValueMemberS); ok {
		out.Version = vAttr.Value
	}

	floatAttrs := make(map[string]bool)
	if lmtAttr, ok := av[attrTypeManifest].(*types.AttributeValueMemberM); ok {
		for k, tv := range lmtAttr.Value {
			if sv, ok := tv.(*types.AttributeValueMemberS); ok && sv.Value == floatTypeTag {
				floatAttrs[k] = true
			}
		}
	}

	for k, v := range av {
		if k == attrPK || k == attrSK || k == attrVersion || k == attrTypeManifest || strings.HasPrefix(k, "__lm") {
			continue
		}
		switch tv := v.(type) {
		case *types.AttributeValueMemberS:
			out.Attrs[k] = hostkit.StringAttr(tv.Value)
		case *types.AttributeValueMemberBOOL:
			out.Attrs[k] = hostkit.BoolAttr(tv.Value)
		case *types.AttributeValueMemberN:
			if floatAttrs[k] {
				f, err := strconv.ParseFloat(tv.Value, 64)
				if err != nil {
					return hostkit.Item{}, hostkit.ProviderError(hostkit.Internal, 0, "InvalidProviderNumber", fmt.Sprintf("invalid float attribute %q=%q: %v", k, tv.Value, err))
				}
				out.Attrs[k] = hostkit.NumberAttr(f)
			} else {
				iv, err := strconv.ParseInt(tv.Value, 10, 64)
				if err != nil {
					f, ferr := strconv.ParseFloat(tv.Value, 64)
					if ferr != nil {
						return hostkit.Item{}, hostkit.ProviderError(hostkit.Internal, 0, "InvalidProviderNumber", fmt.Sprintf("invalid numeric attribute %q=%q: %v", k, tv.Value, err))
					}
					out.Attrs[k] = hostkit.NumberAttr(f)
				} else {
					out.Attrs[k] = hostkit.IntAttr(iv)
				}
			}
		default:
			return hostkit.Item{}, hostkit.ProviderError(hostkit.Internal, 0, "UnsupportedProviderAttributeType", fmt.Sprintf("unsupported attribute type on %q", k))
		}
	}
	return out, nil
}

func billableBytesFromAV(av map[string]types.AttributeValue) (int64, bool) {
	if len(av) == 0 {
		return 0, false
	}
	it, cerr := decodeDDBItem(av)
	if cerr != nil {
		return hostkit.MaxNativeItemBillableBytes, true
	}
	return hostkit.NativeItemBillableBytes(it), true
}

func (r *remote) checkCachedKeyLayout(ctx context.Context, table, sk string) *hostkit.CloudError {
	sorted, ok := r.getTableLayout(ctx, table)
	if !ok {
		return nil
	}
	if sorted && sk == "" {
		return hostkit.Preflightf("table %q has a composite key and requires a sort key (sk)", table)
	}
	if !sorted && sk != "" {
		return hostkit.Preflightf("table %q is partition-key-only and does not accept a sort key (sk)", table)
	}
	return nil
}

func (r *remote) PutItem(ctx context.Context, table string, item hostkit.Item, mode hostkit.PutMode, expectVersion string) (hostkit.Item, error) {
	r.recordCall("PutItem", true)
	if cerr := r.checkCachedKeyLayout(ctx, table, item.SK); cerr != nil {
		return hostkit.Item{}, cerr
	}

	version := newVersionToken()
	av, cerr := encodeDDBItem(item, version)
	if cerr != nil {
		return hostkit.Item{}, cerr
	}

	in := &dynamodb.PutItemInput{
		TableName:    aws.String(table),
		Item:         av,
		ReturnValues: types.ReturnValueAllOld,
	}

	idempotent := false
	switch mode {
	case hostkit.PutUnconditional:
		idempotent = true
	case hostkit.PutIfAbsent:
		in.ConditionExpression = aws.String("attribute_not_exists(#pk)")
		in.ExpressionAttributeNames = map[string]string{
			"#pk": attrPK,
		}
		in.ReturnValuesOnConditionCheckFailure = types.ReturnValuesOnConditionCheckFailureAllOld
	case hostkit.PutIfVersion:
		in.ConditionExpression = aws.String("attribute_exists(#pk) AND #v = :v")
		in.ExpressionAttributeNames = map[string]string{
			"#pk": attrPK,
			"#v":  attrVersion,
		}
		in.ExpressionAttributeValues = map[string]types.AttributeValue{
			":v": &types.AttributeValueMemberS{Value: expectVersion},
		}
		in.ReturnValuesOnConditionCheckFailure = types.ReturnValuesOnConditionCheckFailureAllOld
	default:
		return hostkit.Item{}, hostkit.ProviderError(hostkit.Internal, 0, "", "unknown PutMode")
	}

	cli := r.ddbClient(ctx)
	var out *dynamodb.PutItemOutput
	err := r.doAWS(ctx, idempotent, func(ctx context.Context) error {
		var pErr error
		out, pErr = cli.PutItem(ctx, in)
		return pErr
	})

	stored := item.Clone()
	stored.Version = version
	stored.Exists = true
	newBytes := hostkit.NativeItemBillableBytes(stored)

	if err != nil {
		var ccf *types.ConditionalCheckFailedException
		if errors.As(err, &ccf) && ccf != nil {
			httpStatus, _ := extractHTTPResponse(err)
			if httpStatus == 0 {
				httpStatus = 400
			}
			msg := strings.TrimSpace(aws.ToString(ccf.Message))
			if msg == "" {
				msg = "The conditional request failed"
			}
			priorBytes, priorExists := billableBytesFromAV(ccf.Item)
			hostkit.ReportTableOpMetrics(ctx, hostkit.TableOpMetrics{
				PriorExists:   priorExists,
				PriorBytes:    priorBytes,
				NewBytes:      newBytes,
				Authoritative: true,
			})
			switch mode {
			case hostkit.PutIfAbsent:
				return hostkit.Item{}, hostkit.ProviderError(hostkit.Conflict, httpStatus, "ConditionalCheckFailedException", msg)
			case hostkit.PutIfVersion:
				if priorExists {
					return hostkit.Item{}, hostkit.ProviderError(hostkit.PreconditionFailed, httpStatus, "ConditionalCheckFailedException", msg)
				}
				return hostkit.Item{}, hostkit.ProviderError(hostkit.NotFound, httpStatus, "ConditionalCheckFailedException", msg).WithAbsent(hostkit.AbsentItem)
			}
		}
		return hostkit.Item{}, classify(err, scopeItem)
	}

	var priorBytes int64
	var priorExists bool
	if out != nil && len(out.Attributes) > 0 {
		priorBytes, priorExists = billableBytesFromAV(out.Attributes)
	}
	hostkit.ReportTableOpMetrics(ctx, hostkit.TableOpMetrics{
		PriorExists:   priorExists,
		PriorBytes:    priorBytes,
		NewBytes:      newBytes,
		Authoritative: true,
	})
	return stored, nil
}

func (r *remote) GetItem(ctx context.Context, table, pk, sk string) (hostkit.Item, error) {
	r.recordCall("GetItem", false)
	if cerr := r.checkCachedKeyLayout(ctx, table, sk); cerr != nil {
		return hostkit.Item{}, cerr
	}
	cli := r.ddbClient(ctx)
	var out *dynamodb.GetItemOutput
	err := r.doAWS(ctx, true, func(ctx context.Context) error {
		var gErr error
		out, gErr = cli.GetItem(ctx, &dynamodb.GetItemInput{
			TableName:      aws.String(table),
			Key:            buildKeyAV(pk, sk),
			ConsistentRead: aws.Bool(true),
		})
		return gErr
	})
	if err != nil {
		return hostkit.Item{}, classify(err, scopeItem)
	}
	if out == nil || len(out.Item) == 0 {
		return hostkit.Item{}, hostkit.ProviderError(hostkit.NotFound, 404, "ItemNotFound", "item not found").WithAbsent(hostkit.AbsentItem)
	}
	decoded, cerr := decodeDDBItem(out.Item)
	if cerr != nil {
		return hostkit.Item{}, cerr
	}
	return decoded, nil
}

func (r *remote) DeleteItem(ctx context.Context, table, pk, sk string) error {
	r.recordCall("DeleteItem", true)
	if cerr := r.checkCachedKeyLayout(ctx, table, sk); cerr != nil {
		return cerr
	}
	cli := r.ddbClient(ctx)
	var out *dynamodb.DeleteItemOutput
	err := r.doAWS(ctx, true, func(ctx context.Context) error {
		var dErr error
		out, dErr = cli.DeleteItem(ctx, &dynamodb.DeleteItemInput{
			TableName:    aws.String(table),
			Key:          buildKeyAV(pk, sk),
			ReturnValues: types.ReturnValueAllOld,
		})
		return dErr
	})
	if err != nil {
		return classify(err, scopeItem)
	}
	var priorBytes int64
	var priorExists bool
	if out != nil && len(out.Attributes) > 0 {
		priorBytes, priorExists = billableBytesFromAV(out.Attributes)
	}
	hostkit.ReportTableOpMetrics(ctx, hostkit.TableOpMetrics{
		PriorExists:   priorExists,
		PriorBytes:    priorBytes,
		Authoritative: true,
	})
	return nil
}

func (r *remote) UpdateItem(ctx context.Context, table, pk, sk string, changes hostkit.Item) (hostkit.Item, error) {
	r.recordCall("UpdateItem", true)
	if cerr := r.checkCachedKeyLayout(ctx, table, sk); cerr != nil {
		return hostkit.Item{}, cerr
	}

	version := newVersionToken()
	ean := map[string]string{
		"#pk": attrPK,
		"#v":  attrVersion,
	}
	eav := map[string]types.AttributeValue{
		":v": &types.AttributeValueMemberS{Value: version},
	}

	setClauses := []string{"#v = :v"}
	var removeClauses []string

	keys := make([]string, 0, len(changes.Attrs))
	for k := range changes.Attrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	hasLmt := false
	hasFloat := false
	for i, k := range keys {
		nameTok := fmt.Sprintf("#u_%d", i)
		valTok := fmt.Sprintf(":u_%d", i)
		av, isFloat, cerr := attrToDDB(changes.Attrs[k])
		if cerr != nil {
			return hostkit.Item{}, cerr
		}
		ean[nameTok] = k
		eav[valTok] = av
		setClauses = append(setClauses, fmt.Sprintf("%s = %s", nameTok, valTok))
		hasLmt = true
		if isFloat {
			hasFloat = true
			setClauses = append(setClauses, fmt.Sprintf("#lmt.%s = :numtag", nameTok))
		} else {
			removeClauses = append(removeClauses, fmt.Sprintf("#lmt.%s", nameTok))
		}
	}
	if hasLmt {
		ean["#lmt"] = attrTypeManifest
	}
	if hasFloat {
		eav[":numtag"] = &types.AttributeValueMemberS{Value: floatTypeTag}
	}

	updateExpr := "SET " + strings.Join(setClauses, ", ")
	if len(removeClauses) > 0 {
		updateExpr += " REMOVE " + strings.Join(removeClauses, ", ")
	}

	in := &dynamodb.UpdateItemInput{
		TableName:                           aws.String(table),
		Key:                                 buildKeyAV(pk, sk),
		ConditionExpression:                 aws.String("attribute_exists(#pk)"),
		UpdateExpression:                    aws.String(updateExpr),
		ExpressionAttributeNames:            ean,
		ExpressionAttributeValues:           eav,
		ReturnValues:                        types.ReturnValueAllNew,
		ReturnValuesOnConditionCheckFailure: types.ReturnValuesOnConditionCheckFailureAllOld,
	}

	cli := r.ddbClient(ctx)
	var out *dynamodb.UpdateItemOutput
	err := r.doAWS(ctx, false, func(ctx context.Context) error {
		var uErr error
		out, uErr = cli.UpdateItem(ctx, in)
		return uErr
	})
	if err != nil {
		var ccf *types.ConditionalCheckFailedException
		if errors.As(err, &ccf) && ccf != nil {
			httpStatus, _ := extractHTTPResponse(err)
			if httpStatus == 0 {
				httpStatus = 400
			}
			msg := strings.TrimSpace(aws.ToString(ccf.Message))
			if msg == "" {
				msg = "The conditional request failed"
			}
			hostkit.ReportTableOpMetrics(ctx, hostkit.TableOpMetrics{
				PriorExists:   false,
				Authoritative: true,
			})
			return hostkit.Item{}, hostkit.ProviderError(hostkit.NotFound, httpStatus, "ConditionalCheckFailedException", msg).WithAbsent(hostkit.AbsentItem)
		}
		return hostkit.Item{}, classify(err, scopeItem)
	}

	if out == nil || len(out.Attributes) == 0 {
		return hostkit.Item{}, hostkit.ProviderError(hostkit.Internal, 0, "EmptyUpdateResponse", "dynamodb UpdateItem returned no attributes")
	}
	decoded, cerr := decodeDDBItem(out.Attributes)
	if cerr != nil {
		return hostkit.Item{}, cerr
	}
	newBytes := hostkit.NativeItemBillableBytes(decoded)
	hostkit.ReportTableOpMetrics(ctx, hostkit.TableOpMetrics{
		PriorExists:   true,
		PriorBytes:    newBytes,
		NewBytes:      newBytes,
		Authoritative: true,
	})
	return decoded, nil
}

type ddbCursorKey struct {
	PK string `json:"pk"`
	SK string `json:"sk,omitempty"`
}

func encodeDDBStartKey(lek map[string]types.AttributeValue) string {
	if len(lek) == 0 {
		return ""
	}
	var ck ddbCursorKey
	if pkAttr, ok := lek[attrPK].(*types.AttributeValueMemberS); ok {
		ck.PK = pkAttr.Value
	}
	if skAttr, ok := lek[attrSK].(*types.AttributeValueMemberS); ok {
		ck.SK = skAttr.Value
	}
	if ck.PK == "" {
		return ""
	}
	raw, err := json.Marshal(ck)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func decodeDDBStartKey(token string) (map[string]types.AttributeValue, *hostkit.CloudError) {
	if token == "" {
		return nil, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return nil, hostkit.Preflightf("invalid continuation token")
	}
	var ck ddbCursorKey
	if err := json.Unmarshal(raw, &ck); err != nil || ck.PK == "" {
		return nil, hostkit.Preflightf("invalid continuation token")
	}
	return buildKeyAV(ck.PK, ck.SK), nil
}

func (r *remote) Query(ctx context.Context, table, pk, skFrom, skTo string, max int, token string) (hostkit.TablePage, error) {
	r.recordCall("Query", false)
	if skFrom != "" || skTo != "" {
		if sorted, ok := r.getTableLayout(ctx, table); ok && !sorted {
			return hostkit.TablePage{}, hostkit.Preflightf("sort key range [sk_from, sk_to) is not valid on partition-key-only table %q", table)
		}
	}
	startKey, cerr := decodeDDBStartKey(token)
	if cerr != nil {
		return hostkit.TablePage{}, cerr
	}
	if max <= 0 {
		max = hostkit.DefaultTablePageMax
	}

	ean := map[string]string{
		"#pk": attrPK,
	}
	eav := map[string]types.AttributeValue{
		":pk": &types.AttributeValueMemberS{Value: pk},
	}

	var kce string
	switch {
	case skFrom != "" && skTo != "":
		kce = "#pk = :pk AND #sk BETWEEN :skFrom AND :skTo"
		ean["#sk"] = attrSK
		eav[":skFrom"] = &types.AttributeValueMemberS{Value: skFrom}
		eav[":skTo"] = &types.AttributeValueMemberS{Value: skTo}
	case skFrom != "":
		kce = "#pk = :pk AND #sk >= :skFrom"
		ean["#sk"] = attrSK
		eav[":skFrom"] = &types.AttributeValueMemberS{Value: skFrom}
	case skTo != "":
		kce = "#pk = :pk AND #sk < :skTo"
		ean["#sk"] = attrSK
		eav[":skTo"] = &types.AttributeValueMemberS{Value: skTo}
	default:
		kce = "#pk = :pk"
	}

	in := &dynamodb.QueryInput{
		TableName:                 aws.String(table),
		KeyConditionExpression:    aws.String(kce),
		ExpressionAttributeNames:  ean,
		ExpressionAttributeValues: eav,
		ConsistentRead:            aws.Bool(true),
		ScanIndexForward:          aws.Bool(true),
		Limit:                     aws.Int32(int32(max)),
		ExclusiveStartKey:         startKey,
	}

	cli := r.ddbClient(ctx)
	var out *dynamodb.QueryOutput
	err := r.doAWS(ctx, true, func(ctx context.Context) error {
		var qErr error
		out, qErr = cli.Query(ctx, in)
		return qErr
	})
	if err != nil {
		ce := classify(err, scopeTable)
		if ce.Code == hostkit.InvalidArgument && (skFrom != "" || skTo != "") &&
			(strings.Contains(ce.Message, "key schema") || strings.Contains(ce.Message, "KeyConditionExpression")) {
			return hostkit.TablePage{}, hostkit.Preflightf("sort key range [sk_from, sk_to) is not valid on partition-key-only table %q", table)
		}
		return hostkit.TablePage{}, ce
	}

	var page hostkit.TablePage
	if out == nil {
		return page, nil
	}
	reachedUpperBound := false
	page.Items = make([]hostkit.Item, 0, len(out.Items))
	for _, rawItem := range out.Items {
		it, cerr := decodeDDBItem(rawItem)
		if cerr != nil {
			return hostkit.TablePage{}, cerr
		}
		// DynamoDB BETWEEN is inclusive of skTo; trim any item with sk >= skTo
		// to honor the portable half-open [skFrom, skTo) contract (design 12 §4.3).
		if skTo != "" && it.SK >= skTo {
			reachedUpperBound = true
			continue
		}
		page.Items = append(page.Items, it)
	}
	if !reachedUpperBound && len(out.LastEvaluatedKey) > 0 {
		if skTo != "" {
			if skAttr, ok := out.LastEvaluatedKey[attrSK].(*types.AttributeValueMemberS); ok && skAttr.Value >= skTo {
				reachedUpperBound = true
			}
		}
		if !reachedUpperBound {
			page.NextToken = encodeDDBStartKey(out.LastEvaluatedKey)
		}
	}
	return page, nil
}

func (r *remote) Scan(ctx context.Context, table string, max int, token string) (hostkit.TablePage, error) {
	r.recordCall("Scan", false)
	startKey, cerr := decodeDDBStartKey(token)
	if cerr != nil {
		return hostkit.TablePage{}, cerr
	}
	if max <= 0 {
		max = hostkit.DefaultTablePageMax
	}

	in := &dynamodb.ScanInput{
		TableName:         aws.String(table),
		Limit:             aws.Int32(int32(max)),
		ExclusiveStartKey: startKey,
	}

	cli := r.ddbClient(ctx)
	var out *dynamodb.ScanOutput
	err := r.doAWS(ctx, true, func(ctx context.Context) error {
		var sErr error
		out, sErr = cli.Scan(ctx, in)
		return sErr
	})
	if err != nil {
		return hostkit.TablePage{}, classify(err, scopeTable)
	}

	var page hostkit.TablePage
	if out == nil {
		return page, nil
	}
	page.Items = make([]hostkit.Item, 0, len(out.Items))
	for _, rawItem := range out.Items {
		it, cerr := decodeDDBItem(rawItem)
		if cerr != nil {
			return hostkit.TablePage{}, cerr
		}
		page.Items = append(page.Items, it)
	}
	if len(out.LastEvaluatedKey) > 0 {
		page.NextToken = encodeDDBStartKey(out.LastEvaluatedKey)
	}
	return page, nil
}
