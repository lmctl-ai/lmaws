package host

import (
	"fmt"
	"os"
	"sort"

	lmcode "github.com/lmctl-ai/lmcode-go"
)

func makeStrListValue(reg *lmcode.Registry, items []string) (lmcode.Value, error) {
	newEntry := reg.FunctionBySignature("fn str_list() -> StrList")
	if newEntry == nil {
		return lmcode.None(), fmt.Errorf("std function str_list() is not registered")
	}
	listVal, err := newEntry.Fn(nil)
	if err != nil {
		return lmcode.None(), err
	}
	addEntry := reg.MethodBySignature("method StrList.add(string) -> StrList")
	if addEntry == nil {
		return lmcode.None(), fmt.Errorf("std method StrList.add(string) is not registered")
	}
	for _, s := range items {
		if _, err := addEntry.Fn(listVal.Obj, []lmcode.Value{lmcode.String(s)}); err != nil {
			return lmcode.None(), err
		}
	}
	return listVal, nil
}

func makeStrMapValue(reg *lmcode.Registry, m map[string]string) (lmcode.Value, error) {
	newEntry := reg.FunctionBySignature("fn str_map() -> StrMap")
	if newEntry == nil {
		return lmcode.None(), fmt.Errorf("std function str_map() is not registered")
	}
	mapVal, err := newEntry.Fn(nil)
	if err != nil {
		return lmcode.None(), err
	}
	setEntry := reg.MethodBySignature("method StrMap.set(string, string) -> StrMap")
	if setEntry == nil {
		return lmcode.None(), fmt.Errorf("std method StrMap.set(string, string) is not registered")
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if _, err := setEntry.Fn(mapVal.Obj, []lmcode.Value{lmcode.String(k), lmcode.String(m[k])}); err != nil {
			return lmcode.None(), err
		}
	}
	return mapVal, nil
}

func extractStrMap(val lmcode.Value) (map[string]string, error) {
	if val.Obj == nil {
		return map[string]string{}, nil
	}
	sm, ok := val.Obj.(*lmcode.StrMap)
	if !ok {
		return nil, fmt.Errorf("expected StrMap, got %T", val.Obj)
	}
	entries := sm.Entries()
	out := make(map[string]string, len(entries))
	for _, e := range entries {
		out[e.Key] = e.Value
	}
	return out, nil
}

// Register binds the shared lmcloud schema context, testing helpers, and all Cloud methods to reg.
func Register(reg *lmcode.Registry, h *Host) error {
	if h == nil {
		h = New(Options{})
	}
	if err := lmcode.RegisterTesting(reg, os.Stdout); err != nil {
		return err
	}
	if err := reg.Context("cloud", "Cloud"); err != nil {
		return err
	}

	var firstErr error
	must := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}

	printBool := lmcode.Function(func(args []lmcode.Value) (lmcode.Value, error) {
		fmt.Fprintln(os.Stdout, args[0].Bool)
		return lmcode.None(), nil
	})
	printFloat := lmcode.Function(func(args []lmcode.Value) (lmcode.Value, error) {
		fmt.Fprintln(os.Stdout, lmcode.FormatG15(args[0].Float))
		return lmcode.None(), nil
	})
	printInt := lmcode.Function(func(args []lmcode.Value) (lmcode.Value, error) {
		fmt.Fprintln(os.Stdout, args[0].Int)
		return lmcode.None(), nil
	})
	must(reg.Function("print", []string{"bool"}, "void", printBool, lmcode.Dry(printBool)))
	must(reg.Function("print", []string{"float"}, "void", printFloat, lmcode.Dry(printFloat)))
	must(reg.Function("print", []string{"int"}, "void", printInt, lmcode.Dry(printInt)))

	// ---- Cloud configuration & status ----

	must(reg.Method("Cloud", "provider", nil, "string",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			return lmcode.String(self.(*Host).Provider()), nil
		},
		lmcode.Dry[lmcode.Method](func(self any, args []lmcode.Value) (lmcode.Value, error) {
			return lmcode.String("aws"), nil
		}),
	))

	must(reg.Method("Cloud", "endpoint", []string{"string"}, "string",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			ep, err := self.(*Host).Endpoint(args[0].Str)
			if err != nil {
				return lmcode.None(), err
			}
			return lmcode.String(ep), nil
		},
		lmcode.Dry[lmcode.Method](func(self any, args []lmcode.Value) (lmcode.Value, error) {
			ep, err := self.(*Host).Endpoint(args[0].Str)
			if err != nil {
				return lmcode.None(), err
			}
			return lmcode.String(ep), nil
		}),
	))

	must(reg.Method("Cloud", "set_endpoint", []string{"string", "string"}, "Cloud",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			c, err := self.(*Host).SetEndpoint(args[0].Str, args[1].Str)
			if err != nil {
				return lmcode.None(), err
			}
			return lmcode.Obj("Cloud", c), nil
		},
		lmcode.Dry[lmcode.Method](func(self any, args []lmcode.Value) (lmcode.Value, error) {
			c, err := self.(*Host).SetEndpoint(args[0].Str, args[1].Str)
			if err != nil {
				return lmcode.None(), err
			}
			return lmcode.Obj("Cloud", c), nil
		}),
	))

	must(reg.Method("Cloud", "abort_on_error", nil, "bool",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			return lmcode.Bool(self.(*Host).AbortOnError()), nil
		},
		lmcode.Dry[lmcode.Method](func(self any, args []lmcode.Value) (lmcode.Value, error) {
			return lmcode.Bool(self.(*Host).AbortOnError()), nil
		}),
	))

	must(reg.Method("Cloud", "set_abort_on_error", []string{"bool"}, "Cloud",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			c := self.(*Host).SetAbortOnError(args[0].Bool)
			return lmcode.Obj("Cloud", c), nil
		},
		lmcode.Dry[lmcode.Method](func(self any, args []lmcode.Value) (lmcode.Value, error) {
			c := self.(*Host).SetAbortOnError(args[0].Bool)
			return lmcode.Obj("Cloud", c), nil
		}),
	))

	must(reg.Method("Cloud", "last_error", nil, "CloudError",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			return lmcode.Obj("CloudError", self.(*Host).LastError()), nil
		},
		lmcode.Dry[lmcode.Method](func(self any, args []lmcode.Value) (lmcode.Value, error) {
			return lmcode.Obj("CloudError", self.(*Host).LastError()), nil
		}),
	))

	// ---- Cloud Object Storage ----

	must(reg.Method("Cloud", "bucket_create", []string{"string"}, "bool",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			created, err := self.(*Host).BucketCreate(args[0].Str)
			if err != nil {
				return lmcode.None(), err
			}
			return lmcode.Bool(created), nil
		},
		lmcode.Dry[lmcode.Method](func(self any, args []lmcode.Value) (lmcode.Value, error) {
			if cerr := ValidateBucketName(args[0].Str); cerr != nil {
				return lmcode.None(), self.(*Host).finishErrorLocked("bucket_create", args[0].Str, cerr)
			}
			self.(*Host).finishOKLocked()
			return lmcode.Bool(true), nil
		}),
	))

	must(reg.Method("Cloud", "bucket_delete", []string{"string"}, "bool",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			deleted, err := self.(*Host).BucketDelete(args[0].Str)
			if err != nil {
				return lmcode.None(), err
			}
			return lmcode.Bool(deleted), nil
		},
		lmcode.Dry[lmcode.Method](func(self any, args []lmcode.Value) (lmcode.Value, error) {
			if cerr := ValidateBucketName(args[0].Str); cerr != nil {
				return lmcode.None(), self.(*Host).finishErrorLocked("bucket_delete", args[0].Str, cerr)
			}
			self.(*Host).finishOKLocked()
			return lmcode.Bool(true), nil
		}),
	))

	must(reg.Method("Cloud", "bucket_exists", []string{"string"}, "bool",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			exists, err := self.(*Host).BucketExists(args[0].Str)
			if err != nil {
				return lmcode.None(), err
			}
			return lmcode.Bool(exists), nil
		},
		lmcode.Dry[lmcode.Method](func(self any, args []lmcode.Value) (lmcode.Value, error) {
			if cerr := ValidateBucketName(args[0].Str); cerr != nil {
				return lmcode.None(), self.(*Host).finishErrorLocked("bucket_exists", args[0].Str, cerr)
			}
			self.(*Host).finishOKLocked()
			return lmcode.Bool(false), nil
		}),
	))

	must(reg.Method("Cloud", "bucket_list", nil, "StrList",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			items, err := self.(*Host).BucketList()
			if err != nil {
				return lmcode.None(), err
			}
			return makeStrListValue(reg, items)
		},
		lmcode.Dry[lmcode.Method](func(self any, args []lmcode.Value) (lmcode.Value, error) {
			self.(*Host).finishOKLocked()
			return makeStrListValue(reg, nil)
		}),
	))

	must(reg.Method("Cloud", "object_put", []string{"string", "string", "string"}, "ObjectMeta",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			meta, err := self.(*Host).ObjectPut(args[0].Str, args[1].Str, args[2].Str, "application/octet-stream", map[string]string{})
			if err != nil {
				return lmcode.None(), err
			}
			return lmcode.Obj("ObjectMeta", meta), nil
		},
		lmcode.Dry[lmcode.Method](func(self any, args []lmcode.Value) (lmcode.Value, error) {
			b, k, body := args[0].Str, args[1].Str, args[2].Str
			if cerr := ValidateBucketName(b); cerr != nil {
				return lmcode.None(), self.(*Host).finishErrorLocked("object_put", b+"/"+k, cerr)
			}
			if cerr := ValidateObjectKey(k); cerr != nil {
				return lmcode.None(), self.(*Host).finishErrorLocked("object_put", b+"/"+k, cerr)
			}
			self.(*Host).finishOKLocked()
			return lmcode.Obj("ObjectMeta", &ObjectMeta{
				Exists:      true,
				Bucket:      b,
				Key:         k,
				Size:        int64(len(body)),
				ETag:        computeSHA256Hex([]byte(body)),
				ContentType: "application/octet-stream",
				Metadata:    map[string]string{},
			}), nil
		}),
	))

	must(reg.Method("Cloud", "object_put", []string{"string", "string", "string", "string", "StrMap"}, "ObjectMeta",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			metaMap, err := extractStrMap(args[4])
			if err != nil {
				return lmcode.None(), err
			}
			meta, err := self.(*Host).ObjectPut(args[0].Str, args[1].Str, args[2].Str, args[3].Str, metaMap)
			if err != nil {
				return lmcode.None(), err
			}
			return lmcode.Obj("ObjectMeta", meta), nil
		},
		lmcode.Dry[lmcode.Method](func(self any, args []lmcode.Value) (lmcode.Value, error) {
			b, k, body, ct := args[0].Str, args[1].Str, args[2].Str, args[3].Str
			metaMap, err := extractStrMap(args[4])
			if err != nil {
				return lmcode.None(), err
			}
			if cerr := ValidateBucketName(b); cerr != nil {
				return lmcode.None(), self.(*Host).finishErrorLocked("object_put", b+"/"+k, cerr)
			}
			if cerr := ValidateObjectKey(k); cerr != nil {
				return lmcode.None(), self.(*Host).finishErrorLocked("object_put", b+"/"+k, cerr)
			}
			if cerr := ValidateContentType(ct); cerr != nil {
				return lmcode.None(), self.(*Host).finishErrorLocked("object_put", b+"/"+k, cerr)
			}
			if cerr := ValidateMetadata(metaMap); cerr != nil {
				return lmcode.None(), self.(*Host).finishErrorLocked("object_put", b+"/"+k, cerr)
			}
			self.(*Host).finishOKLocked()
			return lmcode.Obj("ObjectMeta", &ObjectMeta{
				Exists:      true,
				Bucket:      b,
				Key:         k,
				Size:        int64(len(body)),
				ETag:        computeSHA256Hex([]byte(body)),
				ContentType: ct,
				Metadata:    metaMap,
			}), nil
		}),
	))

	must(reg.Method("Cloud", "object_get", []string{"string", "string"}, "string",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			body, err := self.(*Host).ObjectGet(args[0].Str, args[1].Str)
			if err != nil {
				return lmcode.None(), err
			}
			return lmcode.String(body), nil
		},
		lmcode.Dry[lmcode.Method](func(self any, args []lmcode.Value) (lmcode.Value, error) {
			b, k := args[0].Str, args[1].Str
			if cerr := ValidateBucketName(b); cerr != nil {
				return lmcode.None(), self.(*Host).finishErrorLocked("object_get", b+"/"+k, cerr)
			}
			if cerr := ValidateObjectKey(k); cerr != nil {
				return lmcode.None(), self.(*Host).finishErrorLocked("object_get", b+"/"+k, cerr)
			}
			self.(*Host).finishOKLocked()
			return lmcode.String(""), nil
		}),
	))

	must(reg.Method("Cloud", "object_head", []string{"string", "string"}, "ObjectMeta",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			meta, err := self.(*Host).ObjectHead(args[0].Str, args[1].Str)
			if err != nil {
				return lmcode.None(), err
			}
			return lmcode.Obj("ObjectMeta", meta), nil
		},
		lmcode.Dry[lmcode.Method](func(self any, args []lmcode.Value) (lmcode.Value, error) {
			b, k := args[0].Str, args[1].Str
			if cerr := ValidateBucketName(b); cerr != nil {
				return lmcode.None(), self.(*Host).finishErrorLocked("object_head", b+"/"+k, cerr)
			}
			if cerr := ValidateObjectKey(k); cerr != nil {
				return lmcode.None(), self.(*Host).finishErrorLocked("object_head", b+"/"+k, cerr)
			}
			self.(*Host).finishOKLocked()
			return lmcode.Obj("ObjectMeta", notFoundObjectMeta(b, k)), nil
		}),
	))

	must(reg.Method("Cloud", "object_delete", []string{"string", "string"}, "void",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			if err := self.(*Host).ObjectDelete(args[0].Str, args[1].Str); err != nil {
				return lmcode.None(), err
			}
			return lmcode.None(), nil
		},
		lmcode.Dry[lmcode.Method](func(self any, args []lmcode.Value) (lmcode.Value, error) {
			b, k := args[0].Str, args[1].Str
			if cerr := ValidateBucketName(b); cerr != nil {
				return lmcode.None(), self.(*Host).finishErrorLocked("object_delete", b+"/"+k, cerr)
			}
			if cerr := ValidateObjectKey(k); cerr != nil {
				return lmcode.None(), self.(*Host).finishErrorLocked("object_delete", b+"/"+k, cerr)
			}
			self.(*Host).finishOKLocked()
			return lmcode.None(), nil
		}),
	))

	must(reg.Method("Cloud", "object_list", []string{"string", "string"}, "ObjectListPage",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			page, err := self.(*Host).ObjectList(args[0].Str, args[1].Str, 1000, "")
			if err != nil {
				return lmcode.None(), err
			}
			return lmcode.Obj("ObjectListPage", page), nil
		},
		lmcode.Dry[lmcode.Method](func(self any, args []lmcode.Value) (lmcode.Value, error) {
			b, prefix := args[0].Str, args[1].Str
			if cerr := ValidateBucketName(b); cerr != nil {
				return lmcode.None(), self.(*Host).finishErrorLocked("object_list", b, cerr)
			}
			if cerr := ValidateListPrefix(prefix); cerr != nil {
				return lmcode.None(), self.(*Host).finishErrorLocked("object_list", b, cerr)
			}
			self.(*Host).finishOKLocked()
			return lmcode.Obj("ObjectListPage", emptyObjectListPage()), nil
		}),
	))

	must(reg.Method("Cloud", "object_list", []string{"string", "string", "int", "string"}, "ObjectListPage",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			page, err := self.(*Host).ObjectList(args[0].Str, args[1].Str, args[2].Int, args[3].Str)
			if err != nil {
				return lmcode.None(), err
			}
			return lmcode.Obj("ObjectListPage", page), nil
		},
		lmcode.Dry[lmcode.Method](func(self any, args []lmcode.Value) (lmcode.Value, error) {
			b, prefix, maxKeys := args[0].Str, args[1].Str, args[2].Int
			if cerr := ValidateBucketName(b); cerr != nil {
				return lmcode.None(), self.(*Host).finishErrorLocked("object_list", b, cerr)
			}
			if cerr := ValidateListPrefix(prefix); cerr != nil {
				return lmcode.None(), self.(*Host).finishErrorLocked("object_list", b, cerr)
			}
			if cerr := ValidateMaxKeys(maxKeys); cerr != nil {
				return lmcode.None(), self.(*Host).finishErrorLocked("object_list", b, cerr)
			}
			self.(*Host).finishOKLocked()
			return lmcode.Obj("ObjectListPage", emptyObjectListPage()), nil
		}),
	))

	must(reg.Method("Cloud", "object_list_all", []string{"string", "string"}, "StrList",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			keys, err := self.(*Host).ObjectListAll(args[0].Str, args[1].Str)
			if err != nil {
				return lmcode.None(), err
			}
			return makeStrListValue(reg, keys)
		},
		lmcode.Dry[lmcode.Method](func(self any, args []lmcode.Value) (lmcode.Value, error) {
			b, prefix := args[0].Str, args[1].Str
			if cerr := ValidateBucketName(b); cerr != nil {
				return lmcode.None(), self.(*Host).finishErrorLocked("object_list_all", b, cerr)
			}
			if cerr := ValidateListPrefix(prefix); cerr != nil {
				return lmcode.None(), self.(*Host).finishErrorLocked("object_list_all", b, cerr)
			}
			self.(*Host).finishOKLocked()
			return makeStrListValue(reg, nil)
		}),
	))

	// ---- Cloud Queue ----

	must(reg.Method("Cloud", "queue_create", []string{"string"}, "bool",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			created, err := self.(*Host).QueueCreate(args[0].Str)
			if err != nil {
				return lmcode.None(), err
			}
			return lmcode.Bool(created), nil
		},
		lmcode.Dry[lmcode.Method](func(self any, args []lmcode.Value) (lmcode.Value, error) {
			if cerr := ValidateQueueName(args[0].Str); cerr != nil {
				return lmcode.None(), self.(*Host).finishErrorLocked("queue_create", args[0].Str, cerr)
			}
			self.(*Host).finishOKLocked()
			return lmcode.Bool(true), nil
		}),
	))

	must(reg.Method("Cloud", "queue_delete", []string{"string"}, "bool",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			deleted, err := self.(*Host).QueueDelete(args[0].Str)
			if err != nil {
				return lmcode.None(), err
			}
			return lmcode.Bool(deleted), nil
		},
		lmcode.Dry[lmcode.Method](func(self any, args []lmcode.Value) (lmcode.Value, error) {
			if cerr := ValidateQueueName(args[0].Str); cerr != nil {
				return lmcode.None(), self.(*Host).finishErrorLocked("queue_delete", args[0].Str, cerr)
			}
			self.(*Host).finishOKLocked()
			return lmcode.Bool(true), nil
		}),
	))

	must(reg.Method("Cloud", "queue_exists", []string{"string"}, "bool",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			exists, err := self.(*Host).QueueExists(args[0].Str)
			if err != nil {
				return lmcode.None(), err
			}
			return lmcode.Bool(exists), nil
		},
		lmcode.Dry[lmcode.Method](func(self any, args []lmcode.Value) (lmcode.Value, error) {
			if cerr := ValidateQueueName(args[0].Str); cerr != nil {
				return lmcode.None(), self.(*Host).finishErrorLocked("queue_exists", args[0].Str, cerr)
			}
			self.(*Host).finishOKLocked()
			return lmcode.Bool(false), nil
		}),
	))

	must(reg.Method("Cloud", "queue_list", nil, "StrList",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			items, err := self.(*Host).QueueList()
			if err != nil {
				return lmcode.None(), err
			}
			return makeStrListValue(reg, items)
		},
		lmcode.Dry[lmcode.Method](func(self any, args []lmcode.Value) (lmcode.Value, error) {
			self.(*Host).finishOKLocked()
			return makeStrListValue(reg, nil)
		}),
	))

	must(reg.Method("Cloud", "queue_send", []string{"string", "string"}, "string",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			msgID, err := self.(*Host).QueueSend(args[0].Str, args[1].Str)
			if err != nil {
				return lmcode.None(), err
			}
			return lmcode.String(msgID), nil
		},
		lmcode.Dry[lmcode.Method](func(self any, args []lmcode.Value) (lmcode.Value, error) {
			q, body := args[0].Str, args[1].Str
			if cerr := ValidateQueueName(q); cerr != nil {
				return lmcode.None(), self.(*Host).finishErrorLocked("queue_send", q, cerr)
			}
			if cerr := ValidateQueueBody(body); cerr != nil {
				return lmcode.None(), self.(*Host).finishErrorLocked("queue_send", q, cerr)
			}
			self.(*Host).finishOKLocked()
			return lmcode.String("dry-msg-1"), nil
		}),
	))

	must(reg.Method("Cloud", "queue_receive", []string{"string"}, "QueueMessageList",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			list, err := self.(*Host).QueueReceive(args[0].Str, 1, 0, 30)
			if err != nil {
				return lmcode.None(), err
			}
			return lmcode.Obj("QueueMessageList", list), nil
		},
		lmcode.Dry[lmcode.Method](func(self any, args []lmcode.Value) (lmcode.Value, error) {
			q := args[0].Str
			if cerr := ValidateQueueName(q); cerr != nil {
				return lmcode.None(), self.(*Host).finishErrorLocked("queue_receive", q, cerr)
			}
			self.(*Host).finishOKLocked()
			return lmcode.Obj("QueueMessageList", emptyQueueMessageList()), nil
		}),
	))

	must(reg.Method("Cloud", "queue_receive", []string{"string", "int", "int", "int"}, "QueueMessageList",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			list, err := self.(*Host).QueueReceive(args[0].Str, args[1].Int, args[2].Int, args[3].Int)
			if err != nil {
				return lmcode.None(), err
			}
			return lmcode.Obj("QueueMessageList", list), nil
		},
		lmcode.Dry[lmcode.Method](func(self any, args []lmcode.Value) (lmcode.Value, error) {
			q, maxM, waitS, visS := args[0].Str, args[1].Int, args[2].Int, args[3].Int
			if cerr := ValidateQueueName(q); cerr != nil {
				return lmcode.None(), self.(*Host).finishErrorLocked("queue_receive", q, cerr)
			}
			if cerr := ValidateQueueReceiveParams(maxM, waitS, visS); cerr != nil {
				return lmcode.None(), self.(*Host).finishErrorLocked("queue_receive", q, cerr)
			}
			self.(*Host).finishOKLocked()
			return lmcode.Obj("QueueMessageList", emptyQueueMessageList()), nil
		}),
	))

	must(reg.Method("Cloud", "queue_ack", []string{"string", "string"}, "void",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			if err := self.(*Host).QueueAck(args[0].Str, args[1].Str); err != nil {
				return lmcode.None(), err
			}
			return lmcode.None(), nil
		},
		lmcode.Dry[lmcode.Method](func(self any, args []lmcode.Value) (lmcode.Value, error) {
			q, rcpt := args[0].Str, args[1].Str
			if cerr := ValidateQueueName(q); cerr != nil {
				return lmcode.None(), self.(*Host).finishErrorLocked("queue_ack", q, cerr)
			}
			if cerr := ValidateQueueReceipt(rcpt); cerr != nil {
				return lmcode.None(), self.(*Host).finishErrorLocked("queue_ack", q, cerr)
			}
			self.(*Host).finishOKLocked()
			return lmcode.None(), nil
		}),
	))

	must(reg.Method("Cloud", "queue_nack", []string{"string", "string", "int"}, "string",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			newRcpt, err := self.(*Host).QueueNack(args[0].Str, args[1].Str, args[2].Int)
			if err != nil {
				return lmcode.None(), err
			}
			return lmcode.String(newRcpt), nil
		},
		lmcode.Dry[lmcode.Method](func(self any, args []lmcode.Value) (lmcode.Value, error) {
			q, rcpt, visS := args[0].Str, args[1].Str, args[2].Int
			if cerr := ValidateQueueName(q); cerr != nil {
				return lmcode.None(), self.(*Host).finishErrorLocked("queue_nack", q, cerr)
			}
			if cerr := ValidateQueueReceipt(rcpt); cerr != nil {
				return lmcode.None(), self.(*Host).finishErrorLocked("queue_nack", q, cerr)
			}
			if cerr := ValidateQueueNackTimeout(visS); cerr != nil {
				return lmcode.None(), self.(*Host).finishErrorLocked("queue_nack", q, cerr)
			}
			self.(*Host).finishOKLocked()
			return lmcode.String(rcpt), nil
		}),
	))

	// ---- CloudError ----

	must(reg.Method("CloudError", "ok", nil, "bool",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			return lmcode.Bool(self.(*CloudError).OK), nil
		},
		lmcode.Dry[lmcode.Method](func(self any, args []lmcode.Value) (lmcode.Value, error) {
			return lmcode.Bool(self.(*CloudError).OK), nil
		}),
	))

	must(reg.Method("CloudError", "code", nil, "ErrorCode",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			return lmcode.String(self.(*CloudError).Code), nil
		},
		lmcode.Dry[lmcode.Method](func(self any, args []lmcode.Value) (lmcode.Value, error) {
			return lmcode.String(self.(*CloudError).Code), nil
		}),
	))

	must(reg.Method("CloudError", "http_status", nil, "int",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			return lmcode.Int(int64(self.(*CloudError).HTTPStatus)), nil
		},
		lmcode.Dry[lmcode.Method](func(self any, args []lmcode.Value) (lmcode.Value, error) {
			return lmcode.Int(int64(self.(*CloudError).HTTPStatus)), nil
		}),
	))

	must(reg.Method("CloudError", "provider_code", nil, "string",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			return lmcode.String(self.(*CloudError).ProviderCode), nil
		},
		lmcode.Dry[lmcode.Method](func(self any, args []lmcode.Value) (lmcode.Value, error) {
			return lmcode.String(self.(*CloudError).ProviderCode), nil
		}),
	))

	must(reg.Method("CloudError", "message", nil, "string",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			return lmcode.String(self.(*CloudError).Message), nil
		},
		lmcode.Dry[lmcode.Method](func(self any, args []lmcode.Value) (lmcode.Value, error) {
			return lmcode.String(self.(*CloudError).Message), nil
		}),
	))

	// ---- ObjectMeta ----

	must(reg.Method("ObjectMeta", "exists", nil, "bool",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			return lmcode.Bool(self.(*ObjectMeta).Exists), nil
		},
		lmcode.Dry[lmcode.Method](func(self any, args []lmcode.Value) (lmcode.Value, error) {
			return lmcode.Bool(self.(*ObjectMeta).Exists), nil
		}),
	))

	must(reg.Method("ObjectMeta", "bucket", nil, "string",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			return lmcode.String(self.(*ObjectMeta).Bucket), nil
		},
		lmcode.Dry[lmcode.Method](func(self any, args []lmcode.Value) (lmcode.Value, error) {
			return lmcode.String(self.(*ObjectMeta).Bucket), nil
		}),
	))

	must(reg.Method("ObjectMeta", "key", nil, "string",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			return lmcode.String(self.(*ObjectMeta).Key), nil
		},
		lmcode.Dry[lmcode.Method](func(self any, args []lmcode.Value) (lmcode.Value, error) {
			return lmcode.String(self.(*ObjectMeta).Key), nil
		}),
	))

	must(reg.Method("ObjectMeta", "size", nil, "int",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			return lmcode.Int(self.(*ObjectMeta).Size), nil
		},
		lmcode.Dry[lmcode.Method](func(self any, args []lmcode.Value) (lmcode.Value, error) {
			return lmcode.Int(self.(*ObjectMeta).Size), nil
		}),
	))

	must(reg.Method("ObjectMeta", "etag", nil, "string",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			return lmcode.String(self.(*ObjectMeta).ETag), nil
		},
		lmcode.Dry[lmcode.Method](func(self any, args []lmcode.Value) (lmcode.Value, error) {
			return lmcode.String(self.(*ObjectMeta).ETag), nil
		}),
	))

	must(reg.Method("ObjectMeta", "content_type", nil, "string",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			return lmcode.String(self.(*ObjectMeta).ContentType), nil
		},
		lmcode.Dry[lmcode.Method](func(self any, args []lmcode.Value) (lmcode.Value, error) {
			return lmcode.String(self.(*ObjectMeta).ContentType), nil
		}),
	))

	must(reg.Method("ObjectMeta", "metadata", nil, "StrMap",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			return makeStrMapValue(reg, self.(*ObjectMeta).Metadata)
		},
		lmcode.Dry[lmcode.Method](func(self any, args []lmcode.Value) (lmcode.Value, error) {
			return makeStrMapValue(reg, self.(*ObjectMeta).Metadata)
		}),
	))

	// ---- ObjectSummary ----

	must(reg.Method("ObjectSummary", "key", nil, "string",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			return lmcode.String(self.(*ObjectSummary).Key), nil
		},
		lmcode.Dry[lmcode.Method](func(self any, args []lmcode.Value) (lmcode.Value, error) {
			return lmcode.String(self.(*ObjectSummary).Key), nil
		}),
	))

	must(reg.Method("ObjectSummary", "size", nil, "int",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			return lmcode.Int(self.(*ObjectSummary).Size), nil
		},
		lmcode.Dry[lmcode.Method](func(self any, args []lmcode.Value) (lmcode.Value, error) {
			return lmcode.Int(self.(*ObjectSummary).Size), nil
		}),
	))

	must(reg.Method("ObjectSummary", "etag", nil, "string",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			return lmcode.String(self.(*ObjectSummary).ETag), nil
		},
		lmcode.Dry[lmcode.Method](func(self any, args []lmcode.Value) (lmcode.Value, error) {
			return lmcode.String(self.(*ObjectSummary).ETag), nil
		}),
	))

	// ---- ObjectListPage ----

	must(reg.Method("ObjectListPage", "len", nil, "int",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			return lmcode.Int(int64(len(self.(*ObjectListPage).Items))), nil
		},
		lmcode.Dry[lmcode.Method](func(self any, args []lmcode.Value) (lmcode.Value, error) {
			return lmcode.Int(int64(len(self.(*ObjectListPage).Items))), nil
		}),
	))

	must(reg.Method("ObjectListPage", "at", []string{"int"}, "ObjectSummary",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			page := self.(*ObjectListPage)
			idx := args[0].Int
			if idx < 0 || idx >= int64(len(page.Items)) {
				return lmcode.None(), fmt.Errorf("ObjectListPage.at(%d) index out of range [0, %d)", idx, len(page.Items))
			}
			return lmcode.Obj("ObjectSummary", page.Items[idx]), nil
		},
		lmcode.Dry[lmcode.Method](func(self any, args []lmcode.Value) (lmcode.Value, error) {
			page := self.(*ObjectListPage)
			idx := args[0].Int
			if idx >= 0 && idx < int64(len(page.Items)) {
				return lmcode.Obj("ObjectSummary", page.Items[idx]), nil
			}
			return lmcode.Obj("ObjectSummary", &ObjectSummary{}), nil
		}),
	))

	must(reg.Method("ObjectListPage", "keys", nil, "StrList",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			page := self.(*ObjectListPage)
			keys := make([]string, len(page.Items))
			for i, item := range page.Items {
				keys[i] = item.Key
			}
			return makeStrListValue(reg, keys)
		},
		lmcode.Dry[lmcode.Method](func(self any, args []lmcode.Value) (lmcode.Value, error) {
			page := self.(*ObjectListPage)
			keys := make([]string, len(page.Items))
			for i, item := range page.Items {
				keys[i] = item.Key
			}
			return makeStrListValue(reg, keys)
		}),
	))

	must(reg.Method("ObjectListPage", "has_more", nil, "bool",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			return lmcode.Bool(self.(*ObjectListPage).HasMore), nil
		},
		lmcode.Dry[lmcode.Method](func(self any, args []lmcode.Value) (lmcode.Value, error) {
			return lmcode.Bool(self.(*ObjectListPage).HasMore), nil
		}),
	))

	must(reg.Method("ObjectListPage", "next_token", nil, "string",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			return lmcode.String(self.(*ObjectListPage).NextToken), nil
		},
		lmcode.Dry[lmcode.Method](func(self any, args []lmcode.Value) (lmcode.Value, error) {
			return lmcode.String(self.(*ObjectListPage).NextToken), nil
		}),
	))

	// ---- QueueMessage ----

	must(reg.Method("QueueMessage", "id", nil, "string",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			return lmcode.String(self.(*QueueMessage).ID), nil
		},
		lmcode.Dry[lmcode.Method](func(self any, args []lmcode.Value) (lmcode.Value, error) {
			return lmcode.String(self.(*QueueMessage).ID), nil
		}),
	))

	must(reg.Method("QueueMessage", "body", nil, "string",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			return lmcode.String(self.(*QueueMessage).Body), nil
		},
		lmcode.Dry[lmcode.Method](func(self any, args []lmcode.Value) (lmcode.Value, error) {
			return lmcode.String(self.(*QueueMessage).Body), nil
		}),
	))

	must(reg.Method("QueueMessage", "receipt", nil, "string",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			return lmcode.String(self.(*QueueMessage).Receipt), nil
		},
		lmcode.Dry[lmcode.Method](func(self any, args []lmcode.Value) (lmcode.Value, error) {
			return lmcode.String(self.(*QueueMessage).Receipt), nil
		}),
	))

	// ---- QueueMessageList ----

	must(reg.Method("QueueMessageList", "len", nil, "int",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			return lmcode.Int(int64(len(self.(*QueueMessageList).Items))), nil
		},
		lmcode.Dry[lmcode.Method](func(self any, args []lmcode.Value) (lmcode.Value, error) {
			return lmcode.Int(int64(len(self.(*QueueMessageList).Items))), nil
		}),
	))

	must(reg.Method("QueueMessageList", "at", []string{"int"}, "QueueMessage",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			list := self.(*QueueMessageList)
			idx := args[0].Int
			if idx < 0 || idx >= int64(len(list.Items)) {
				return lmcode.None(), fmt.Errorf("QueueMessageList.at(%d) index out of range [0, %d)", idx, len(list.Items))
			}
			return lmcode.Obj("QueueMessage", list.Items[idx]), nil
		},
		lmcode.Dry[lmcode.Method](func(self any, args []lmcode.Value) (lmcode.Value, error) {
			list := self.(*QueueMessageList)
			idx := args[0].Int
			if idx >= 0 && idx < int64(len(list.Items)) {
				return lmcode.Obj("QueueMessage", list.Items[idx]), nil
			}
			return lmcode.Obj("QueueMessage", &QueueMessage{}), nil
		}),
	))

	return firstErr
}
