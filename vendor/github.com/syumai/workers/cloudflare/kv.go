package cloudflare

import (
	"fmt"
	"io"
	"syscall/js"

	"github.com/syumai/workers/cloudflare/internal/cfruntimecontext"
	"github.com/syumai/workers/internal/jsutil"
)

// KVNamespace represents interface of Cloudflare Worker's KV namespace instance.
//   - https://developers.cloudflare.com/workers/runtime-apis/kv/
//   - https://github.com/cloudflare/workers-types/blob/3012f263fb1239825e5f0061b267c8650d01b717/index.d.ts#L850
type KVNamespace struct {
	instance js.Value
}

// NewKVNamespace returns KVNamespace for given variable name.
//   - variable name must be defined in wrangler.toml as kv_namespace's binding.
//   - if the given variable name doesn't exist on runtime context, returns error.
//   - This function panics when a runtime context is not found.
func NewKVNamespace(varName string) (*KVNamespace, error) {
	inst := cfruntimecontext.MustGetRuntimeContextEnv().Get(varName)
	if inst.IsUndefined() {
		return nil, fmt.Errorf("%s is undefined", varName)
	}
	return &KVNamespace{instance: inst}, nil
}

// KVNamespaceGetOptions represents Cloudflare KV namespace get options.
//   - https://github.com/cloudflare/workers-types/blob/3012f263fb1239825e5f0061b267c8650d01b717/index.d.ts#L930
type KVNamespaceGetOptions struct {
	CacheTTL int
}

func (opts *KVNamespaceGetOptions) toJS(type_ string) js.Value {
	obj := jsutil.NewObject()
	obj.Set("type", type_)
	if opts == nil {
		return obj
	}
	if opts.CacheTTL != 0 {
		obj.Set("cacheTtl", opts.CacheTTL)
	}
	return obj
}

// GetString gets string value by the specified key.
//   - if a network error happens, returns error.
func (kv *KVNamespace) GetString(key string, opts *KVNamespaceGetOptions) (string, error) {
	p := kv.instance.Call("get", key, opts.toJS("text"))
	v, err := jsutil.AwaitPromise(p)
	if err != nil {
		return "", err
	}
	return v.String(), nil
}

// GetReader gets stream value by the specified key.
//   - if a network error happens, returns error.
func (kv *KVNamespace) GetReader(key string, opts *KVNamespaceGetOptions) (io.Reader, error) {
	p := kv.instance.Call("get", key, opts.toJS("stream"))
	v, err := jsutil.AwaitPromise(p)
	if err != nil {
		return nil, err
	}
	return jsutil.ConvertReadableStreamToReadCloser(v), nil
}

// KVNamespaceListOptions represents Cloudflare KV namespace list options.
//   - https://github.com/cloudflare/workers-types/blob/3012f263fb1239825e5f0061b267c8650d01b717/index.d.ts#L946
type KVNamespaceListOptions struct {
	Limit  int
	Prefix string
	Cursor string
}

func (opts *KVNamespaceListOptions) toJS() js.Value {
	if opts == nil {
		return js.Undefined()
	}
	obj := jsutil.NewObject()
	if opts.Limit != 0 {
		obj.Set("limit", opts.Limit)
	}
	if opts.Prefix != "" {
		obj.Set("prefix", opts.Prefix)
	}
	if opts.Cursor != "" {
		obj.Set("cursor", opts.Cursor)
	}
	return obj
}

// KVNamespaceListKey represents Cloudflare KV namespace list key.
//   - https://github.com/cloudflare/workers-types/blob/3012f263fb1239825e5f0061b267c8650d01b717/index.d.ts#L940
type KVNamespaceListKey struct {
	Name string
	// Expiration is an expiration of KV value cache. The value `0` means no expiration.
	Expiration int
	// Metadata   map[string]any // TODO: implement
}

// toKVNamespaceListResult converts JavaScript side's KVNamespaceListKey to *KVNamespaceListKey.
//   - https://github.com/cloudflare/workers-types/blob/3012f263fb1239825e5f0061b267c8650d01b717/index.d.ts#L940
func toKVNamespaceListKey(v js.Value) (*KVNamespaceListKey, error) {
	expVal := v.Get("expiration")
	var exp int
	if !expVal.IsUndefined() {
		exp = expVal.Int()
	}
	return &KVNamespaceListKey{
		Name:       v.Get("name").String(),
		Expiration: exp,
		// Metadata // TODO: implement. This may return an error, so this func signature has an error in return parameters.
	}, nil
}

// KVNamespaceListResult represents Cloudflare KV namespace list result.
//   - https://github.com/cloudflare/workers-types/blob/3012f263fb1239825e5f0061b267c8650d01b717/index.d.ts#L952
type KVNamespaceListResult struct {
	Keys         []*KVNamespaceListKey
	ListComplete bool
	Cursor       string
}

// toKVNamespaceListResult converts JavaScript side's KVNamespaceListResult to *KVNamespaceListResult.
//   - https://github.com/cloudflare/workers-types/blob/3012f263fb1239825e5f0061b267c8650d01b717/index.d.ts#L952
func toKVNamespaceListResult(v js.Value) (*KVNamespaceListResult, error) {
	keysVal := v.Get("keys")
	keys := make([]*KVNamespaceListKey, keysVal.Length())
	for i := 0; i < len(keys); i++ {
		key, err := toKVNamespaceListKey(keysVal.Index(i))
		if err != nil {
			return nil, fmt.Errorf("error converting to KVNamespaceListKey: %w", err)
		}
		keys[i] = key
	}

	cursorVal := v.Get("cursor")
	var cursor string
	if !cursorVal.IsUndefined() {
		cursor = cursorVal.String()
	}

	return &KVNamespaceListResult{
		Keys:         keys,
		ListComplete: v.Get("list_complete").Bool(),
		Cursor:       cursor,
	}, nil
}

// List lists keys stored into the KV namespace.
func (kv *KVNamespace) List(opts *KVNamespaceListOptions) (*KVNamespaceListResult, error) {
	p := kv.instance.Call("list", opts.toJS())
	v, err := jsutil.AwaitPromise(p)
	if err != nil {
		return nil, err
	}
	return toKVNamespaceListResult(v)
}

// KVNamespacePutOptions represents Cloudflare KV namespace put options.
//   - https://github.com/cloudflare/workers-types/blob/3012f263fb1239825e5f0061b267c8650d01b717/index.d.ts#L958
type KVNamespacePutOptions struct {
	Expiration    int
	ExpirationTTL int
	// Metadata // TODO: implement
}

func (opts *KVNamespacePutOptions) toJS() js.Value {
	if opts == nil {
		return js.Undefined()
	}
	obj := jsutil.NewObject()
	if opts.Expiration != 0 {
		obj.Set("expiration", opts.Expiration)
	}
	if opts.ExpirationTTL != 0 {
		obj.Set("expirationTtl", opts.ExpirationTTL)
	}
	return obj
}

// PutString puts string value into KV with key.
//   - if a network error happens, returns error.
func (kv *KVNamespace) PutString(key string, value string, opts *KVNamespacePutOptions) error {
	p := kv.instance.Call("put", key, value, opts.toJS())
	_, err := jsutil.AwaitPromise(p)
	if err != nil {
		return err
	}
	return nil
}

// PutReader puts stream value into KV with key.
//   - This method copies all bytes into memory for implementation restriction.
//   - if a network error happens, returns error.
func (kv *KVNamespace) PutReader(key string, value io.Reader, opts *KVNamespacePutOptions) error {
	// fetch body cannot be ReadableStream. see: https://github.com/whatwg/fetch/issues/1438
	b, err := io.ReadAll(value)
	if err != nil {
		return err
	}
	ua := jsutil.NewUint8Array(len(b))
	js.CopyBytesToJS(ua, b)
	p := kv.instance.Call("put", key, ua.Get("buffer"), opts.toJS())
	_, err = jsutil.AwaitPromise(p)
	if err != nil {
		return err
	}
	return nil
}

// Delete deletes key-value pair specified by the key.
//   - if a network error happens, returns error.
func (kv *KVNamespace) Delete(key string) error {
	p := kv.instance.Call("delete", key)
	_, err := jsutil.AwaitPromise(p)
	if err != nil {
		return err
	}
	return nil
}
