package cloudflare

import (
	"fmt"
	"syscall/js"

	"github.com/syumai/workers/internal/jsutil"
)

// R2Objects represents Cloudflare R2 objects.
//   - https://github.com/cloudflare/workers-types/blob/3012f263fb1239825e5f0061b267c8650d01b717/index.d.ts#L1121
type R2Objects struct {
	Objects   []*R2Object
	Truncated bool
	// Cursor indicates next cursor of R2Objects.
	//   - This becomes empty string if cursor doesn't exist.
	Cursor            string
	DelimitedPrefixes []string
}

// toR2Objects converts JavaScript side's R2Objects to *R2Objects.
//   - https://github.com/cloudflare/workers-types/blob/3012f263fb1239825e5f0061b267c8650d01b717/index.d.ts#L1121
func toR2Objects(v js.Value) (*R2Objects, error) {
	objectsVal := v.Get("objects")
	objects := make([]*R2Object, objectsVal.Length())
	for i := 0; i < len(objects); i++ {
		obj, err := toR2Object(objectsVal.Index(i))
		if err != nil {
			return nil, fmt.Errorf("error converting to R2Object: %w", err)
		}
		objects[i] = obj
	}
	prefixesVal := v.Get("delimitedPrefixes")
	prefixes := make([]string, prefixesVal.Length())
	for i := 0; i < len(prefixes); i++ {
		prefixes[i] = prefixesVal.Index(i).String()
	}
	return &R2Objects{
		Objects:           objects,
		Truncated:         v.Get("truncated").Bool(),
		Cursor:            jsutil.MaybeString(v.Get("cursor")),
		DelimitedPrefixes: prefixes,
	}, nil
}
