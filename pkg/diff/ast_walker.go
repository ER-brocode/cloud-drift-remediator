package diff

import (
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/ER-brocode/cloud-drift-remediator/pkg/model"
)

// DiffOptions controls structural diff behavior.
type DiffOptions struct {
	IgnorePaths      []string
	IgnoreRegexes    []*regexp.Regexp
	MaskSensitive    bool
	EnableCoercion   bool
	IgnoreOrderLists bool
}

// DefaultDiffOptions returns standard production diff settings.
func DefaultDiffOptions() *DiffOptions {
	defaults := []string{
		`^id$`,
		`^arn$`,
		`^etag$`,
		`^version_id$`,
		`^schema_version$`,
		`.*\.id$`,
		`.*\.arn$`,
		`.*\.created_at$`,
		`.*\.updated_at$`,
		`.*\.etag$`,
		`.*\.version_id$`,
		`.*\.schema_version$`,
		`^tags\["aws:.*"\]$`,
	}
	var regexes []*regexp.Regexp
	for _, p := range defaults {
		if re, err := regexp.Compile(p); err == nil {
			regexes = append(regexes, re)
		}
	}
	return &DiffOptions{
		IgnorePaths:      defaults,
		IgnoreRegexes:    regexes,
		MaskSensitive:    true,
		EnableCoercion:   true,
		IgnoreOrderLists: true,
	}
}

// ASTWalker executes deep structural AST comparison between desired and live attributes.
type ASTWalker struct {
	opts    *DiffOptions
	resType model.ResourceType
}

// NewASTWalker constructs a new structural AST comparison walker.
func NewASTWalker(resType model.ResourceType, opts *DiffOptions) *ASTWalker {
	if opts == nil {
		opts = DefaultDiffOptions()
	}
	return &ASTWalker{
		opts:    opts,
		resType: resType,
	}
}

// Compare traverses desired and actual attribute trees, emitting granular FieldDiffs.
func (w *ASTWalker) Compare(desired, actual map[string]interface{}) []model.FieldDiff {
	var diffs []model.FieldDiff
	allKeys := make(map[string]bool)

	for k := range desired {
		allKeys[k] = true
	}
	for k := range actual {
		allKeys[k] = true
	}

	// Sort keys for deterministic diff order
	var sortedKeys []string
	for k := range allKeys {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Strings(sortedKeys)

	for _, k := range sortedKeys {
		dVal := desired[k]
		aVal := actual[k]
		diffs = append(diffs, w.compareNode(k, dVal, aVal)...)
	}

	return diffs
}

func (w *ASTWalker) compareNode(path string, desired, actual interface{}) []model.FieldDiff {
	if w.shouldIgnore(path) {
		return nil
	}

	// 1. Check for nil vs empty equivalence
	if w.opts.EnableCoercion && isNilOrEmpty(desired) && isNilOrEmpty(actual) {
		return nil
	}

	// 2. Missing attribute cases
	if desired == nil && actual != nil {
		sev, reason := ClassifyFieldSeverity(w.resType, path, desired, actual)
		return []model.FieldDiff{w.buildDiff(path, nil, actual, sev, reason)}
	}
	if desired != nil && actual == nil {
		sev, reason := ClassifyFieldSeverity(w.resType, path, desired, actual)
		return []model.FieldDiff{w.buildDiff(path, desired, nil, sev, reason)}
	}

	// 3. Try JSON string unmarshaling if both are string representations of JSON
	if w.opts.EnableCoercion {
		if dStr, ok := desired.(string); ok && strings.HasPrefix(strings.TrimSpace(dStr), "{") {
			if aStr, ok := actual.(string); ok && strings.HasPrefix(strings.TrimSpace(aStr), "{") {
				var dMap, aMap map[string]interface{}
				if err1 := json.Unmarshal([]byte(dStr), &dMap); err1 == nil {
					if err2 := json.Unmarshal([]byte(aStr), &aMap); err2 == nil {
						return w.compareMaps(path, dMap, aMap)
					}
				}
			}
		}
	}

	// 4. Handle Maps
	dMap, dIsMap := toMap(desired)
	aMap, aIsMap := toMap(actual)
	if dIsMap && aIsMap {
		return w.compareMaps(path, dMap, aMap)
	}

	// 5. Handle Slices
	dSlice, dIsSlice := toSlice(desired)
	aSlice, aIsSlice := toSlice(actual)
	if dIsSlice && aIsSlice {
		return w.compareSlices(path, dSlice, aSlice)
	}

	// 6. Primitive Comparison with Coercion
	if w.opts.EnableCoercion && areCoercedEqual(desired, actual) {
		return nil
	}

	if !reflect.DeepEqual(desired, actual) {
		sev, reason := ClassifyFieldSeverity(w.resType, path, desired, actual)
		return []model.FieldDiff{w.buildDiff(path, desired, actual, sev, reason)}
	}

	return nil
}

func (w *ASTWalker) compareMaps(parentPath string, desired, actual map[string]interface{}) []model.FieldDiff {
	var diffs []model.FieldDiff
	allKeys := make(map[string]bool)
	for k := range desired {
		allKeys[k] = true
	}
	for k := range actual {
		allKeys[k] = true
	}

	var sortedKeys []string
	for k := range allKeys {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Strings(sortedKeys)

	for _, k := range sortedKeys {
		childPath := fmt.Sprintf("%s.%s", parentPath, k)
		diffs = append(diffs, w.compareNode(childPath, desired[k], actual[k])...)
	}

	return diffs
}

func (w *ASTWalker) compareSlices(parentPath string, desired, actual []interface{}) []model.FieldDiff {
	// If length differs and elements don't align
	if len(desired) != len(actual) {
		sev, reason := ClassifyFieldSeverity(w.resType, parentPath, desired, actual)
		return []model.FieldDiff{w.buildDiff(parentPath, desired, actual, sev, reason)}
	}

	var diffs []model.FieldDiff
	for i := 0; i < len(desired); i++ {
		elemPath := fmt.Sprintf("%s[%d]", parentPath, i)
		diffs = append(diffs, w.compareNode(elemPath, desired[i], actual[i])...)
	}

	return diffs
}

func (w *ASTWalker) buildDiff(path string, desired, actual interface{}, sev model.DriftSeverity, reason string) model.FieldDiff {
	sensitive := isSensitivePath(path)
	dVal := desired
	aVal := actual

	if sensitive && w.opts.MaskSensitive {
		dVal = "********"
		aVal = "********"
	}

	return model.FieldDiff{
		Path:         path,
		DesiredValue: dVal,
		ActualValue:  aVal,
		Severity:     sev,
		Sensitive:    sensitive,
		Reason:       reason,
	}
}

func (w *ASTWalker) shouldIgnore(path string) bool {
	for _, re := range w.opts.IgnoreRegexes {
		if re.MatchString(path) {
			return true
		}
	}
	return false
}

func isSensitivePath(path string) bool {
	lower := strings.ToLower(path)
	sensitiveTerms := []string{
		"password",
		"secret",
		"token",
		"private_key",
		"key_material",
		"credential",
		"auth",
	}
	for _, t := range sensitiveTerms {
		if strings.Contains(lower, t) {
			return true
		}
	}
	return false
}

func isNilOrEmpty(v interface{}) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.String:
		return rv.Len() == 0
	case reflect.Slice, reflect.Array, reflect.Map:
		return rv.Len() == 0
	default:
		return false
	}
}

func areCoercedEqual(a, b interface{}) bool {
	if reflect.DeepEqual(a, b) {
		return true
	}

	// String vs Numeric
	strA := fmt.Sprintf("%v", a)
	strB := fmt.Sprintf("%v", b)
	if strA == strB {
		return true
	}

	// Bool string coercion
	if boolA, errA := strconv.ParseBool(strA); errA == nil {
		if boolB, errB := strconv.ParseBool(strB); errB == nil {
			return boolA == boolB
		}
	}

	// Float string coercion
	if fltA, errA := strconv.ParseFloat(strA, 64); errA == nil {
		if fltB, errB := strconv.ParseFloat(strB, 64); errB == nil {
			return fltA == fltB
		}
	}

	return false
}

func toMap(v interface{}) (map[string]interface{}, bool) {
	if v == nil {
		return nil, false
	}
	if m, ok := v.(map[string]interface{}); ok {
		return m, true
	}
	return nil, false
}

func toSlice(v interface{}) ([]interface{}, bool) {
	if v == nil {
		return nil, false
	}
	if s, ok := v.([]interface{}); ok {
		return s, true
	}
	rv := reflect.ValueOf(v)
	if rv.Kind() == reflect.Slice || rv.Kind() == reflect.Array {
		var out []interface{}
		for i := 0; i < rv.Len(); i++ {
			out = append(out, rv.Index(i).Interface())
		}
		return out, true
	}
	return nil, false
}
