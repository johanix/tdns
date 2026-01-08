package tdns

import (
	"log"
	"net/http"
	"reflect"
	"strings"
	"time"

	core "github.com/johanix/tdns/v0.x/tdns/core"
)

// canBeNil returns true if the given reflect.Value can be nil
func canBeNil(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return true
	default:
		return false
	}
}

// isUnsupportedType checks if a type is unsupported for JSON serialization
func isUnsupportedType(v reflect.Value) bool {
	// Check for general unsupported kinds
	switch v.Kind() {
	case reflect.Func, reflect.Chan, reflect.Complex64, reflect.Complex128, reflect.UnsafePointer:
		return true
	default:
		// Check for types that contain "http.Client" which often has function fields
		typeName := v.Type().String()
		if strings.Contains(typeName, "http.Client") || strings.Contains(typeName, "http.RoundTripper") {
			return true
		}
		// Check for sync.Mutex and similar types
		if strings.HasPrefix(typeName, "sync.") {
			return true
		}
		return false
	}
}

// deepCopyAndSanitize creates a deep copy of v and removes unsupported fields.
func deepCopyAndSanitize(v interface{}) interface{} {
	if v == nil {
		return nil
	}

	// log.Printf("deepCopyAndSanitize: type of v: %T", v)

	// Check if the value is a cmap.ConcurrentMap
	// if cm, ok := v.(ConcurrentMap[interface{}, interface{}]); ok {
	if strings.Contains(reflect.TypeOf(v).String(), "ConcurrentMap") {
		log.Printf("deepCopyAndSanitize: ConcurrentMap found")
		// Convert to a regular map for serialization
		// regularMap := make(map[interface{}]interface{})
		cMap := core.NewStringer[AgentId, *Agent]()
		if cm, ok := v.(core.ConcurrentMap[AgentId, *Agent]); ok {
			log.Printf("deepCopyAndSanitize: ConcurrentMap, len(m.shards)=%d", cm.NumShards())
			if cm.NumShards() == 0 {
				log.Printf("deepCopyAndSanitize: ConcurrentMap: num shards=0, returning empty map")
				return cMap
			}
			// log.Printf("deepCopyAndSanitize: ConcurrentMap: %d keys: %v", len(cm.Keys()), cm.Keys())
			for item := range cm.IterBuffered() {
				// Recursively sanitize each value
				// log.Printf("deepCopyAndSanitize: ConcurrentMap: copying item: %v (type %T)", item.Key, item)
				if foo, ok := deepCopyAndSanitize(item.Val).(*Agent); ok {
					cMap.Set(item.Key, foo)
				}
			}
		} else {
			log.Printf("*** Warning: deepCopyAndSanitize: ConcurrentMap: not a ConcurrentMap[AgentId,*Agent]")
		}
		// log.Printf("deepCopyAndSanitize: ConcurrentMap, len(m.shards)=%d", cm.NumShards())
		// for item := range cm.IterBuffered() {
		// 	// Recursively sanitize each value
		// 	regularMap[item.Key] = deepCopyAndSanitize(item.Val)
		// }
		return cMap
	}

	if _, ok := v.(time.Time); ok {
		return v
	}

	// Special case for http.Request and http.Response which contain function fields
	if req, ok := v.(*http.Request); ok {
		// Create a simplified version of the request
		return map[string]interface{}{
			"method": req.Method,
			"url":    req.URL.String(),
			"host":   req.Host,
			"path":   req.URL.Path,
		}
	}

	// Special case for http.Client which contains function fields
	if _, ok := v.(*http.Client); ok {
		return map[string]interface{}{
			"type": "http.Client",
			"info": "HTTP client details omitted for serialization",
		}
	}

	val := reflect.ValueOf(v)

	// Handle special case for zero values
	if !val.IsValid() {
		return nil
	}

	// Handle unsupported types early
	if isUnsupportedType(val) {
		return nil
	}

	switch val.Kind() {
	case reflect.Ptr:
		// log.Printf("deepCopyAndSanitize: ptr: %s", val.Type().String())
		if canBeNil(val) && val.IsNil() {
			return nil
		}
		// Check if we're pointing to an unsupported type
		if isUnsupportedType(val.Elem()) {
			return nil
		}
		copy := reflect.New(val.Elem().Type())
		elemValue := deepCopyAndSanitize(val.Elem().Interface())
		if elemValue != nil {
			copy.Elem().Set(reflect.ValueOf(elemValue))
		}
		return copy.Interface()

	case reflect.Struct:
		// log.Printf("deepCopyAndSanitize: struct: %s", val.Type().String())
		if val.Type().String() == "time.Time" {
			return val
		}
		copy := reflect.New(val.Type()).Elem()
		for i := 0; i < val.NumField(); i++ {
			field := val.Field(i)
			copyField := copy.Field(i)
			fieldType := val.Type().Field(i)

			// Skip unexported fields
			if !field.CanInterface() {
				continue
			}

			// Skip fields that can't be set
			if !copyField.CanSet() {
				continue
			}

			// Skip fields with unsupported types
			if isUnsupportedType(field) {
				copyField.Set(reflect.Zero(field.Type()))
				continue
			}

			// Skip fields named "Body" in http.Request or http.Response
			if (val.Type().String() == "*http.Request" || val.Type().String() == "*http.Response") &&
				fieldType.Name == "Body" {
				copyField.Set(reflect.Zero(field.Type()))
				continue
			}

			// Skip fields named "Client" which might be http.Client
			if fieldType.Name == "Client" && field.Type().Kind() == reflect.Ptr {
				copyField.Set(reflect.Zero(field.Type()))
				continue
			}

			// Skip fields that might contain HTTP clients
			fieldTypeName := field.Type().String()
			if strings.Contains(fieldTypeName, "http.Client") || strings.Contains(fieldTypeName, "http.RoundTripper") {
				copyField.Set(reflect.Zero(field.Type()))
				continue
			}

			// Recursively copy supported types
			fieldValue := deepCopyAndSanitize(field.Interface())
			if fieldValue == nil {
				// If the sanitized value is nil, set to zero value
				copyField.Set(reflect.Zero(field.Type()))
			} else {
				// log.Printf("deepCopyAndSanitize: struct: field: %v (type %T)", field, field.Type().String())
				// Use a try-catch approach with defer/recover
				func() {
					// log.Printf("deepCopyAndSanitize: struct: field: %s", val.Type().Field(i).Name)
					defer func() {
						if r := recover(); r != nil {
							log.Printf("*** Warning: struct: field type: %s", reflect.TypeOf(v).String())
							log.Printf("*** Warning: Failed to set field #%d %s: %v", i, val.Type().Field(i).Name, r)
							// Set to zero value as fallback
							copyField.Set(reflect.Zero(field.Type()))
							// copyField.Set(reflect.ValueOf(""))
						}
					}()
					copyField.Set(reflect.ValueOf(fieldValue))
				}()
			}
		}
		return copy.Interface()

	case reflect.Slice:
		// log.Printf("deepCopyAndSanitize: slice: %s", val.Type().String())
		if canBeNil(val) && val.IsNil() {
			return nil
		}
		copy := reflect.MakeSlice(val.Type(), val.Len(), val.Cap())
		for i := 0; i < val.Len(); i++ {
			elemValue := deepCopyAndSanitize(val.Index(i).Interface())
			if elemValue != nil {
				func() {
					defer func() {
						if r := recover(); r != nil {
							log.Printf("Warning: Failed to set slice element %d: %v", i, r)
						}
					}()
					copy.Index(i).Set(reflect.ValueOf(elemValue))
				}()
			}
		}
		return copy.Interface()

	case reflect.Array:
		// Arrays can't be nil, so we don't need to check IsNil()
		copy := reflect.New(val.Type()).Elem()
		for i := 0; i < val.Len(); i++ {
			elemValue := deepCopyAndSanitize(val.Index(i).Interface())
			if elemValue != nil {
				func() {
					defer func() {
						if r := recover(); r != nil {
							log.Printf("Warning: Failed to set array element %d: %v", i, r)
						}
					}()
					copy.Index(i).Set(reflect.ValueOf(elemValue))
				}()
			}
		}
		return copy.Interface()

	case reflect.Map:
		if canBeNil(val) && val.IsNil() {
			return nil
		}
		copy := reflect.MakeMap(val.Type())
		for _, key := range val.MapKeys() {
			mapValue := val.MapIndex(key)

			// Skip unsupported values
			if isUnsupportedType(mapValue) {
				continue
			}

			elemValue := deepCopyAndSanitize(mapValue.Interface())
			if elemValue != nil {
				func() {
					defer func() {
						if r := recover(); r != nil {
							log.Printf("Warning: Failed to set map key %v: %v", key.Interface(), r)
						}
					}()
					copy.SetMapIndex(key, reflect.ValueOf(elemValue))
				}()
			}
		}
		return copy.Interface()

	case reflect.Interface:
		if canBeNil(val) && val.IsNil() {
			return nil
		}

		// Check if the concrete value is an unsupported type
		if isUnsupportedType(val.Elem()) {
			return nil
		}

		return deepCopyAndSanitize(val.Elem().Interface())

	default:
		// Return original value for basic types
		return v
	}
}

// SanitizeForJSON is a wrapper function that sanitizes a struct for JSON serialization
func SanitizeForJSON(v interface{}) interface{} {
	if v == nil {
		return nil
	}

	// Use recover to catch any panics during sanitization
	var result interface{}
	func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("Warning: Sanitization failed: %v", r)
				// Return a simplified version as fallback
				result = simplifiedCopy(v)
			}
		}()
		result = deepCopyAndSanitize(v)
	}()

	if result == nil {
		// If we got nil back, return an empty map to avoid null in JSON
		return map[string]interface{}{}
	}

	return result
}

// simplifiedCopy creates a very basic copy without using reflection
// This is a fallback for when deepCopyAndSanitize fails
func simplifiedCopy(v interface{}) interface{} {
	// Special case for http.Request
	if req, ok := v.(*http.Request); ok {
		return map[string]interface{}{
			"method": req.Method,
			"url":    req.URL.String(),
			"host":   req.Host,
		}
	}

	// For the fallback, we'll just return a simple map with basic info
	// This prevents the API from completely failing
	switch obj := v.(type) {
	case map[string]interface{}:
		// For maps, copy only string keys with simple values
		result := make(map[string]interface{})
		for k, v := range obj {
			switch v.(type) {
			case string, int, int64, float64, bool, nil:
				result[k] = v
			default:
				// Skip complex values
			}
		}
		return result
	default:
		// For other types, return a simple status message
		return map[string]interface{}{
			"status": "Object sanitized due to serialization issues",
			"type":   reflect.TypeOf(v).String(),
		}
	}
}
