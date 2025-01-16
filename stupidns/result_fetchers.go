package stupidns

/* For sanity tests */
func getEmptySlice(obj ...interface{}) []string {
	return make([]string, 0)
}

/* For sanity tests */
func getEmptyString(obj ...interface{}) []string {
	ret := make([]string, 1)
	ret[0] = ""
	return ret
}

/* For sanity tests */
func getFoo(obj ...interface{}) []string {
	ret := make([]string, 1)
	ret[0] = "foo"
	return ret
}

/* For sanity tests */
func getBar(obj ...interface{}) []string {
	ret := make([]string, 1)
	ret[0] = "bar"
	return ret
}

/* For sanity tests */
func getFooBar(obj ...interface{}) []string {
	ret := make([]string, 2)
	ret[0] = "foo"
	ret[1] = "bar"
	return ret
}

/* For sanity tests */
func getBarFoo(obj ...interface{}) []string {
	ret := make([]string, 2)
	ret[0] = "bar"
	ret[1] = "foo"
	return ret
}

func getFromBucket(obj ...interface{}) []string {
	if len(obj) != 1 {
		panic("\"getFromBucket\" requires one argument!")
	}

	var b Bucket = obj[0].(Bucket)
	return b.Get()
}
