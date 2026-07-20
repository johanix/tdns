package stupidns

import (
	"strings"
)

/*
 * Compares two string slices and makes sure they have the same contents and
 * ordering.
 */
func orderedSliceCompare(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}

	for i, _ := range got {
		if got[i] != want[i] {
			return false
		}
	}

	return true
}

/*
 * Compares two string slices and makes sure they have the same contents.
 */
func unorderedSliceCompare(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}

	diff := make(map[string]int, len(got))
	for _, g := range got {
		if g == "" {
			continue
		}

		diff[g]++
	}

	for _, w := range want {
		if w == "" {
			continue
		}

		_, ok := diff[w]
		if !ok {
			return false
		}
		diff[w]--
		if diff[w] == 0 {
			delete(diff, w)
		}
	}

	return true
}

/*
 * Compares two string slices and makes sure they have the same contents and
 * ordering.
 * Ignores whitespaces when comparing the slice elements (the strings).
 */
func orderedSliceWithoutWhitespaceCompare(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}

	for i, _ := range got {
		if !_equalExceptWhitespace(got[i], want[i]) {
			return false
		}
	}

	return true
}

/*
 * Compares two string slices and makes sure they have the same contents.
 * Ignores whitespaces when comparing the slice elements (the strings).
 */
func unorderedSliceWithoutWhitespaceCompare(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}

	diff := make(map[string]int, len(got))
	for _, g := range got {
		if g == "" {
			continue
		}

		diff[strings.Join(strings.Fields(g), " ")]++
	}

	for _, w := range want {
		if w == "" {
			continue
		}

		_w := strings.Join(strings.Fields(w), " ")
		_, ok := diff[_w]
		if !ok {
			return false
		}
		diff[_w]--
		if diff[_w] == 0 {
			delete(diff, _w)
		}
	}

	return true
}

func _equalExceptWhitespace(a, b string) bool {
	aWords := strings.Fields(a)
	bWords := strings.Fields(b)

	if len(aWords) != len(bWords) {
		return false
	}

	for i, _ := range aWords {
		if aWords[i] != bWords[i] {
			return false
		}
	}

	return true
}
