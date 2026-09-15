package cbor

import "fmt"

// negativeText is the decimal of the negative integer -1-magnitude, for every
// magnitude a Value holds, the ones beyond int64's range included.
func negativeText(magnitude uint64) string {
	switch {
	case magnitude < 1<<63:
		return fmt.Sprintf("%d", -1-int64(magnitude))
	case magnitude < ^uint64(0):
		return fmt.Sprintf("-%d", magnitude+1)
	default:
		return "-18446744073709551616"
	}
}
