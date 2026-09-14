// Package calibration holds the shared nesting calibration shapes.
package calibration

// Flat is S1: no control structure.
func Flat(x int) int {
	return x + 1
}

// OneBranch is S2: one control structure.
func OneBranch(x int) string {
	if x == 0 {
		return "zero"
	}
	return "other"
}

// BranchInBranch is S3: a control structure inside one.
func BranchInBranch(x, y int) string {
	if x == 0 {
		if y == 0 {
			return "both"
		}
		return "first_only"
	}
	return "neither"
}

// ThreeDeep is S4: three control structures deep.
func ThreeDeep(x, y, z int) string {
	if x == 0 {
		if y == 0 {
			if z == 0 {
				return "all"
			}
			return "two"
		}
		return "one"
	}
	return "none"
}

// ClosureInBody is S5: a closure in the function body.
func ClosureInBody(xs []int) []int {
	return apply(xs, func(x int) int { return x + 1 })
}

// ClosureInBranch is S6: a closure inside a branch.
func ClosureInBranch(xs []int) []int {
	if len(xs) > 0 {
		return apply(xs, func(x int) int { return x + 1 })
	}
	return nil
}

// BranchInClosure is S7: a control structure inside a closure.
func BranchInClosure(xs []int) []string {
	return label(xs, func(x int) string {
		if x == 0 {
			return "zero"
		}
		return "other"
	})
}

func apply(xs []int, f func(int) int) []int {
	out := make([]int, 0, len(xs))
	for _, x := range xs {
		out = append(out, f(x))
	}
	return out
}

func label(xs []int, f func(int) string) []string {
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		out = append(out, f(x))
	}
	return out
}
