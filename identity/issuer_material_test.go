package identity

import "testing"

// materialOf is issuer.ConnectMaterial(), and fails the test if it panics.
func materialOf(t *testing.T, issuer *StatementIssuer) (material ConnectMaterial, err error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("ConnectMaterial panicked: %v", r)
		}
	}()
	return issuer.ConnectMaterial()
}

// currentMaterial is issuer.ConnectMaterial(), and fails the test on an error.
func currentMaterial(t *testing.T, issuer *StatementIssuer) ConnectMaterial {
	t.Helper()
	material, err := materialOf(t, issuer)
	if err != nil {
		t.Fatalf("ConnectMaterial: %v", err)
	}
	return material
}
