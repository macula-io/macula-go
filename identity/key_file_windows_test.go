//go:build windows

package identity

import (
	"errors"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/macula-io/macula-go/profile"
)

// securityOf is a file's owner and DACL, read by path.
func securityOf(t *testing.T, path string) (*windows.SID, *windows.ACL, windows.SECURITY_DESCRIPTOR_CONTROL) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("GetNamedSecurityInfo: %v", err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		t.Fatalf("owner: %v", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatalf("DACL: %v", err)
	}
	control, _, err := sd.Control()
	if err != nil {
		t.Fatalf("control: %v", err)
	}
	return owner, dacl, control
}

// A saved key file's DACL is protected from inheritance and grants the
// current user alone, and the file loads.
func TestASavedWindowsKeyFileGrantsItsUserAlone(t *testing.T) {
	key := sharedKey(t, pureIdentityKey)
	path := savedKeyFile(t, key)
	user, err := currentUser()
	if err != nil {
		t.Fatal(err)
	}
	_, dacl, control := securityOf(t, path)
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Error("the key file's DACL inherits from its directory")
	}
	if dacl == nil || dacl.AceCount != 1 {
		t.Fatalf("the key file's DACL has %v entries, want one", dacl)
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &ace); err != nil {
		t.Fatal(err)
	}
	if sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)); !sid.Equals(user) {
		t.Errorf("the key file's one entry grants %v, want the current user %v", sid, user)
	}
	if _, err := LoadKey(path, PurposeIdentity, profile.PQPure); err != nil {
		t.Fatalf("LoadKey of a saved key file: %v", err)
	}
}

// grant adds an entry granting trustee rights to path's DACL.
func grant(t *testing.T, path string, trustee windows.WELL_KNOWN_SID_TYPE, rights windows.ACCESS_MASK) {
	t.Helper()
	sid, err := windows.CreateWellKnownSid(trustee)
	if err != nil {
		t.Fatal(err)
	}
	_, dacl, _ := securityOf(t, path)
	merged, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: rights,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(sid)},
	}}, dacl)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, merged, nil); err != nil {
		t.Fatal(err)
	}
}

// A key file anyone else may read is refused; one only SYSTEM or
// Administrators may also read loads, as root may read any file where there
// are mode bits.
func TestAWindowsKeyFileOthersCanReadIsRefused(t *testing.T) {
	key := sharedKey(t, pureIdentityKey)
	for _, c := range []struct {
		trustee windows.WELL_KNOWN_SID_TYPE
		rights  windows.ACCESS_MASK
		want    error
	}{
		{windows.WinWorldSid, windows.FILE_READ_DATA, ErrKeyFilePermissions},
		{windows.WinBuiltinUsersSid, windows.GENERIC_READ, ErrKeyFilePermissions},
		{windows.WinAuthenticatedUserSid, windows.GENERIC_ALL, ErrKeyFilePermissions},
		{windows.WinWorldSid, windows.FILE_READ_ATTRIBUTES, nil},
		{windows.WinLocalSystemSid, windows.GENERIC_ALL, nil},
		{windows.WinBuiltinAdministratorsSid, windows.GENERIC_ALL, nil},
	} {
		path := savedKeyFile(t, key)
		grant(t, path, c.trustee, c.rights)
		if _, err := LoadKey(path, PurposeIdentity, profile.PQPure); !errors.Is(err, c.want) {
			t.Errorf("a key file also granting %v %#x: LoadKey = %v, want %v", c.trustee, c.rights, err, c.want)
		}
	}
}

// A file with no DACL at all grants everyone everything, and is refused.
func TestAWindowsKeyFileWithoutADACLIsRefused(t *testing.T) {
	path := savedKeyFile(t, sharedKey(t, pureIdentityKey))
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION,
		nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKey(path, PurposeIdentity, profile.PQPure); !errors.Is(err, ErrKeyFilePermissions) {
		t.Fatalf("a key file with no DACL: LoadKey = %v, want ErrKeyFilePermissions", err)
	}
}
