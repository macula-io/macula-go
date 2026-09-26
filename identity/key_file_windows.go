//go:build windows

package identity

import (
	"fmt"
	"io/fs"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// On Windows a file's permissions are its DACL, not mode bits: Go reports
// every file as mode 666, so the mode check other platforms make would refuse
// every key file. A key file is saved with a protected DACL that grants the
// current user alone, and loaded only when its owner is the current user,
// SYSTEM or the Administrators group, and no one else is granted read access.
// SYSTEM and Administrators are let through as root is where there are mode
// bits: they can read any file whatever its DACL says.

// keyFileOpenFlags open a key file for reading.
const keyFileOpenFlags = os.O_RDONLY

// readRights are the access rights that let a trustee read a file's contents.
const readRights = windows.FILE_READ_DATA | windows.GENERIC_READ | windows.GENERIC_ALL | windows.MAXIMUM_ALLOWED

// currentUser is the SID of the user this process runs as.
func currentUser() (*windows.SID, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("identity: the current user: %w", err)
	}
	return user.User.Sid.Copy()
}

// restrictKeyFile gives f a protected DACL that grants the current user full
// control and no one else anything. It is set by path: a handle os.OpenFile
// opens has no right to change its own DACL.
func restrictKeyFile(f *os.File) error {
	user, err := currentUser()
	if err != nil {
		return err
	}
	dacl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.SET_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(user),
		},
	}}, nil)
	if err != nil {
		return fmt.Errorf("identity: the key file's DACL: %w", err)
	}
	return windows.SetNamedSecurityInfo(f.Name(), windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

// ownerOnlyFile refuses an opened key file that is not a regular file, whose
// owner is someone else, or whose DACL grants read access to anyone but the
// current user, SYSTEM and Administrators. The security descriptor is read
// through the opened handle, so it describes the file that is then read.
func ownerOnlyFile(f *os.File, info fs.FileInfo) error {
	if !info.Mode().IsRegular() {
		return ErrKeyFileNotRegular
	}
	user, err := currentUser()
	if err != nil {
		return err
	}
	sd, err := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("identity: the key file's security descriptor: %w", err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !trusted(owner, user) {
		return ErrKeyFileOwner
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("identity: the key file's DACL: %w", err)
	}
	// A missing DACL grants everyone everything.
	if dacl == nil {
		return ErrKeyFilePermissions
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return fmt.Errorf("identity: the key file's DACL: %w", err)
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
		default:
			// An allow entry of another shape (an object or callback ACE)
			// is not one this check can read: refused, never let through.
			return ErrKeyFilePermissions
		}
		if ace.Mask&readRights == 0 {
			continue
		}
		if !trusted((*windows.SID)(unsafe.Pointer(&ace.SidStart)), user) {
			return ErrKeyFilePermissions
		}
	}
	return nil
}

// trusted reports whether sid may own or read a key file: the current user,
// SYSTEM or the Administrators group.
func trusted(sid, user *windows.SID) bool {
	return sid.Equals(user) || sid.IsWellKnown(windows.WinLocalSystemSid) ||
		sid.IsWellKnown(windows.WinBuiltinAdministratorsSid)
}

// syncDir does nothing: Windows cannot sync a directory's entries.
func syncDir(string) error {
	return nil
}
