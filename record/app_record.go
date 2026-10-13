package record

import (
	"strings"

	"github.com/macula-io/macula-go/cbor"
)

// An app record (tag 0x17, macula#75) is an org's signed statement of one of
// its apps, so a reader can go from an app's MRI, mri:app:<realm>/<org>/<app>,
// to where it runs. It is signed by an org key, which its org_key names, lives
// at most 30 minutes, and is stored under its realm id, org name and app name.

// maxAppTextBytes bounds an app record's names and version.
const maxAppTextBytes = 64

// appPayloadOK reports whether an app record's payload holds exactly its seven
// fields, as macula_record's app_payload_ok/1 has them: realm_id and org_key as
// 32-byte ids; an org that is a real org namespace (not "_", not a node's
// "~<node_id>", no slash); an app name without a slash and a version, each 1
// to 64 bytes of text; services, each exactly a unique name and procedures all
// in the record's own org namespace, so an org cannot present another org's
// providers, or a bare node's, as part of its app; and an authorization of
// exactly org_directory, as bytes.
func appPayloadOK(payload cbor.Value, size int) bool {
	field := func(name string) cbor.Value {
		value, _ := payload.Get(name)
		return value
	}
	orgName, _ := field("org_name").AsText()
	appName, appIsText := field("app_name").AsText()
	version, versionIsText := field("version").AsText()
	services, servicesIsList := field("services").AsList()
	authorization, authorizationIsMap := field("authorization").AsMap()
	directory, _ := field("authorization").Get("org_directory")
	_, directoryIsBytes := directory.AsBytes()
	return size == 7 && isID(field("realm_id")) && isID(field("org_key")) && appOrg(orgName) &&
		appIsText && appText(appName) && !strings.Contains(appName, "/") && versionIsText && appText(version) &&
		servicesIsList && appServicesOK(services, orgName) &&
		authorizationIsMap && len(authorization) == 1 && directoryIsBytes
}

func appOrg(orgName string) bool {
	return orgName != "_" && !strings.HasPrefix(orgName, OwnNamespacePrefix) && appText(orgName) &&
		!strings.Contains(orgName, "/")
}

func appText(text string) bool {
	return len(text) > 0 && len(text) <= maxAppTextBytes
}

// appServicesOK reports whether each service is exactly a name and its
// procedures, the names unique and every procedure in orgName's namespace.
func appServicesOK(services []cbor.Value, orgName string) bool {
	names := make(map[string]bool, len(services))
	for _, service := range services {
		entries, isMap := service.AsMap()
		nameValue, _ := service.Get("name")
		name, nameIsText := nameValue.AsText()
		proceduresValue, _ := service.Get("procedures")
		procedures, proceduresIsList := proceduresValue.AsList()
		if !isMap || len(entries) != 2 || !nameIsText || !appText(name) || !proceduresIsList || names[name] {
			return false
		}
		for _, procedureValue := range procedures {
			procedure, isText := procedureValue.AsText()
			org, hasOrg, err := ProcedureOrg(procedure)
			if !isText || err != nil || !hasOrg || org != orgName {
				return false
			}
		}
		names[name] = true
	}
	return true
}

// AppRecordKey is the storage key of an app record, from the parts of the
// app's MRI, mri:app:<realm>/<org>/<app>: the realm id, the org name and the
// app name.
func AppRecordKey(realmID [32]byte, orgName, appName string) [32]byte {
	return derived(int64(TypeAppRecord), realmID[:], lengthPrefixed([]byte(orgName)), lengthPrefixed([]byte(appName)))
}
