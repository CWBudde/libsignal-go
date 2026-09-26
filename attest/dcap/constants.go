// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package dcap

import "encoding/hex"

// MRENCLAVE values (hex) of the enclaves libsignal v0.102.2 knows
// (constants.rs).
const (
	EnclaveIDSVR2Staging2026Q1   = "97f151f6ed078edbbfd72fa9cae694dcc08353f1f5e8d9ccd79a971b10ffc535" // ENCLAVE_ID_SVR2_2026Q1_STAGING
	EnclaveIDSVR2Prod2026Q1      = "1240acbd4aa26974184844c8a46b1022d3957ac8a76c1fd8f5b1a15141ee0708" // ENCLAVE_ID_SVR2_2026Q1_PROD
	EnclaveIDSVRBStaging2026Q1   = "97f151f6ed078edbbfd72fa9cae694dcc08353f1f5e8d9ccd79a971b10ffc535" // ENCLAVE_ID_SVRB_2026Q1_STAGING
	EnclaveIDSVRBProd2026Q1      = "bee62050df1072e3d9fdf7660bfaf4e4b71f5622db9de8b30fc5f4b9852d8359" // ENCLAVE_ID_SVRB_2026Q1_PROD
	EnclaveIDSVR2Staging2026Q2   = "3c699f4975aaa3d172c0aad042f94f031b2b03e10b9c19a45116a01693d83302" // ENCLAVE_ID_SVR2_2026Q2_STAGING
	EnclaveIDSVR2Prod2026Q2      = "ced8217b26228e4b210c985786999d095c4958a94faf37b14acaf25c4cbb02a4" // ENCLAVE_ID_SVR2_2026Q2_PROD
	EnclaveIDSVRBStaging2026Q2   = "3c699f4975aaa3d172c0aad042f94f031b2b03e10b9c19a45116a01693d83302" // ENCLAVE_ID_SVRB_2026Q2_STAGING
	EnclaveIDSVRBProd2026Q2      = "2048e20fcd07d0992c4907e8e04c5a85f1f993d195004c7342675343ca2e524b" // ENCLAVE_ID_SVRB_2026Q2_PROD
	EnclaveIDSVR2StagingV12026Q3 = "c9e8a0c4ead9434c1c66004fed3e186dd184299c216bc33359e46745c0fc7e16" // ENCLAVE_ID_SVR2_2026Q3_STAGING_V1
	EnclaveIDSVR2Staging2026Q3   = "0ff2d7d4efbe7cfc24ac069a16fba898928dbe6c40d500c8b6da55733c727d6e" // ENCLAVE_ID_SVR2_2026Q3_STAGING
	EnclaveIDSVR2Prod2026Q3      = "fdbbacdc0c043d0d53fe1440f62728de0386f45ab0a275bd8f99e03a02af355e" // ENCLAVE_ID_SVR2_2026Q3_PROD
	EnclaveIDSVRBStaging2026Q3   = "0ff2d7d4efbe7cfc24ac069a16fba898928dbe6c40d500c8b6da55733c727d6e" // ENCLAVE_ID_SVRB_2026Q3_STAGING
	EnclaveIDSVRBProd2026Q3      = "fdbbacdc0c043d0d53fe1440f62728de0386f45ab0a275bd8f99e03a02af355e" // ENCLAVE_ID_SVRB_2026Q3_PROD
	EnclaveIDCDSIStaging         = "6d9b9649fa3a337754a98059c66d48ac77aaca5299d3b27d6ed1e646c7c81c0a" // ENCLAVE_ID_CDSI_STAGING
	EnclaveIDCDSIProd            = "15637fa1e54fe655176d3df1a9f94b87c01ed377acaa570682dc5d72c95ef07b" // ENCLAVE_ID_CDSI_PROD
)

// commonAdvisories are the Intel advisories every known enclave mitigates.
var commonAdvisories = []string{"INTEL-SA-00615", "INTEL-SA-00657"}

// acceptableAdvisories lists the advisories each known enclave's build
// mitigates (constants.rs ACCEPTABLE_SW_ADVISORIES). Staging SVR2 and SVRB
// share MRENCLAVE values; like upstream's SmallMap, the first match wins.
var acceptableAdvisories = []struct {
	mrenclave  string
	advisories []string
}{
	{EnclaveIDSVR2Staging2026Q1, commonAdvisories},
	{EnclaveIDSVR2Prod2026Q1, commonAdvisories},
	{EnclaveIDSVRBStaging2026Q1, commonAdvisories},
	{EnclaveIDSVRBProd2026Q1, commonAdvisories},
	{EnclaveIDSVR2Staging2026Q2, commonAdvisories},
	{EnclaveIDSVR2Prod2026Q2, commonAdvisories},
	{EnclaveIDSVRBStaging2026Q2, commonAdvisories},
	{EnclaveIDSVRBProd2026Q2, commonAdvisories},
	{EnclaveIDSVR2StagingV12026Q3, commonAdvisories},
	{EnclaveIDSVR2Staging2026Q3, commonAdvisories},
	{EnclaveIDSVR2Prod2026Q3, commonAdvisories},
	{EnclaveIDSVRBStaging2026Q3, commonAdvisories},
	{EnclaveIDSVRBProd2026Q3, commonAdvisories},
	{EnclaveIDCDSIStaging, commonAdvisories},
	{EnclaveIDCDSIProd, commonAdvisories},
}

// SWAdvisories returns the software advisories known to be mitigated in
// the enclave with MRENCLAVE mrenclave; unknown enclaves mitigate none
// (util.rs get_sw_advisories).
func SWAdvisories(mrenclave []byte) []string {
	id := hex.EncodeToString(mrenclave)
	for _, e := range acceptableAdvisories {
		if e.mrenclave == id {
			return append([]string(nil), e.advisories...)
		}
	}
	return nil
}
