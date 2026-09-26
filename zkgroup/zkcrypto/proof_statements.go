// Copyright 2020-2022 Signal Messenger, LLC.
// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package zkcrypto

import "github.com/cwbudde/libsignal-go/poksho"

// Statement order and first-occurrence argument order are part of the transcript.
// These are the statements in the pinned upstream crypto/proofs.rs.
func addEquation(s *poksho.Statement, lhs string, terms ...poksho.Term) {
	if err := s.Add(lhs, terms); err != nil {
		panic(err)
	} // fixed compile-time equations
}

func profileRequestProofStatement() *poksho.Statement {
	s := poksho.NewStatement()
	addEquation(s, "Y", poksho.Term{Scalar: "y", Point: "G"})
	addEquation(s, "D1", poksho.Term{Scalar: "r1", Point: "G"})
	addEquation(s, "E1", poksho.Term{Scalar: "r2", Point: "G"})
	addEquation(s, "J3", poksho.Term{Scalar: "j3", Point: "G_j3"})
	addEquation(s, "D2-J1", poksho.Term{Scalar: "r1", Point: "Y"}, poksho.Term{Scalar: "j3", Point: "-G_j1"})
	addEquation(s, "E2-J2", poksho.Term{Scalar: "r2", Point: "Y"}, poksho.Term{Scalar: "j3", Point: "-G_j2"})
	return s
}

func profileIssuanceProofStatement() *poksho.Statement {
	s := poksho.NewStatement()
	addEquation(s, "C_W", poksho.Term{Scalar: "w", Point: "G_w"}, poksho.Term{Scalar: "wprime", Point: "G_wprime"})
	addEquation(s, "G_V-I", poksho.Term{Scalar: "x0", Point: "G_x0"}, poksho.Term{Scalar: "x1", Point: "G_x1"}, poksho.Term{Scalar: "y1", Point: "G_y1"}, poksho.Term{Scalar: "y2", Point: "G_y2"}, poksho.Term{Scalar: "y3", Point: "G_y3"}, poksho.Term{Scalar: "y4", Point: "G_y4"}, poksho.Term{Scalar: "y5", Point: "G_y5"})
	addEquation(s, "S1", poksho.Term{Scalar: "y3", Point: "D1"}, poksho.Term{Scalar: "y4", Point: "E1"}, poksho.Term{Scalar: "rprime", Point: "G"})
	addEquation(s, "S2", poksho.Term{Scalar: "y3", Point: "D2"}, poksho.Term{Scalar: "y4", Point: "E2"}, poksho.Term{Scalar: "rprime", Point: "Y"}, poksho.Term{Scalar: "w", Point: "G_w"}, poksho.Term{Scalar: "x0", Point: "U"}, poksho.Term{Scalar: "x1", Point: "tU"}, poksho.Term{Scalar: "y1", Point: "M1"}, poksho.Term{Scalar: "y2", Point: "M2"}, poksho.Term{Scalar: "y5", Point: "M5"})
	return s
}

func receiptIssuanceProofStatement() *poksho.Statement {
	s := poksho.NewStatement()
	addEquation(s, "C_W", poksho.Term{Scalar: "w", Point: "G_w"}, poksho.Term{Scalar: "wprime", Point: "G_wprime"})
	addEquation(s, "G_V-I", poksho.Term{Scalar: "x0", Point: "G_x0"}, poksho.Term{Scalar: "x1", Point: "G_x1"}, poksho.Term{Scalar: "y1", Point: "G_y1"}, poksho.Term{Scalar: "y2", Point: "G_y2"})
	addEquation(s, "S1", poksho.Term{Scalar: "y2", Point: "D1"}, poksho.Term{Scalar: "rprime", Point: "G"})
	addEquation(s, "S2", poksho.Term{Scalar: "y2", Point: "D2"}, poksho.Term{Scalar: "rprime", Point: "Y"}, poksho.Term{Scalar: "w", Point: "G_w"}, poksho.Term{Scalar: "x0", Point: "U"}, poksho.Term{Scalar: "x1", Point: "tU"}, poksho.Term{Scalar: "y1", Point: "M1"})
	return s
}

func profilePresentationProofStatement() *poksho.Statement {
	s := poksho.NewStatement()
	addEquation(s, "Z", poksho.Term{Scalar: "z", Point: "I"})
	addEquation(s, "C_x1", poksho.Term{Scalar: "t", Point: "C_x0"}, poksho.Term{Scalar: "z0", Point: "G_x0"}, poksho.Term{Scalar: "z", Point: "G_x1"})
	addEquation(s, "A+B", poksho.Term{Scalar: "a1", Point: "G_a1"}, poksho.Term{Scalar: "a2", Point: "G_a2"}, poksho.Term{Scalar: "b1", Point: "G_b1"}, poksho.Term{Scalar: "b2", Point: "G_b2"})
	addEquation(s, "C_y2-E_A2", poksho.Term{Scalar: "z", Point: "G_y2"}, poksho.Term{Scalar: "a2", Point: "-E_A1"})
	addEquation(s, "E_A1", poksho.Term{Scalar: "a1", Point: "C_y1"}, poksho.Term{Scalar: "z1", Point: "G_y1"})
	addEquation(s, "C_y4-E_B2", poksho.Term{Scalar: "z", Point: "G_y4"}, poksho.Term{Scalar: "b2", Point: "-E_B1"})
	addEquation(s, "E_B1", poksho.Term{Scalar: "b1", Point: "C_y3"}, poksho.Term{Scalar: "z2", Point: "G_y3"})
	addEquation(s, "0", poksho.Term{Scalar: "z1", Point: "I"}, poksho.Term{Scalar: "a1", Point: "Z"})
	addEquation(s, "0", poksho.Term{Scalar: "z2", Point: "I"}, poksho.Term{Scalar: "b1", Point: "Z"})
	addEquation(s, "C_y5", poksho.Term{Scalar: "z", Point: "G_y5"})
	return s
}

func receiptPresentationProofStatement() *poksho.Statement {
	s := poksho.NewStatement()
	addEquation(s, "Z", poksho.Term{Scalar: "z", Point: "I"})
	addEquation(s, "C_x1", poksho.Term{Scalar: "t", Point: "C_x0"}, poksho.Term{Scalar: "-zt", Point: "G_x0"}, poksho.Term{Scalar: "z", Point: "G_x1"})
	addEquation(s, "C_y1", poksho.Term{Scalar: "z", Point: "G_y1"})
	addEquation(s, "C_y2", poksho.Term{Scalar: "z", Point: "G_y2"})
	return s
}
