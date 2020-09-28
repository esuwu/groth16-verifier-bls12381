package bn256

import (
	"bytes"
	"fmt"
	"github.com/esuwu/groth16-verifier-bls12381/bn256/utils/bn254"
)

type VerificationKey struct {
	AlphaG1 *bn254.PointG1
	BetaG2  *bn254.PointG2
	GammaG2 *bn254.PointG2
	DeltaG2 *bn254.PointG2
	Ic      []*bn254.PointG1
}

func GetVerificationKeyFromCompressed(vk []byte) (*VerificationKey, error) {
	reader := bytes.NewReader(vk)

	var g1Repr = make([]byte, 32)
	//var g2Repr = make([]byte, 64)

	// Alpha G1
	_, err := reader.Read(g1Repr)
	if err != nil {
		return nil, err
	}
	alphaG1, err := bn254.NewG1().FromCompressed(g1Repr)
	fmt.Println(alphaG1)
	if err != nil {
		return nil, err
	}




	return &VerificationKey{
		AlphaG1: alphaG1,
	}, nil
}
