package bls12381

import (
	"errors"
	"math/big"
)

type Bls12381 struct {

}

type Bn256 struct {

}

func ReadInputs(inputs []byte) ([]*big.Int, error) {
	var result []*big.Int
	const sizeUint64 = 8
	const lenOneFrElement = 4

	if len(inputs)%32 != 0 {
		return nil, errors.New("inputs should be % 32 = 0")
	}

	lenFrElements := len(inputs) / 32
	frReprSize := sizeUint64 * lenOneFrElement

	var currentOffset int
	var oldOffSet int

	// Appending every 32 bytes [0..32], [32..64], ...
	for i := 0; i < lenFrElements; i++ {
		currentOffset += frReprSize
		elem := new(big.Int)
		elem.SetBytes((inputs)[oldOffSet:currentOffset])
		oldOffSet += frReprSize

		result = append(result, elem)
	}

	return result, nil
}


func (Bls12381) Groth16Verify(vk []byte, proof []byte, inputs []byte) (bool, error) {
	buffVkLen := len(vk)
	buffProofLen := len(proof)
	buffInputsLen := len(inputs)

	if buffVkLen % 48 != 0 || buffProofLen % 32 != 0 {
		return false, errors.New("wrong buffer length")
	}

	inputsLen := buffInputsLen / 32

	if (buffVkLen / 48) != (inputsLen + 8) || (buffProofLen != 192) {
		return false, errors.New("wrong buffer length")
	}

	vkT, _ := GetVerificationKeyFromCompressed(vk)
	proofT, _ := GetProofFromCompressed(proof)
	inputsFr, err := ReadInputs(inputs)
	if err != nil {
		return false, err
	}

	if len(inputsFr) != inputsLen || len(vkT.Ic) != inputsLen + 1 {
		return false, err
	}

	return ProofVerify(vkT, proofT, inputsFr)
}

func (Bn256) Groth16Verify(vk []byte, proof []byte, inputs []byte) (bool, error) {
	//TODO: implement function
	return false, nil
}
