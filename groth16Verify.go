package bls12381

import (
	"errors"
	"github.com/consensys/gurvy/bls381/fr"
	Proof "github.com/esuwu/groth16-verifier-bls12381/proof"
	VerificationKey "github.com/esuwu/groth16-verifier-bls12381/verificationKey"
	Verifier "github.com/esuwu/groth16-verifier-bls12381/verifier"
	"math/big"
)



func ReadInputs(inputs []byte) ([]fr.Element, error) {
	var result []fr.Element
	const sizeUint64 = 8
	const lenOneFrElement = 4

	if len(inputs) % 32 != 0 {
		return nil, errors.New("inputs should be % 32 = 0")
	}

	lenFrElements := len(inputs) / 32
	frReprSize := sizeUint64 * lenOneFrElement

	var currentOffset int
	var oldOffSet int

	// скармливаем чанками по 32 байта
	for i := 0; i < lenFrElements; i++ {
		currentOffset += frReprSize
		elem := fr.One()
		elem.SetBytes(inputs[oldOffSet:currentOffset])
		oldOffSet += frReprSize

		result = append(result, elem)
	}

	return result, nil
}

func makeSliceBigInt(inputs []fr.Element) []*big.Int {
	publicInput := make([]*big.Int, 0)
	for _, v := range inputs {
		z := new(big.Int)
		z.SetBytes(v.Bytes())
		publicInput = append(publicInput, z)
	}
	return publicInput
}

func Groth16Verify(vk []byte, proof []byte, inputs []byte) (bool, error) {
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

	vkT, _ := VerificationKey.GetVerificationKeyFromCompressed(vk)
	proofT, _ := Proof.GetProofFromCompressed(proof)
	inputsFr, err := ReadInputs(inputs)
	if err != nil {
		return false, err
	}

	if len(inputsFr) != inputsLen || len(vkT.Ic) != inputsLen + 1 {
		return false, err
	}

	return Verifier.ProofVerify(vkT, proofT, makeSliceBigInt(inputsFr))
}