package mkbfv

import (
	"flag"
	"fmt"
	"math"
	"math/big"
	"mk-lattigo/mkrlwe"
	"strconv"
	"testing"
	"time"

	"github.com/ldsec/lattigo/v2/ring"
	"github.com/ldsec/lattigo/v2/rlwe"
	"github.com/ldsec/lattigo/v2/utils"
	"github.com/stretchr/testify/require"
)

// import "github.com/ldsec/lattigo/v2/bfv"

// import "math"

func GetTestName(params Parameters, opname string) string {
	return fmt.Sprintf("%slogN=%d/logQP=%d/levels=%d",
		opname,
		params.LogN(),
		params.LogQP(),
		params.MaxLevel(),
	)
}

var maxGroups = flag.Int("n", 32, "maximum number of parties")

var PN15QP880 = ParametersLiteral{
	LogN: 15,

	Q: []uint64{
		// 10 * 54 + 4 * 55
		0x3fffffffd60001,
		0x3fffffff6d0001,
		0x3fffffff550001,
		0x3fffffff360001,
		0x3fffffff000001,
		0x3ffffffef40001,
		0x3ffffffed30001,
		0x3ffffffe970001,
		0x3ffffffe800001,
		0x3ffffffe410001,

		0x7fffffffe90001,
		0x7fffffffbd0001,
		0x7fffffffaa0001,
		0x7fffffff9f0001,
	},

	QMul: []uint64{
		// 10 * 54 + 4 * 55
		0x3fffffffca0001,
		0x3fffffff5d0001,
		0x3fffffff390001,
		0x3fffffff2a0001,
		0x3ffffffefa0001,
		0x3ffffffed70001,
		0x3ffffffeaa0001,
		0x3ffffffe920001,
		0x3ffffffe790001,
		0x3ffffffe320001,

		0x7fffffffbf0001,
		0x7fffffffba0001,
		0x7fffffffa50001,
		0x7fffffff7e0001,
	},

	P: []uint64{
		// 30, 45, 60 x 2

		//0x3ffc0001, 0x3fde0001,

		//0x1fffffc20001, 0x1fffff980001,

		0xffffffffffc0001, 0xfffffffff840001,
	},
	T:     65537,
	Sigma: rlwe.DefaultSigma,
}

var PN14QP439 = ParametersLiteral{
	LogN: 14,

	Q: []uint64{
		// 6 x 53
		0x200000000e0001, 0x20000000140001,
		0x200000007c0001, 0x20000000820001,
		0x20000001360001, 0x20000001460001,
	},

	QMul: []uint64{
		// 6 x 53
		0x20000000280001, 0x20000000640001,
		0x200000010c0001, 0x20000001180001,
		0x20000001520001, 0x200000015e0001,
	},
	P: []uint64{
		// 30, 45, 60 x 2

		// 0x3ffc0001, 0x3fde0001,

		//0x1fffffc20001, 0x1fffff980001,

		0xffffffffffc0001, 0xfffffffff840001,
	},
	T:     65537,
	Sigma: rlwe.DefaultSigma,
}

type testParams struct {
	params    Parameters
	ringQ     *ring.Ring
	ringP     *ring.Ring
	ringQMul  *ring.Ring
	ringR     *ring.Ring
	prng      utils.PRNG
	kgen      *KeyGenerator
	skSet     *mkrlwe.SecretKeySet
	pkSet     *mkrlwe.PublicKeySet
	rlkSet    *RelinearizationKeySet
	rtkSet    *mkrlwe.RotationKeySet
	cjkSet    *mkrlwe.ConjugationKeySet
	encryptor *Encryptor
	decryptor *Decryptor
	evaluator *Evaluator
	idset     *mkrlwe.IDSet

	swkSet     [1024]*mkrlwe.SWKSet
	swkheadSet [1024]*mkrlwe.SWKSet
}

func meanStdDuration(vals []time.Duration) (mean, std time.Duration) {
	var sum time.Duration
	for _, v := range vals {
		sum += v
	}
	mean = sum / time.Duration(len(vals))

	// std calculation
	var variance float64
	for _, v := range vals {
		diff := float64(v - mean)
		variance += diff * diff
	}
	variance /= float64(len(vals))

	std = time.Duration(math.Sqrt(variance))
	return
}

func meanStdDuration2(vals [][]time.Duration) (mean, std []time.Duration) {
	if len(vals) == 0 {
		return nil, nil
	}

	rows := len(vals)
	cols := len(vals[0])

	mean = make([]time.Duration, cols)
	std = make([]time.Duration, cols)

	// -----------------------
	// Mean (column-wise)
	// -----------------------
	for i := 0; i < rows; i++ {
		if len(vals[i]) != cols {
			panic("meanStdDurationMatrix: inconsistent inner slice length")
		}
		for j := 0; j < cols; j++ {
			mean[j] += vals[i][j]
		}
	}

	for j := 0; j < cols; j++ {
		mean[j] /= time.Duration(rows)
	}

	// -----------------------
	// Std (column-wise)
	// -----------------------
	for j := 0; j < cols; j++ {
		var variance float64
		meanF := float64(mean[j])

		for i := 0; i < rows; i++ {
			diff := float64(vals[i][j]) - meanF
			variance += diff * diff
		}

		variance /= float64(rows)
		std[j] = time.Duration(math.Sqrt(variance))
	}

	return
}

func meanStdFloat64(vals [][]float64) (mean, std []float64) {
	if len(vals) == 0 {
		return nil, nil
	}

	rows := len(vals)
	cols := len(vals[0])

	mean = make([]float64, cols)
	std = make([]float64, cols)

	// -----------------------
	// Mean (column-wise)
	// -----------------------
	for i := 0; i < rows; i++ {
		if len(vals[i]) != cols {
			panic("meanStdFloat64Matrix: inconsistent inner slice length")
		}
		for j := 0; j < cols; j++ {
			mean[j] += vals[i][j]
		}
	}

	for j := 0; j < cols; j++ {
		mean[j] /= float64(rows)
	}

	// -----------------------
	// Variance (column-wise)
	// -----------------------
	for i := 0; i < rows; i++ {
		for j := 0; j < cols; j++ {
			diff := vals[i][j] - mean[j]
			std[j] += diff * diff
		}
	}

	for j := 0; j < cols; j++ {
		std[j] = math.Sqrt(std[j] / float64(rows))
	}

	return
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

const iternum = 1

func Test_MPHE_BFV(t *testing.T) {

	// var expPartyset = [9]int{4, 8, 16, 32, 64, 128, 256, 512, 1024}
	var expPartyset = [2]int{512, 1024}
	for _, expParty := range expPartyset {
		fmt.Printf("Number of Parties Before Join = %d\n", expParty)

		numJoin := int(math.Log2(float64(expParty))) // 5

		KeyGen := make([]time.Duration, iternum)
		Switch := make([]time.Duration, iternum)
		EvalTime1 := make([]time.Duration, iternum)
		Extend := make([][]time.Duration, iternum)
		for i := 0; i < iternum; i++ {
			Extend[i] = make([]time.Duration, numJoin)
		}
		EvalTime2 := make([][]time.Duration, iternum)
		for i := 0; i < iternum; i++ {
			EvalTime2[i] = make([]time.Duration, numJoin)
		}

		logInfAbsErr := make([][]float64, iternum)
		for i := 0; i < iternum; i++ {
			logInfAbsErr[i] = make([]float64, numJoin)
		}
		Noisebudget := make([][]float64, iternum)
		for i := 0; i < iternum; i++ {
			Noisebudget[i] = make([]float64, numJoin)
		}

		for iter := 0; iter < iternum; iter++ {
			var (
				KeyGentemp, Switchtemp,
				EvalTime1temp time.Duration
				// , Extendtemp,
				// EvalTime2temp
				// logInfAbsErrtemp, Noisebudgettemp float64
			)

			defaultParams := []ParametersLiteral{PN15QP880} // PN14QP439, PN15QP880}
			for _, defaultParam := range defaultParams {

				numParties := expParty
				fmt.Printf("================= BFV_MPHE %d ===================\n\n\n", numParties)

				logJoin := int(math.Log2(float64(numParties)))

				// 1. SET-UP Phase
				KeyGenstart := time.Now()
				params := NewParametersFromLiteral(defaultParam)

				if params.PCount() < 2 {
					continue
				}

				*maxGroups = 1
				groupList := make([]string, *maxGroups)
				idset := mkrlwe.NewIDSet()
				for i := range groupList {
					groupList[i] = "group" + strconv.Itoa(i)
					idset.Add(groupList[i])
				}

				var testContext2 *testParams

				testContext2, _, _, _, _, _, _,
					_, _, _, _, _ = genTestParams(params, idset, numParties)

				KeyGentemp = time.Since(KeyGenstart)
				fmt.Print("KeyGen time =", KeyGentemp, "\n")

				// 2. Ctxt Generation
				numofctxtout := 1
				ctxtList := make([]*Ciphertext, numParties)
				ctxtUpdateList := make([]*Ciphertext, numofctxtout)
				msgList := make([]*Message, numParties)
				msgVals := make([]int64, testContext2.params.N())
				for k := 0; k < numParties; k++ {
					msgList[k], ctxtList[k] = newTestVectors(testContext2, "group0", (int64)(1), (int64)(2))
				}
				copy(msgVals, msgList[0].Value)

				// 3. Ctxt Mul
				EvalTime1start := time.Now()
				ctxts := make([]*Ciphertext, 0, numParties)
				for k := 0; k < numParties; k++ {
					ctxts = append(ctxts, ctxtList[k].CopyNew())
				}
				for len(ctxts) > 1 {
					var next []*Ciphertext
					for i := 0; i < len(ctxts); i += 2 {
						if i+1 < len(ctxts) {
							prod := testContext2.evaluator.MulRelinNew(ctxts[i], ctxts[i+1], testContext2.rlkSet)
							next = append(next, prod)
						} else {
							next = append(next, ctxts[i])
						}
					}
					ctxts = next
				}
				ctxtUpdateList[0] = ctxts[0]
				EvalTime1temp = time.Since(EvalTime1start)
				fmt.Print("EvalTime1 time = ", EvalTime1temp, "\n")

				// MPHE Error n parties
				logInfAbsErr[iter][logJoin-1], Noisebudget[iter][logJoin-1] = Error(testContext2, msgVals, ctxtUpdateList[0])

			}
			KeyGen[iter], Switch[iter], EvalTime1[iter] = KeyGentemp, Switchtemp, EvalTime1temp
		}

		KeyGenavg, KeyGenstd := meanStdDuration(KeyGen)
		Switchavg, Switchstd := meanStdDuration(Switch)
		EvalTime1avg, EvalTime1std := meanStdDuration(EvalTime1)
		Extendavg, Extendstd := meanStdDuration2(Extend)
		EvalTime2avg, EvalTime2std := meanStdDuration2(EvalTime2)

		logInfAbsErravg, logInfAbsErrstd := meanStdFloat64(logInfAbsErr)
		Noisebudgetavg, Noisebudgetstd := meanStdFloat64(Noisebudget)

		fmt.Println("KeyGen =", KeyGenavg, " (std: ", KeyGenstd, ")")
		fmt.Println("Switch =", Switchavg, " (std: ", Switchstd, ")")
		fmt.Println("EvalTime1 =", EvalTime1avg, " (std: ", EvalTime1std, ")")
		fmt.Println("Extend =", Extendavg, " (std: ", Extendstd, ")")
		fmt.Println("EvalTime2 =", EvalTime2avg, " (std: ", EvalTime2std, ")")

		fmt.Println("logInfAbsErr =", logInfAbsErravg, " (std: ", logInfAbsErrstd, ")")
		fmt.Println("Noisebudget =", Noisebudgetavg, " (std: ", Noisebudgetstd, ")")
	}
}

func Test_rdMPHE_BFV(t *testing.T) {

	// var PartySet = [9]int{2, 4, 8, 16, 32, 64, 128, 256, 512}
	var PartySet = [2]int{256, 512}
	for _, numParties := range PartySet {

		numJoin := int(math.Log2(float64(numParties))) // 5

		KeyGen := make([]time.Duration, iternum)
		Switch := make([]time.Duration, iternum)
		EvalTime1 := make([]time.Duration, iternum)
		Extend := make([][]time.Duration, iternum)
		for i := 0; i < iternum; i++ {
			Extend[i] = make([]time.Duration, numJoin)
		}
		EvalTime2 := make([][]time.Duration, iternum)
		for i := 0; i < iternum; i++ {
			EvalTime2[i] = make([]time.Duration, numJoin)
		}

		logInfAbsErr := make([][]float64, iternum)
		for i := 0; i < iternum; i++ {
			logInfAbsErr[i] = make([]float64, numJoin+1)
		}
		Noisebudget := make([][]float64, iternum)
		for i := 0; i < iternum; i++ {
			Noisebudget[i] = make([]float64, numJoin+1)
		}
		// Extend := make([][]time.Duration, iternum, numJoin)
		// EvalTime2 := make([][]time.Duration, iternum, numJoin)

		// logInfAbsErr := make([][]float64, iternum, numJoin+1)
		// Noisebudget := make([][]float64, iternum, numJoin+1)

		for iter := 0; iter < iternum; iter++ {
			numParties2 := numParties

			var (
				KeyGentemp, Switchtemp,
				EvalTime1temp time.Duration
				// , Extendtemp,
				// EvalTime2temp
				// logInfAbsErrtemp, Noisebudgettemp float64
			)

			defaultParams := []ParametersLiteral{PN15QP880} // PN14QP439, PN15QP880}
			for _, defaultParam := range defaultParams {
				fmt.Println("========Paramset=========")
				fmt.Printf("Number of Parties Before Join = %d\n", numParties2)
				// 1. SET-UP Phase
				KeyGenstart := time.Now()
				params := NewParametersFromLiteral(defaultParam)
				if params.PCount() < 2 {
					continue
				}
				*maxGroups = 1
				groupList := make([]string, *maxGroups)
				idset := mkrlwe.NewIDSet()
				for i := range groupList {
					groupList[i] = "group" + strconv.Itoa(i)
					idset.Add(groupList[i])
				}

				var (
					testContext2 *testParams
					sk           = make([]*mkrlwe.SecretKey, numParties2)
					gsk          *mkrlwe.SecretKey
					gpk          *mkrlwe.PublicKey
					grlk         *RelinearizationKey
					gcjk         *mkrlwe.ConjugationKey
					grtk         *mkrlwe.RotationKey
				)

				testContext2, _, gsk, gpk, grlk, gcjk, grtk,
					sk, _, _, _, _ =
					genTestParams(params, idset, numParties2)

				testContext2, _, _, _ = MPgenSWK(testContext2, gsk, gpk, sk, idset, numParties2)

				jk := mkrlwe.NewSWK(testContext2.params.Parameters, "group0")
				jkhead := mkrlwe.NewSWK(testContext2.params.Parameters, "group0")
				uaux := mkrlwe.NewSWK(testContext2.params.Parameters, "group0")
				uauxhead := mkrlwe.NewSWK(testContext2.params.Parameters, "group0")

				KeyGentemp = time.Since(KeyGenstart)
				fmt.Print("KeyGen time =", KeyGentemp, "\n")

				// 2. Pre-Eval
				numofctxtout := 1
				ctxtList := make([]*Ciphertext, numParties2)
				ctxtUpdateList := make([]*Ciphertext, numofctxtout)
				msgList := make([]*Message, numParties2)
				msgVals := make([]int64, testContext2.params.N())

				for j := range groupList {
					for i := 0; i < numParties2; i++ {
						msgList[i+j], ctxtList[i+j] = newTestVectors(testContext2, groupList[j], (int64)(1), (int64)(2))
					}
				}
				copy(msgVals, msgList[0].Value)

				for j := range groupList {
					for i := 0; i < numParties2; i++ {
						ctcache := testContext2.encryptor.EncryptSkMsgNew(msgList[i+j], sk[i+j])
						ctxtList[i+j] = ctcache.CopyNew()
					}
				}

				// Switch
				Switchstart := time.Now()
				for j := 0; j < len(groupList)-1+numParties2; j++ {
					var ctxtKS *Ciphertext
					ctxtKS = ctxtList[j].CopyNew()
					testContext2.evaluator.ksw.KS(ctxtList[j].Ciphertext, testContext2.swkSet[j].Value["group0"], testContext2.swkheadSet[j].Value["group0"], ctxtKS.Ciphertext)
					ctxtList[j] = ctxtKS
				}
				Switchtemp = time.Since(Switchstart)
				fmt.Print("Switch time = ", Switchtemp, "\n")

				// EvalTime1start := time.Now()
				// ctxtUpdateList[0] = ctxtList[0]
				// for k := 1; k < numParties; k++ {
				// 	ctxtUpdateList[0] = testContext2.evaluator.MulRelinNew(ctxtUpdateList[0], ctxtList[k], testContext2.rlkSet)
				// }
				// EvalTime1temp = time.Since(EvalTime1start)
				// fmt.Print("EvalTime1 time = ", EvalTime1temp, "\n")

				// 3. Ctxt Mul
				EvalTime1start := time.Now()
				ctxts := make([]*Ciphertext, 0, numParties2)
				for k := 0; k < numParties2; k++ {
					ctxts = append(ctxts, ctxtList[k].CopyNew())
				}
				for len(ctxts) > 1 {
					var next []*Ciphertext
					for i := 0; i < len(ctxts); i += 2 {
						if i+1 < len(ctxts) {
							prod := testContext2.evaluator.MulRelinNew(ctxts[i], ctxts[i+1], testContext2.rlkSet)
							next = append(next, prod)
						} else {
							next = append(next, ctxts[i])
						}
					}
					ctxts = next
				}
				ctxtUpdateList[0] = ctxts[0]
				EvalTime1temp = time.Since(EvalTime1start)
				fmt.Print("EvalTime1 time = ", EvalTime1temp, "\n")

				// MPHE Error n-1 parties
				logInfAbsErr[iter][0], Noisebudget[iter][0] = Error(testContext2, msgVals, ctxtUpdateList[0])

				for JoiningParties := numParties2; JoiningParties <= (1 << numJoin); JoiningParties = JoiningParties * 2 {

					logJoin := int(math.Log2(float64(JoiningParties)))

					fmt.Printf("================= BFV_rdMPHE %d ===================\n\n\n",
						numParties2+JoiningParties)

					// 3. Joining
					Extendstart := time.Now()

					testContext2, _, _, _, _, _, _, sk, _, _, _, _, ctxtUpdateList, _, _ =
						Join_rdMPHE(testContext2, gsk, gpk, grlk, gcjk, grtk, sk,
							jk, jkhead, uaux, uauxhead,
							idset, numParties2, JoiningParties, ctxtUpdateList, t)

					Extend[iter][logJoin-1] = time.Since(Extendstart)
					fmt.Print("Extend time = ", Extend[iter][logJoin-1], "\n")

					// // MPHE Error n parties
					// Error(testContext2, msgVals, ctxtUpdateList[0])

					// 4. Post-Eval
					// EvalTime2start := time.Now()

					ctxtUpdateList[0], EvalTime2[iter][logJoin-1] = VectorProd_After_Join(testContext2, groupList,
						numParties2, JoiningParties, ctxtUpdateList[0], 0, t)

					// EvalTime2[iter][logJoin] = time.Since(EvalTime2start)
					// fmt.Print("EvalTime2 time = ", EvalTime2[iter][logJoin], "\n")

					// msgRes2 := testContext2.decryptor.DecryptSk(ctxtUpdateList[0], gsk)
					// fmt.Print("ctxt after Post-Eval = ", msgRes2.Value[:2], "\n")

					// MPHE Error n parties
					logInfAbsErr[iter][logJoin], Noisebudget[iter][logJoin] = Error(testContext2, msgVals, ctxtUpdateList[0])

					numParties2 = numParties2 + JoiningParties
				}
			}

			KeyGen[iter], Switch[iter], EvalTime1[iter] = KeyGentemp, Switchtemp, EvalTime1temp
			// Extend[iter], EvalTime2[iter] = Extendtemp, EvalTime2temp
			// logInfAbsErr[iter], Noisebudget[iter] = logInfAbsErrtemp, Noisebudgettemp
		}

		KeyGenavg, KeyGenstd := meanStdDuration(KeyGen)
		Switchavg, Switchstd := meanStdDuration(Switch)
		EvalTime1avg, EvalTime1std := meanStdDuration(EvalTime1)
		Extendavg, Extendstd := meanStdDuration2(Extend)
		EvalTime2avg, EvalTime2std := meanStdDuration2(EvalTime2)

		logInfAbsErravg, logInfAbsErrstd := meanStdFloat64(logInfAbsErr)
		Noisebudgetavg, Noisebudgetstd := meanStdFloat64(Noisebudget)

		fmt.Println("KeyGen =", KeyGenavg, " (std: ", KeyGenstd, ")")
		fmt.Println("Switch =", Switchavg, " (std: ", Switchstd, ")")
		fmt.Println("EvalTime1 =", EvalTime1avg, " (std: ", EvalTime1std, ")")
		fmt.Println("Extend =", Extendavg, " (std: ", Extendstd, ")")
		fmt.Println("EvalTime2 =", EvalTime2avg, " (std: ", EvalTime2std, ")")

		fmt.Println("logInfAbsErr =", logInfAbsErravg, " (std: ", logInfAbsErrstd, ")")
		fmt.Println("Noisebudget =", Noisebudgetavg, " (std: ", Noisebudgetstd, ")")
	}
}

func Test_dMPHE_BFV(t *testing.T) {

	// var PartySet = [9]int{2, 4, 8, 16, 32, 64, 128, 256, 512}
	var PartySet = [2]int{256, 512}
	for _, numParties := range PartySet {
		fmt.Printf("Number of Parties Before Join = %d\n", numParties)

		numJoin := int(math.Log2(float64(numParties))) // 5

		KeyGen := make([]time.Duration, iternum)
		Switch := make([]time.Duration, iternum)
		EvalTime1 := make([]time.Duration, iternum)
		Extend := make([][]time.Duration, iternum)
		for i := 0; i < iternum; i++ {
			Extend[i] = make([]time.Duration, numJoin)
		}
		EvalTime2 := make([][]time.Duration, iternum)
		for i := 0; i < iternum; i++ {
			EvalTime2[i] = make([]time.Duration, numJoin)
		}

		logInfAbsErr := make([][]float64, iternum)
		for i := 0; i < iternum; i++ {
			logInfAbsErr[i] = make([]float64, numJoin+1)
		}
		Noisebudget := make([][]float64, iternum)
		for i := 0; i < iternum; i++ {
			Noisebudget[i] = make([]float64, numJoin+1)
		}

		for iter := 0; iter < iternum; iter++ {
			numParties2 := numParties
			var (
				KeyGentemp, Switchtemp,
				EvalTime1temp time.Duration
				// , Extendtemp,
				// EvalTime2temp
				// logInfAbsErrtemp, Noisebudgettemp float64
			)

			defaultParams := []ParametersLiteral{PN15QP880} // PN14QP439, PN15QP880}
			for _, defaultParam := range defaultParams {
				fmt.Println("========Paramset=========")

				// 1. SET-UP Phase
				KeyGenstart := time.Now()
				params := NewParametersFromLiteral(defaultParam)

				if params.PCount() < 2 {
					continue
				}

				*maxGroups = 1
				groupList := make([]string, *maxGroups)
				idset := mkrlwe.NewIDSet()
				for i := range groupList {
					groupList[i] = "group" + strconv.Itoa(i)
					idset.Add(groupList[i])
				}

				var (
					testContext2 *testParams

					gsk  *mkrlwe.SecretKey
					gpk  *mkrlwe.PublicKey
					grlk *RelinearizationKey
					gcjk *mkrlwe.ConjugationKey
					grtk *mkrlwe.RotationKey
				)

				testContext2, _, gsk, gpk, grlk, gcjk, grtk,
					_, _, _, _, _ = genTestParams(params, idset, numParties2)

				jk := mkrlwe.NewSWK(testContext2.params.Parameters, "group0")
				jkhead := mkrlwe.NewSWK(testContext2.params.Parameters, "group0")
				uaux := mkrlwe.NewSWK(testContext2.params.Parameters, "group0")
				uauxhead := mkrlwe.NewSWK(testContext2.params.Parameters, "group0")

				KeyGentemp = time.Since(KeyGenstart)
				fmt.Print("KeyGen time =", KeyGentemp, "\n")

				// 2. Pre-Eval
				numofctxtout := 1
				ctxtList := make([]*Ciphertext, numParties2)
				ctxtUpdateList := make([]*Ciphertext, numofctxtout)
				msgList := make([]*Message, numParties2)
				msgVals := make([]int64, testContext2.params.N())
				for k := 0; k < numParties2; k++ {
					msgList[k], ctxtList[k] = newTestVectors(testContext2, "group0", (int64)(1), (int64)(2))
				}
				copy(msgVals, msgList[0].Value)

				// EvalTime1start := time.Now()
				// ctxtUpdateList[0] = ctxtList[0]
				// for k := 1; k < numParties; k++ {
				// 	ctxtUpdateList[0] = testContext2.evaluator.MulRelinNew(ctxtUpdateList[0], ctxtList[k], testContext2.rlkSet)
				// }
				// EvalTime1temp = time.Since(EvalTime1start)
				// fmt.Print("EvalTime1 time = ", EvalTime1temp, "\n")

				// 3. Ctxt Mul
				EvalTime1start := time.Now()
				ctxts := make([]*Ciphertext, 0, numParties2)
				for k := 0; k < numParties2; k++ {
					ctxts = append(ctxts, ctxtList[k].CopyNew())
				}
				for len(ctxts) > 1 {
					var next []*Ciphertext
					for i := 0; i < len(ctxts); i += 2 {
						if i+1 < len(ctxts) {
							prod := testContext2.evaluator.MulRelinNew(ctxts[i], ctxts[i+1], testContext2.rlkSet)
							next = append(next, prod)
						} else {
							next = append(next, ctxts[i])
						}
					}
					ctxts = next
				}
				ctxtUpdateList[0] = ctxts[0]
				EvalTime1temp = time.Since(EvalTime1start)
				fmt.Print("EvalTime1 time = ", EvalTime1temp, "\n")

				// MPHE Error n-1 parties
				logInfAbsErr[iter][0], Noisebudget[iter][0] = Error(testContext2, msgVals, ctxtUpdateList[0])

				for JoiningParties := numParties2; JoiningParties <= (1 << numJoin); JoiningParties = JoiningParties * 2 {

					logJoin := int(math.Log2(float64(JoiningParties)))

					fmt.Printf("================= BFV_dMPHE %d ===================\n\n\n",
						numParties2+JoiningParties)

					// 3. Joining
					Extendstart := time.Now()

					testContext2, _, _, _, _, _, _, _, _, _, _, ctxtUpdateList, _, _ =
						Join_dMPHE(testContext2, gsk, gpk, grlk, gcjk, grtk,
							jk, jkhead, uaux, uauxhead,
							idset, numParties2, JoiningParties, ctxtUpdateList, t)

					Extend[iter][logJoin-1] = time.Since(Extendstart)
					fmt.Print("Extend time = ", Extend[iter][logJoin-1], "\n")

					// // MPHE Error n parties
					// Error(testContext2, msgVals, ctxtUpdateList[0])

					// 4. Post-Eval
					// EvalTime2start := time.Now()
					ctxtUpdateList[0], EvalTime2[iter][logJoin-1] = VectorProd_After_Join(testContext2, groupList,
						numParties2, JoiningParties, ctxtUpdateList[0], 0, t)

					// EvalTime2[iter][logJoin] = time.Since(EvalTime2start)
					// fmt.Print("EvalTime2 time = ", EvalTime2[iter][logJoin], "\n")

					// MPHE Error n parties
					logInfAbsErr[iter][logJoin], Noisebudget[iter][logJoin] = Error(testContext2, msgVals, ctxtUpdateList[0])

					numParties2 = numParties2 + JoiningParties
				}
			}
			KeyGen[iter], Switch[iter], EvalTime1[iter] = KeyGentemp, Switchtemp, EvalTime1temp
			// Extend[iter], EvalTime2[iter] = Extendtemp, EvalTime2temp
			// logInfAbsErr[iter], Noisebudget[iter] = logInfAbsErrtemp, Noisebudgettemp
		}

		KeyGenavg, KeyGenstd := meanStdDuration(KeyGen)
		Switchavg, Switchstd := meanStdDuration(Switch)
		EvalTime1avg, EvalTime1std := meanStdDuration(EvalTime1)
		Extendavg, Extendstd := meanStdDuration2(Extend)
		EvalTime2avg, EvalTime2std := meanStdDuration2(EvalTime2)

		logInfAbsErravg, logInfAbsErrstd := meanStdFloat64(logInfAbsErr)
		Noisebudgetavg, Noisebudgetstd := meanStdFloat64(Noisebudget)

		fmt.Println("KeyGen =", KeyGenavg, " (std: ", KeyGenstd, ")")
		fmt.Println("Switch =", Switchavg, " (std: ", Switchstd, ")")
		fmt.Println("EvalTime1 =", EvalTime1avg, " (std: ", EvalTime1std, ")")
		fmt.Println("Extend =", Extendavg, " (std: ", Extendstd, ")")
		fmt.Println("EvalTime2 =", EvalTime2avg, " (std: ", EvalTime2std, ")")

		fmt.Println("logInfAbsErr =", logInfAbsErravg, " (std: ", logInfAbsErrstd, ")")
		fmt.Println("Noisebudget =", Noisebudgetavg, " (std: ", Noisebudgetstd, ")")
	}
}

func Test_MKHE_BFV(t *testing.T) {

	// var PartySet = [9]int{2, 4, 8, 16, 32, 64, 128, 256, 512}
	var PartySet = [2]int{256, 512}
	for _, P := range PartySet {
		fmt.Printf("P = %d\n", P)

		numJoin := int(math.Log2(float64(P))) // 5
		KeyGen := make([]time.Duration, iternum)
		Switch := make([]time.Duration, iternum)
		EvalTime1 := make([]time.Duration, iternum)
		Extend := make([][]time.Duration, iternum)
		for i := 0; i < iternum; i++ {
			Extend[i] = make([]time.Duration, numJoin)
		}
		EvalTime2 := make([][]time.Duration, iternum)
		for i := 0; i < iternum; i++ {
			EvalTime2[i] = make([]time.Duration, numJoin)
		}

		logInfAbsErr := make([][]float64, iternum)
		for i := 0; i < iternum; i++ {
			logInfAbsErr[i] = make([]float64, numJoin+1)
		}
		Noisebudget := make([][]float64, iternum)
		for i := 0; i < iternum; i++ {
			Noisebudget[i] = make([]float64, numJoin+1)
		}

		for iter := 0; iter < iternum; iter++ {

			var (
				KeyGentemp, Switchtemp,
				EvalTime1temp time.Duration
				// , Extendtemp,
				// EvalTime2temp
				// logInfAbsErrtemp, Noisebudgettemp float64
			)

			defaultParams := []ParametersLiteral{PN15QP880} // PN14QP439, PN15QP880}
			for _, defaultParam := range defaultParams {

				for _, numGroups := range []int{P} {
					*maxGroups = numGroups
					numParties := 1

					fmt.Printf("================= MKHE_BFV %d ===================\n\n\n",
						numGroups)

					// ---------------- Key Generation ----------------
					KeyGenstart := time.Now()
					params := NewParametersFromLiteral(defaultParam)

					if params.PCount() < 2 {
						continue
					}

					groupList := make([]string, *maxGroups)
					idset := mkrlwe.NewIDSet()
					for i := range groupList {
						groupList[i] = "group" + strconv.Itoa(i)
						idset.Add(groupList[i])
					}

					var (
						testContext2 *testParams

						gsk  *mkrlwe.SecretKey
						gpk  *mkrlwe.PublicKey
						grlk *RelinearizationKey
						gcjk *mkrlwe.ConjugationKey
						grtk *mkrlwe.RotationKey
					)

					testContext2, _, gsk, gpk, grlk, gcjk, grtk,
						_, _, _, _, _ = genTestParams(params, idset, 1)

					_, _, _, _, _ = gsk, gpk, grlk, gcjk, grtk

					KeyGentemp = time.Since(KeyGenstart)
					fmt.Print("KeyGen time =", KeyGentemp, "\n")

					// 2. Pre-Eval
					numofctxtout := 1
					ctxtList := make([]*Ciphertext, numGroups)
					ctxtUpdateList := make([]*Ciphertext, numofctxtout)
					msgList := make([]*Message, numGroups)
					msgVals := make([]int64, testContext2.params.N())

					for j := range groupList {
						for i := 0; i < numParties; i++ {
							msgList[i+j], ctxtList[i+j] = newTestVectors(testContext2, groupList[j], (int64)(1), (int64)(2))
							// fmt.Print("ctxt group list = ", ctxtList[i+j].IDSet(), "\n")
						}
					}
					copy(msgVals, msgList[0].Value)

					// EvalTime1start := time.Now()
					// ctxtUpdateList[0] = ctxtList[0]
					// for k := 1; k < numGroups; k++ {
					// 	ctxtUpdateList[0] = testContext2.evaluator.MulRelinNew(ctxtUpdateList[0], ctxtList[k], testContext2.rlkSet)
					// }
					// EvalTime1temp = time.Since(EvalTime1start)
					// fmt.Print("EvalTime1 time = ", EvalTime1temp, "\n")

					// 3. Ctxt Mul
					EvalTime1start := time.Now()
					ctxts := make([]*Ciphertext, 0, numGroups)
					for k := 0; k < numGroups; k++ {
						ctxts = append(ctxts, ctxtList[k].CopyNew())
					}
					for len(ctxts) > 1 {
						var next []*Ciphertext
						for i := 0; i < len(ctxts); i += 2 {
							if i+1 < len(ctxts) {
								prod := testContext2.evaluator.MulRelinNew(ctxts[i], ctxts[i+1], testContext2.rlkSet)
								next = append(next, prod)
							} else {
								next = append(next, ctxts[i])
							}
						}
						ctxts = next
					}
					ctxtUpdateList[0] = ctxts[0]
					EvalTime1temp = time.Since(EvalTime1start)
					fmt.Print("EvalTime1 time = ", EvalTime1temp, "\n")

					// MPHE Error n-1 parties
					logInfAbsErr[iter][0], Noisebudget[iter][0] = Error(testContext2, msgVals, ctxtUpdateList[0])

					for JoiningParties := numGroups; JoiningParties <= (1 << numJoin); JoiningParties = JoiningParties * 2 {

						logJoin := int(math.Log2(float64(JoiningParties)))

						fmt.Printf("================= BFV_MKHE %d ===================\n\n\n",
							numGroups+JoiningParties)

						// 3. Joining
						Extendstart := time.Now()

						testContext2, idset, _ =
							testJoinPartyMK(testContext2, idset, groupList, 1, JoiningParties, t)

						groupListUp := make([]string, *maxGroups+1)
						for i := range groupListUp {
							groupListUp[i] = "group" + strconv.Itoa(i)
						}
						groupList = groupListUp

						Extend[iter][logJoin-1] = time.Since(Extendstart)
						fmt.Print("Extend time = ", Extend[iter][logJoin-1], "\n")

						// // MPHE Error n parties
						// Error(testContext2, msgVals, ctxtUpdateList[0])

						// 4. Post-Eval
						// EvalTime2start := time.Now()
						ctxtUpdateList[0], EvalTime2[iter][logJoin-1] = VectorProd_After_Join(testContext2, groupList,
							numParties, JoiningParties, ctxtUpdateList[0], 1, t)

						// EvalTime2[iter][logJoin] = time.Since(EvalTime2start)
						// fmt.Print("EvalTime2 time = ", EvalTime2[iter][logJoin], "\n")

						// MPHE Error n parties
						logInfAbsErr[iter][logJoin], Noisebudget[iter][logJoin] = Error(testContext2, msgVals, ctxtUpdateList[0])

						numGroups = numGroups + JoiningParties
					}
				}
			}

			KeyGen[iter], Switch[iter], EvalTime1[iter] = KeyGentemp, Switchtemp, EvalTime1temp
			// Extend[iter], EvalTime2[iter] = Extendtemp, EvalTime2temp
			// logInfAbsErr[iter], Noisebudget[iter] = logInfAbsErrtemp, Noisebudgettemp
		}

		KeyGenavg, KeyGenstd := meanStdDuration(KeyGen)
		Switchavg, Switchstd := meanStdDuration(Switch)
		EvalTime1avg, EvalTime1std := meanStdDuration(EvalTime1)
		Extendavg, Extendstd := meanStdDuration2(Extend)
		EvalTime2avg, EvalTime2std := meanStdDuration2(EvalTime2)

		logInfAbsErravg, logInfAbsErrstd := meanStdFloat64(logInfAbsErr)
		Noisebudgetavg, Noisebudgetstd := meanStdFloat64(Noisebudget)

		fmt.Println("KeyGen =", KeyGenavg, " (std: ", KeyGenstd, ")")
		fmt.Println("Switch =", Switchavg, " (std: ", Switchstd, ")")
		fmt.Println("EvalTime1 =", EvalTime1avg, " (std: ", EvalTime1std, ")")
		fmt.Println("Extend =", Extendavg, " (std: ", Extendstd, ")")
		fmt.Println("EvalTime2 =", EvalTime2avg, " (std: ", EvalTime2std, ")")

		fmt.Println("logInfAbsErr =", logInfAbsErravg, " (std: ", logInfAbsErrstd, ")")
		fmt.Println("Noisebudget =", Noisebudgetavg, " (std: ", Noisebudgetstd, ")")
	}
}

func Test_MPHE_BFV_fig(t *testing.T) {

	numJoin := 10
	KeyGen := make([]time.Duration, iternum)
	Switch := make([]time.Duration, iternum)
	EvalTime1 := make([]time.Duration, iternum)
	Extend := make([][]time.Duration, iternum)
	for i := 0; i < iternum; i++ {
		Extend[i] = make([]time.Duration, numJoin)
	}
	EvalTime2 := make([][]time.Duration, iternum)
	for i := 0; i < iternum; i++ {
		EvalTime2[i] = make([]time.Duration, numJoin)
	}

	logInfAbsErr := make([][]float64, iternum)
	for i := 0; i < iternum; i++ {
		logInfAbsErr[i] = make([]float64, numJoin)
	}
	Noisebudget := make([][]float64, iternum)
	for i := 0; i < iternum; i++ {
		Noisebudget[i] = make([]float64, numJoin)
	}

	for iter := 0; iter < iternum; iter++ {
		var (
			KeyGentemp, Switchtemp,
			EvalTime1temp time.Duration
			// , Extendtemp,
			// EvalTime2temp
			// logInfAbsErrtemp, Noisebudgettemp float64
		)

		defaultParams := []ParametersLiteral{PN15QP880} // PN14QP439, PN15QP880}
		for _, defaultParam := range defaultParams {
			fmt.Println("========Paramset=========")

			for numParties := 2; numParties <= (1 << numJoin); numParties = numParties * 2 {
				fmt.Printf("================= BFV_MPHE %d ===================\n\n\n", numParties)

				logJoin := int(math.Log2(float64(numParties)))

				// 1. SET-UP Phase
				KeyGenstart := time.Now()
				params := NewParametersFromLiteral(defaultParam)

				if params.PCount() < 2 {
					continue
				}

				*maxGroups = 1
				groupList := make([]string, *maxGroups)
				idset := mkrlwe.NewIDSet()
				for i := range groupList {
					groupList[i] = "group" + strconv.Itoa(i)
					idset.Add(groupList[i])
				}

				var testContext2 *testParams

				testContext2, _, _, _, _, _, _,
					_, _, _, _, _ = genTestParams(params, idset, numParties)

				KeyGentemp = time.Since(KeyGenstart)
				fmt.Print("KeyGen time =", KeyGentemp, "\n")

				// 2. Ctxt Generation
				numofctxtout := 1
				ctxtList := make([]*Ciphertext, numParties)
				ctxtUpdateList := make([]*Ciphertext, numofctxtout)
				msgList := make([]*Message, numParties)
				msgVals := make([]int64, testContext2.params.N())
				for k := 0; k < numParties; k++ {
					msgList[k], ctxtList[k] = newTestVectors(testContext2, "group0", (int64)(1), (int64)(2))
				}
				copy(msgVals, msgList[0].Value)

				// 3. Ctxt Mul
				EvalTime1start := time.Now()
				ctxts := make([]*Ciphertext, 0, numParties)
				for k := 0; k < numParties; k++ {
					ctxts = append(ctxts, ctxtList[k].CopyNew())
				}
				for len(ctxts) > 1 {
					var next []*Ciphertext
					for i := 0; i < len(ctxts); i += 2 {
						if i+1 < len(ctxts) {
							prod := testContext2.evaluator.MulRelinNew(ctxts[i], ctxts[i+1], testContext2.rlkSet)
							next = append(next, prod)
						} else {
							next = append(next, ctxts[i])
						}
					}
					ctxts = next
				}
				ctxtUpdateList[0] = ctxts[0]
				EvalTime1temp = time.Since(EvalTime1start)
				fmt.Print("EvalTime1 time = ", EvalTime1temp, "\n")

				// MPHE Error n parties
				logInfAbsErr[iter][logJoin-1], Noisebudget[iter][logJoin-1] = Error(testContext2, msgVals, ctxtUpdateList[0])
			}
		}
		KeyGen[iter], Switch[iter], EvalTime1[iter] = KeyGentemp, Switchtemp, EvalTime1temp
	}

	KeyGenavg, KeyGenstd := meanStdDuration(KeyGen)
	Switchavg, Switchstd := meanStdDuration(Switch)
	EvalTime1avg, EvalTime1std := meanStdDuration(EvalTime1)
	Extendavg, Extendstd := meanStdDuration2(Extend)
	EvalTime2avg, EvalTime2std := meanStdDuration2(EvalTime2)

	logInfAbsErravg, logInfAbsErrstd := meanStdFloat64(logInfAbsErr)
	Noisebudgetavg, Noisebudgetstd := meanStdFloat64(Noisebudget)

	fmt.Println("KeyGen =", KeyGenavg, " (std: ", KeyGenstd, ")")
	fmt.Println("Switch =", Switchavg, " (std: ", Switchstd, ")")
	fmt.Println("EvalTime1 =", EvalTime1avg, " (std: ", EvalTime1std, ")")
	fmt.Println("Extend =", Extendavg, " (std: ", Extendstd, ")")
	fmt.Println("EvalTime2 =", EvalTime2avg, " (std: ", EvalTime2std, ")")

	fmt.Println("logInfAbsErr =", logInfAbsErravg, " (std: ", logInfAbsErrstd, ")")
	fmt.Println("Noisebudget =", Noisebudgetavg, " (std: ", Noisebudgetstd, ")")

}

func Test_rdMPHE_BFV_fig(t *testing.T) {
	var PartySet = [1]int{2} // , 3, 7, 15, 31
	for _, numParties := range PartySet {
		fmt.Printf("Number of Parties Before Join = %d\n", numParties)

		numJoin := 9
		KeyGen := make([]time.Duration, iternum)
		Switch := make([]time.Duration, iternum)
		EvalTime1 := make([]time.Duration, iternum)
		Extend := make([][]time.Duration, iternum)
		for i := 0; i < iternum; i++ {
			Extend[i] = make([]time.Duration, numJoin)
		}
		EvalTime2 := make([][]time.Duration, iternum)
		for i := 0; i < iternum; i++ {
			EvalTime2[i] = make([]time.Duration, numJoin)
		}

		logInfAbsErr := make([][]float64, iternum)
		for i := 0; i < iternum; i++ {
			logInfAbsErr[i] = make([]float64, numJoin+1)
		}
		Noisebudget := make([][]float64, iternum)
		for i := 0; i < iternum; i++ {
			Noisebudget[i] = make([]float64, numJoin+1)
		}
		// Extend := make([][]time.Duration, iternum, numJoin)
		// EvalTime2 := make([][]time.Duration, iternum, numJoin)

		// logInfAbsErr := make([][]float64, iternum, numJoin+1)
		// Noisebudget := make([][]float64, iternum, numJoin+1)

		for iter := 0; iter < iternum; iter++ {
			numParties = PartySet[0]

			var (
				KeyGentemp, Switchtemp,
				EvalTime1temp time.Duration
				// , Extendtemp,
				// EvalTime2temp
				// logInfAbsErrtemp, Noisebudgettemp float64
			)

			defaultParams := []ParametersLiteral{PN15QP880} // PN14QP439, PN15QP880}
			for _, defaultParam := range defaultParams {
				fmt.Println("========Paramset=========")

				// 1. SET-UP Phase
				KeyGenstart := time.Now()
				params := NewParametersFromLiteral(defaultParam)
				if params.PCount() < 2 {
					continue
				}
				*maxGroups = 1
				groupList := make([]string, *maxGroups)
				idset := mkrlwe.NewIDSet()
				for i := range groupList {
					groupList[i] = "group" + strconv.Itoa(i)
					idset.Add(groupList[i])
				}

				var (
					testContext2 *testParams
					sk           = make([]*mkrlwe.SecretKey, numParties)
					gsk          *mkrlwe.SecretKey
					gpk          *mkrlwe.PublicKey
					grlk         *RelinearizationKey
					gcjk         *mkrlwe.ConjugationKey
					grtk         *mkrlwe.RotationKey
				)

				testContext2, _, gsk, gpk, grlk, gcjk, grtk,
					sk, _, _, _, _ =
					genTestParams(params, idset, numParties)

				testContext2, _, _, _ = MPgenSWK(testContext2, gsk, gpk, sk, idset, numParties)

				jk := mkrlwe.NewSWK(testContext2.params.Parameters, "group0")
				jkhead := mkrlwe.NewSWK(testContext2.params.Parameters, "group0")
				uaux := mkrlwe.NewSWK(testContext2.params.Parameters, "group0")
				uauxhead := mkrlwe.NewSWK(testContext2.params.Parameters, "group0")

				KeyGentemp = time.Since(KeyGenstart)
				fmt.Print("KeyGen time =", KeyGentemp, "\n")

				// 2. Pre-Eval
				numofctxtout := 1
				ctxtList := make([]*Ciphertext, numParties)
				ctxtUpdateList := make([]*Ciphertext, numofctxtout)
				msgList := make([]*Message, numParties)
				msgVals := make([]int64, testContext2.params.N())

				for j := range groupList {
					for i := 0; i < numParties; i++ {
						msgList[i+j], ctxtList[i+j] = newTestVectors(testContext2, groupList[j], (int64)(1), (int64)(2))
					}
				}
				copy(msgVals, msgList[0].Value)

				for j := range groupList {
					for i := 0; i < numParties; i++ {
						ctcache := testContext2.encryptor.EncryptSkMsgNew(msgList[i+j], sk[i+j])
						ctxtList[i+j] = ctcache.CopyNew()
					}
				}

				// Switch
				Switchstart := time.Now()
				for j := 0; j < len(groupList)-1+numParties; j++ {
					var ctxtKS *Ciphertext
					ctxtKS = ctxtList[j].CopyNew()
					testContext2.evaluator.ksw.KS(ctxtList[j].Ciphertext, testContext2.swkSet[j].Value["group0"], testContext2.swkheadSet[j].Value["group0"], ctxtKS.Ciphertext)
					ctxtList[j] = ctxtKS
				}
				Switchtemp = time.Since(Switchstart)
				fmt.Print("Switch time = ", Switchtemp, "\n")

				EvalTime1start := time.Now()
				ctxtUpdateList[0] = ctxtList[0]
				for k := 1; k < numParties; k++ {
					ctxtUpdateList[0] = testContext2.evaluator.MulRelinNew(ctxtUpdateList[0], ctxtList[k], testContext2.rlkSet)
				}
				EvalTime1temp = time.Since(EvalTime1start)
				fmt.Print("EvalTime1 time = ", EvalTime1temp, "\n")

				// MPHE Error n-1 parties
				logInfAbsErr[iter][0], Noisebudget[iter][0] = Error(testContext2, msgVals, ctxtUpdateList[0])

				for JoiningParties := 2; JoiningParties <= (1 << numJoin); JoiningParties = JoiningParties * 2 {

					logJoin := int(math.Log2(float64(JoiningParties)))

					fmt.Printf("================= BFV_rdMPHE %d ===================\n\n\n",
						numParties+JoiningParties)

					// 3. Joining
					Extendstart := time.Now()

					testContext2, _, _, _, _, _, _, sk, _, _, _, _, ctxtUpdateList, _, _ =
						Join_rdMPHE(testContext2, gsk, gpk, grlk, gcjk, grtk, sk,
							jk, jkhead, uaux, uauxhead,
							idset, numParties, JoiningParties, ctxtUpdateList, t)

					Extend[iter][logJoin-1] = time.Since(Extendstart)
					fmt.Print("Extend time = ", Extend[iter][logJoin-1], "\n")

					// // MPHE Error n parties
					// Error(testContext2, msgVals, ctxtUpdateList[0])

					// 4. Post-Eval
					// EvalTime2start := time.Now()

					ctxtUpdateList[0], EvalTime2[iter][logJoin-1] = VectorProd_After_Join(testContext2, groupList,
						numParties, JoiningParties, ctxtUpdateList[0], 0, t)

					// EvalTime2[iter][logJoin] = time.Since(EvalTime2start)
					// fmt.Print("EvalTime2 time = ", EvalTime2[iter][logJoin], "\n")

					// msgRes2 := testContext2.decryptor.DecryptSk(ctxtUpdateList[0], gsk)
					// fmt.Print("ctxt after Post-Eval = ", msgRes2.Value[:2], "\n")

					// MPHE Error n parties
					logInfAbsErr[iter][logJoin], Noisebudget[iter][logJoin] = Error(testContext2, msgVals, ctxtUpdateList[0])

					numParties = numParties + JoiningParties
				}
			}

			KeyGen[iter], Switch[iter], EvalTime1[iter] = KeyGentemp, Switchtemp, EvalTime1temp
			// Extend[iter], EvalTime2[iter] = Extendtemp, EvalTime2temp
			// logInfAbsErr[iter], Noisebudget[iter] = logInfAbsErrtemp, Noisebudgettemp
		}

		KeyGenavg, KeyGenstd := meanStdDuration(KeyGen)
		Switchavg, Switchstd := meanStdDuration(Switch)
		EvalTime1avg, EvalTime1std := meanStdDuration(EvalTime1)
		Extendavg, Extendstd := meanStdDuration2(Extend)
		EvalTime2avg, EvalTime2std := meanStdDuration2(EvalTime2)

		logInfAbsErravg, logInfAbsErrstd := meanStdFloat64(logInfAbsErr)
		Noisebudgetavg, Noisebudgetstd := meanStdFloat64(Noisebudget)

		fmt.Println("KeyGen =", KeyGenavg, " (std: ", KeyGenstd, ")")
		fmt.Println("Switch =", Switchavg, " (std: ", Switchstd, ")")
		fmt.Println("EvalTime1 =", EvalTime1avg, " (std: ", EvalTime1std, ")")
		fmt.Println("Extend =", Extendavg, " (std: ", Extendstd, ")")
		fmt.Println("EvalTime2 =", EvalTime2avg, " (std: ", EvalTime2std, ")")

		fmt.Println("logInfAbsErr =", logInfAbsErravg, " (std: ", logInfAbsErrstd, ")")
		fmt.Println("Noisebudget =", Noisebudgetavg, " (std: ", Noisebudgetstd, ")")
	}
}

func Test_dMPHE_BFV_fig(t *testing.T) {
	var PartySet = [1]int{2} // , 3, 7, 15, 31
	for _, numParties := range PartySet {
		fmt.Printf("Number of Parties Before Join = %d\n", numParties)

		numJoin := 9
		KeyGen := make([]time.Duration, iternum)
		Switch := make([]time.Duration, iternum)
		EvalTime1 := make([]time.Duration, iternum)
		Extend := make([][]time.Duration, iternum)
		for i := 0; i < iternum; i++ {
			Extend[i] = make([]time.Duration, numJoin)
		}
		EvalTime2 := make([][]time.Duration, iternum)
		for i := 0; i < iternum; i++ {
			EvalTime2[i] = make([]time.Duration, numJoin)
		}

		logInfAbsErr := make([][]float64, iternum)
		for i := 0; i < iternum; i++ {
			logInfAbsErr[i] = make([]float64, numJoin+1)
		}
		Noisebudget := make([][]float64, iternum)
		for i := 0; i < iternum; i++ {
			Noisebudget[i] = make([]float64, numJoin+1)
		}

		for iter := 0; iter < iternum; iter++ {
			numParties = PartySet[0]
			var (
				KeyGentemp, Switchtemp,
				EvalTime1temp time.Duration
				// , Extendtemp,
				// EvalTime2temp
				// logInfAbsErrtemp, Noisebudgettemp float64
			)

			defaultParams := []ParametersLiteral{PN15QP880} // PN14QP439, PN15QP880}
			for _, defaultParam := range defaultParams {
				fmt.Println("========Paramset=========")

				// 1. SET-UP Phase
				KeyGenstart := time.Now()
				params := NewParametersFromLiteral(defaultParam)

				if params.PCount() < 2 {
					continue
				}

				*maxGroups = 1
				groupList := make([]string, *maxGroups)
				idset := mkrlwe.NewIDSet()
				for i := range groupList {
					groupList[i] = "group" + strconv.Itoa(i)
					idset.Add(groupList[i])
				}

				var (
					testContext2 *testParams

					gsk  *mkrlwe.SecretKey
					gpk  *mkrlwe.PublicKey
					grlk *RelinearizationKey
					gcjk *mkrlwe.ConjugationKey
					grtk *mkrlwe.RotationKey
				)

				testContext2, _, gsk, gpk, grlk, gcjk, grtk,
					_, _, _, _, _ = genTestParams(params, idset, numParties)

				jk := mkrlwe.NewSWK(testContext2.params.Parameters, "group0")
				jkhead := mkrlwe.NewSWK(testContext2.params.Parameters, "group0")
				uaux := mkrlwe.NewSWK(testContext2.params.Parameters, "group0")
				uauxhead := mkrlwe.NewSWK(testContext2.params.Parameters, "group0")

				KeyGentemp = time.Since(KeyGenstart)
				fmt.Print("KeyGen time =", KeyGentemp, "\n")

				// 2. Pre-Eval
				numofctxtout := 1
				ctxtList := make([]*Ciphertext, numParties)
				ctxtUpdateList := make([]*Ciphertext, numofctxtout)
				msgList := make([]*Message, numParties)
				msgVals := make([]int64, testContext2.params.N())
				for k := 0; k < numParties; k++ {
					msgList[k], ctxtList[k] = newTestVectors(testContext2, "group0", (int64)(1), (int64)(2))
				}
				copy(msgVals, msgList[0].Value)

				EvalTime1start := time.Now()
				ctxtUpdateList[0] = ctxtList[0]
				for k := 1; k < numParties; k++ {
					ctxtUpdateList[0] = testContext2.evaluator.MulRelinNew(ctxtUpdateList[0], ctxtList[k], testContext2.rlkSet)
				}
				EvalTime1temp = time.Since(EvalTime1start)
				fmt.Print("EvalTime1 time = ", EvalTime1temp, "\n")

				// MPHE Error n-1 parties
				logInfAbsErr[iter][0], Noisebudget[iter][0] = Error(testContext2, msgVals, ctxtUpdateList[0])

				for JoiningParties := 2; JoiningParties <= (1 << numJoin); JoiningParties = JoiningParties * 2 {

					logJoin := int(math.Log2(float64(JoiningParties)))

					fmt.Printf("================= BFV_dMPHE %d ===================\n\n\n",
						numParties+JoiningParties)

					// 3. Joining
					Extendstart := time.Now()

					testContext2, _, _, _, _, _, _, _, _, _, _, ctxtUpdateList, _, _ =
						Join_dMPHE(testContext2, gsk, gpk, grlk, gcjk, grtk,
							jk, jkhead, uaux, uauxhead,
							idset, numParties, JoiningParties, ctxtUpdateList, t)

					Extend[iter][logJoin-1] = time.Since(Extendstart)
					fmt.Print("Extend time = ", Extend[iter][logJoin-1], "\n")

					// // MPHE Error n parties
					// Error(testContext2, msgVals, ctxtUpdateList[0])

					// 4. Post-Eval
					// EvalTime2start := time.Now()
					ctxtUpdateList[0], EvalTime2[iter][logJoin-1] = VectorProd_After_Join(testContext2, groupList,
						numParties, JoiningParties, ctxtUpdateList[0], 0, t)

					// EvalTime2[iter][logJoin] = time.Since(EvalTime2start)
					// fmt.Print("EvalTime2 time = ", EvalTime2[iter][logJoin], "\n")

					// MPHE Error n parties
					logInfAbsErr[iter][logJoin], Noisebudget[iter][logJoin] = Error(testContext2, msgVals, ctxtUpdateList[0])

					numParties = numParties + JoiningParties
				}
			}
			KeyGen[iter], Switch[iter], EvalTime1[iter] = KeyGentemp, Switchtemp, EvalTime1temp
			// Extend[iter], EvalTime2[iter] = Extendtemp, EvalTime2temp
			// logInfAbsErr[iter], Noisebudget[iter] = logInfAbsErrtemp, Noisebudgettemp
		}

		KeyGenavg, KeyGenstd := meanStdDuration(KeyGen)
		Switchavg, Switchstd := meanStdDuration(Switch)
		EvalTime1avg, EvalTime1std := meanStdDuration(EvalTime1)
		Extendavg, Extendstd := meanStdDuration2(Extend)
		EvalTime2avg, EvalTime2std := meanStdDuration2(EvalTime2)

		logInfAbsErravg, logInfAbsErrstd := meanStdFloat64(logInfAbsErr)
		Noisebudgetavg, Noisebudgetstd := meanStdFloat64(Noisebudget)

		fmt.Println("KeyGen =", KeyGenavg, " (std: ", KeyGenstd, ")")
		fmt.Println("Switch =", Switchavg, " (std: ", Switchstd, ")")
		fmt.Println("EvalTime1 =", EvalTime1avg, " (std: ", EvalTime1std, ")")
		fmt.Println("Extend =", Extendavg, " (std: ", Extendstd, ")")
		fmt.Println("EvalTime2 =", EvalTime2avg, " (std: ", EvalTime2std, ")")

		fmt.Println("logInfAbsErr =", logInfAbsErravg, " (std: ", logInfAbsErrstd, ")")
		fmt.Println("Noisebudget =", Noisebudgetavg, " (std: ", Noisebudgetstd, ")")
	}
}

func Test_MKHE_BFV_fig(t *testing.T) {
	var PartySet = [1]int{2} // , 3, 7, 15, 31
	for _, P := range PartySet {
		fmt.Printf("P = %d\n", P)

		numJoin := 9
		KeyGen := make([]time.Duration, iternum)
		Switch := make([]time.Duration, iternum)
		EvalTime1 := make([]time.Duration, iternum)
		Extend := make([][]time.Duration, iternum)
		for i := 0; i < iternum; i++ {
			Extend[i] = make([]time.Duration, numJoin)
		}
		EvalTime2 := make([][]time.Duration, iternum)
		for i := 0; i < iternum; i++ {
			EvalTime2[i] = make([]time.Duration, numJoin)
		}

		logInfAbsErr := make([][]float64, iternum)
		for i := 0; i < iternum; i++ {
			logInfAbsErr[i] = make([]float64, numJoin+1)
		}
		Noisebudget := make([][]float64, iternum)
		for i := 0; i < iternum; i++ {
			Noisebudget[i] = make([]float64, numJoin+1)
		}

		for iter := 0; iter < iternum; iter++ {

			var (
				KeyGentemp, Switchtemp,
				EvalTime1temp time.Duration
				// , Extendtemp,
				// EvalTime2temp
				// logInfAbsErrtemp, Noisebudgettemp float64
			)

			defaultParams := []ParametersLiteral{PN15QP880} // PN14QP439, PN15QP880}
			for _, defaultParam := range defaultParams {
				fmt.Println("========Paramset=========")

				for _, numGroups := range []int{P} {
					*maxGroups = numGroups
					numParties := 1

					fmt.Printf("================= MKHE_BFV %d ===================\n\n\n",
						numGroups)

					// ---------------- Key Generation ----------------
					KeyGenstart := time.Now()
					params := NewParametersFromLiteral(defaultParam)

					if params.PCount() < 2 {
						continue
					}

					groupList := make([]string, *maxGroups)
					idset := mkrlwe.NewIDSet()
					for i := range groupList {
						groupList[i] = "group" + strconv.Itoa(i)
						idset.Add(groupList[i])
					}

					var (
						testContext2 *testParams

						gsk  *mkrlwe.SecretKey
						gpk  *mkrlwe.PublicKey
						grlk *RelinearizationKey
						gcjk *mkrlwe.ConjugationKey
						grtk *mkrlwe.RotationKey
					)

					testContext2, _, gsk, gpk, grlk, gcjk, grtk,
						_, _, _, _, _ = genTestParams(params, idset, 1)

					_, _, _, _, _ = gsk, gpk, grlk, gcjk, grtk

					KeyGentemp = time.Since(KeyGenstart)
					fmt.Print("KeyGen time =", KeyGentemp, "\n")

					// 2. Pre-Eval
					numofctxtout := 1
					ctxtList := make([]*Ciphertext, numGroups)
					ctxtUpdateList := make([]*Ciphertext, numofctxtout)
					msgList := make([]*Message, numGroups)
					msgVals := make([]int64, testContext2.params.N())

					for j := range groupList {
						for i := 0; i < numParties; i++ {
							msgList[i+j], ctxtList[i+j] = newTestVectors(testContext2, groupList[j], (int64)(1), (int64)(2))
						}
					}
					copy(msgVals, msgList[0].Value)

					EvalTime1start := time.Now()
					ctxtUpdateList[0] = ctxtList[0]
					for k := 1; k < numGroups; k++ {
						ctxtUpdateList[0] = testContext2.evaluator.MulRelinNew(ctxtUpdateList[0], ctxtList[k], testContext2.rlkSet)
					}
					EvalTime1temp = time.Since(EvalTime1start)
					fmt.Print("EvalTime1 time = ", EvalTime1temp, "\n")

					// MPHE Error n-1 parties
					logInfAbsErr[iter][0], Noisebudget[iter][0] = Error(testContext2, msgVals, ctxtUpdateList[0])

					for JoiningParties := 2; JoiningParties <= (1 << numJoin); JoiningParties = JoiningParties * 2 {

						logJoin := int(math.Log2(float64(JoiningParties)))

						fmt.Printf("================= BFV_MKHE %d ===================\n\n\n",
							numGroups+JoiningParties)

						// 3. Joining
						Extendstart := time.Now()

						testContext2, idset, _ =
							testJoinPartyMK(testContext2, idset, groupList, 1, JoiningParties, t)

						groupListUp := make([]string, *maxGroups+1)
						for i := range groupListUp {
							groupListUp[i] = "group" + strconv.Itoa(i)
						}
						groupList = groupListUp

						Extend[iter][logJoin-1] = time.Since(Extendstart)
						fmt.Print("Extend time = ", Extend[iter][logJoin-1], "\n")

						// // MPHE Error n parties
						// Error(testContext2, msgVals, ctxtUpdateList[0])

						// 4. Post-Eval
						// EvalTime2start := time.Now()
						ctxtUpdateList[0], EvalTime2[iter][logJoin-1] = VectorProd_After_Join(testContext2, groupList,
							numParties, JoiningParties, ctxtUpdateList[0], 0, t)

						// EvalTime2[iter][logJoin] = time.Since(EvalTime2start)
						// fmt.Print("EvalTime2 time = ", EvalTime2[iter][logJoin], "\n")

						// MPHE Error n parties
						logInfAbsErr[iter][logJoin], Noisebudget[iter][logJoin] = Error(testContext2, msgVals, ctxtUpdateList[0])

						numGroups = numGroups + JoiningParties
					}
				}
			}

			KeyGen[iter], Switch[iter], EvalTime1[iter] = KeyGentemp, Switchtemp, EvalTime1temp
			// Extend[iter], EvalTime2[iter] = Extendtemp, EvalTime2temp
			// logInfAbsErr[iter], Noisebudget[iter] = logInfAbsErrtemp, Noisebudgettemp
		}

		KeyGenavg, KeyGenstd := meanStdDuration(KeyGen)
		Switchavg, Switchstd := meanStdDuration(Switch)
		EvalTime1avg, EvalTime1std := meanStdDuration(EvalTime1)
		Extendavg, Extendstd := meanStdDuration2(Extend)
		EvalTime2avg, EvalTime2std := meanStdDuration2(EvalTime2)

		logInfAbsErravg, logInfAbsErrstd := meanStdFloat64(logInfAbsErr)
		Noisebudgetavg, Noisebudgetstd := meanStdFloat64(Noisebudget)

		fmt.Println("KeyGen =", KeyGenavg, " (std: ", KeyGenstd, ")")
		fmt.Println("Switch =", Switchavg, " (std: ", Switchstd, ")")
		fmt.Println("EvalTime1 =", EvalTime1avg, " (std: ", EvalTime1std, ")")
		fmt.Println("Extend =", Extendavg, " (std: ", Extendstd, ")")
		fmt.Println("EvalTime2 =", EvalTime2avg, " (std: ", EvalTime2std, ")")

		fmt.Println("logInfAbsErr =", logInfAbsErravg, " (std: ", logInfAbsErrstd, ")")
		fmt.Println("Noisebudget =", Noisebudgetavg, " (std: ", Noisebudgetstd, ")")
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

func VectorProd_Before_Join(testContext *testParams, userList []string, numParties int, sk []*mkrlwe.SecretKey, swk []*mkrlwe.SWK, swkhead []*mkrlwe.SWK, flag int, t *testing.T) (ctxtout *Ciphertext, Switchtemp time.Duration, MultBtemp time.Duration) {

	msgList := make([]*Message, numParties+len(userList)-1)
	ctList := make([]*Ciphertext, numParties+len(userList)-1)

	rlkSet := testContext.rlkSet
	eval := testContext.evaluator

	for j := range userList {
		for i := 0; i < numParties; i++ {
			msgList[i+j], ctList[i+j] = newTestVectors(testContext, userList[j], (int64)(1), (int64)(2))
		}
	}

	if flag == 0 {
		for j := range userList {
			for i := 0; i < numParties; i++ {
				ctcache := testContext.encryptor.EncryptSkMsgNew(msgList[i+j], sk[i+j])
				ctList[i+j] = ctcache.CopyNew()
			}
		}

		Switchtime_start := time.Now()
		for j := 0; j < len(userList)-1+numParties; j++ {
			var ctxtKS *Ciphertext
			ctxtKS = ctList[j].CopyNew()
			eval.ksw.KS(ctList[j].Ciphertext, swk[j], swkhead[j], ctxtKS.Ciphertext)
			ctList[j] = ctxtKS
		}
		Switchtemp = time.Since(Switchtime_start)
		fmt.Print("Switch = ", Switchtemp, "\n")
	}

	ctxtout = ctList[0].CopyNew()
	ctMulstart := time.Now()

	ctxts := make([]*Ciphertext, len(ctList))
	for i := 0; i < len(ctList); i++ {
		ctxts[i] = ctList[i].CopyNew()
	}

	// binary tree reduction
	for len(ctxts) > 1 {
		var next []*Ciphertext

		for i := 0; i < len(ctxts); i += 2 {
			if i+1 < len(ctxts) {
				prod := eval.MulRelinNew(ctxts[i], ctxts[i+1], rlkSet)
				next = append(next, prod)
			} else {
				next = append(next, ctxts[i])
			}
		}

		ctxts = next
	}
	ctxtout = ctxts[0]

	MultBtemp = time.Since(ctMulstart)
	fmt.Print("Mult Before Join = ", MultBtemp, "\n")

	return ctxtout, Switchtemp, MultBtemp
}

func VectorProd_After_Join(testContext *testParams, userList []string, numParties int, JoiningParties int, ctxtin *Ciphertext, flag int, t *testing.T) (ctxtout *Ciphertext, MultAtemp time.Duration) {

	msgList := make([]*Message, JoiningParties)
	ctList := make([]*Ciphertext, JoiningParties)

	rlkSet := testContext.rlkSet
	eval := testContext.evaluator

	if flag == 0 {
		for i := 0; i < JoiningParties; i++ {
			msgList[i], ctList[i] = newTestVectors(testContext, "group0", (int64)(1), (int64)(2))
		}
	} else {
		for i := 0; i < JoiningParties; i++ {
			msgList[i], ctList[i] = newTestVectors(testContext, "group"+strconv.Itoa(len(userList)+i-1), (int64)(1), (int64)(2))
			// fmt.Print("Joining group = ", ctList[i].IDSet(), "\n")
		}
	}

	// var ctxtout *Ciphertext

	ctMulstart := time.Now()

	// -------------------------------------------------
	// 1) inputs = ctList[0..JoiningParties-1] ONLY
	// -------------------------------------------------
	ctxts := make([]*Ciphertext, 0, JoiningParties)

	for k := 0; k < JoiningParties; k++ {
		ctxts = append(ctxts, ctList[k].CopyNew())
	}

	// -------------------------------------------------
	// 2) binary tree reduction on ctList
	// -------------------------------------------------
	for len(ctxts) > 1 {
		var next []*Ciphertext

		for i := 0; i < len(ctxts); i += 2 {
			if i+1 < len(ctxts) {
				prod := eval.MulRelinNew(ctxts[i], ctxts[i+1], rlkSet)
				next = append(next, prod)
			} else {
				next = append(next, ctxts[i])
			}
		}

		ctxts = next
	}

	// -------------------------------------------------
	// 3) multiply ctxtin LAST (depth-critical)
	// -------------------------------------------------
	ctxtout = eval.MulRelinNew(ctxts[0], ctxtin, rlkSet)

	MultAtemp = time.Since(ctMulstart)
	fmt.Print("Mult After Join (Binary Tree, ctxtin last) = ", MultAtemp, "\n")

	return ctxtout, MultAtemp
}

// Returns the ceil(log2) of the sum of the absolute value of all the coefficients
func log2OfInnerSum(level int, ringQ *ring.Ring, poly *ring.Poly) (logSum float64) {
	sumRNS := make([]uint64, level+1)

	for j := 0; j < ringQ.N; j++ {

		for i := 0; i < level+1; i++ {
			coeffs := poly.Coeffs[i]
			sumRNS[i] = coeffs[j]
		}

		var qi uint64
		var crtReconstruction *big.Int

		sumBigInt := ring.NewUint(0)
		QiB := new(big.Int)
		tmp := new(big.Int)
		modulusBigint := ring.NewInt(1)

		for i := 0; i < level+1; i++ {

			qi = ringQ.Modulus[i]
			QiB.SetUint64(qi)

			modulusBigint.Mul(modulusBigint, QiB)

			crtReconstruction = new(big.Int)
			crtReconstruction.Quo(ringQ.ModulusBigint, QiB)
			tmp.ModInverse(crtReconstruction, QiB)
			tmp.Mod(tmp, QiB)
			crtReconstruction.Mul(crtReconstruction, tmp)

			sumBigInt.Add(sumBigInt, tmp.Mul(ring.NewUint(sumRNS[i]), crtReconstruction))
		}

		sumBigInt.Mod(sumBigInt, modulusBigint)
		sumBigInt.Abs(sumBigInt)
		logSum1 := sumBigInt.BitLen()

		sumBigInt.Sub(sumBigInt, modulusBigint)
		sumBigInt.Abs(sumBigInt)
		logSum2 := sumBigInt.BitLen()

		if logSum1 < logSum2 {
			logSum += float64(logSum1) / float64(ringQ.N)
		} else {
			logSum += float64(logSum2) / float64(ringQ.N)
		}
	}

	return
}

func genTestParams(
	defaultParam Parameters,
	groupIdSet *mkrlwe.IDSet,
	numParties int,
) (
	testContext *testParams, err error,
	gskup *mkrlwe.SecretKey,
	gpkup *mkrlwe.PublicKey,
	grlkup *RelinearizationKey,
	gcjkup *mkrlwe.ConjugationKey,
	grtkup *mkrlwe.RotationKey,
	skup []*mkrlwe.SecretKey,
	pkup []*mkrlwe.PublicKey,
	rlkup []*RelinearizationKey,
	cjkup []*mkrlwe.ConjugationKey,
	rtksup []map[uint]*mkrlwe.RotationKey,
) {

	testContext = new(testParams)
	testContext.params = defaultParam
	testContext.kgen = NewKeyGenerator(defaultParam)
	testContext.evaluator = NewEvaluator(defaultParam)

	testContext.skSet = mkrlwe.NewSecretKeySet()
	testContext.pkSet = mkrlwe.NewPublicKeyKeySet()
	testContext.rlkSet = NewRelinearizationKeySet(defaultParam)
	testContext.rtkSet = mkrlwe.NewRotationKeySet()
	testContext.cjkSet = mkrlwe.NewConjugationKeySet()

	sk := make([]*mkrlwe.SecretKey, numParties)
	pk := make([]*mkrlwe.PublicKey, numParties)
	rlk := make([]*RelinearizationKey, numParties)
	cjk := make([]*mkrlwe.ConjugationKey, numParties)
	rtks := make([]map[uint]*mkrlwe.RotationKey, numParties)
	// ------------------------------------------------------------

	for groupId := range groupIdSet.Value {
		for p := 0; p < numParties; p++ {
			sk[p], pk[p] = testContext.kgen.GenKeyPair(groupId)
			rlk[p] = testContext.kgen.GenRelinearizationKey(sk[p])
			cjk[p] = testContext.kgen.GenConjugationKey(sk[p])
			rtks[p] = testContext.kgen.GenDefaultRotationKeys(sk[p])
		}

		gsk := testContext.kgen.GenGroupSecretKey(sk)
		testContext.skSet.AddSecretKey(gsk)

		gpk := testContext.kgen.GenGroupPublicKey(pk)
		testContext.pkSet.AddPublicKey(gpk)

		grlk := testContext.kgen.GenGroupRelinKey(rlk)
		testContext.rlkSet.AddRelinearizationKey(grlk)

		gcjk := testContext.kgen.GenGroupConjKey(cjk)
		testContext.cjkSet.AddConjugationKey(gcjk)

		// rotation key
		for idx := range rtks[0] {
			rtkParts := make([]*mkrlwe.RotationKey, numParties)
			for p := 0; p < numParties; p++ {
				rtkParts[p] = rtks[p][idx]
			}
			grtk := testContext.kgen.GenGroupRotKey(rtkParts)
			testContext.rtkSet.AddRotationKey(grtk)

			grtkup = grtk
		}

		gskup = gsk
		gpkup = gpk
		grlkup = grlk
		gcjkup = gcjk
	}

	testContext.ringQ = defaultParam.RingQ()
	testContext.ringQMul = defaultParam.RingQMul()
	testContext.ringR = defaultParam.RingR()

	skup = sk
	pkup = pk
	rlkup = rlk
	cjkup = cjk
	rtksup = rtks

	if testContext.prng, err = utils.NewPRNG(); err != nil {
		return nil, err, gskup, gpkup, grlkup, gcjkup, grtkup, skup, pkup, rlkup, cjkup, rtksup
	}

	testContext.encryptor = NewEncryptor(defaultParam)
	testContext.decryptor = NewDecryptor(defaultParam)
	testContext.evaluator = NewEvaluator(defaultParam)

	return testContext, nil, gskup, gpkup, grlkup, gcjkup, grtkup, skup, pkup, rlkup, cjkup, rtksup
}

func testKS(testContext *testParams, userList []string, gsk *mkrlwe.SecretKey, gpk *mkrlwe.PublicKey, sk []*mkrlwe.SecretKey, pk []*mkrlwe.PublicKey, swk []*mkrlwe.SWK, swkhead []*mkrlwe.SWK, t *testing.T) (msg *Message, ctxt *Ciphertext, ctsk *Ciphertext) {

	params := testContext.params
	eval := testContext.evaluator
	levelQ := params.QCount() - 1
	levelP := params.PCount() - 1

	numUsers := len(sk)
	msgListsk := make([]*Message, numUsers)
	ctListsk := make([]*Ciphertext, numUsers)

	fmt.Print("userList = ", userList, "\n")
	fmt.Print("numUsers = ", numUsers, "\n")

	for i := range userList {
		msgListsk[i], ctListsk[i] = newTestVectors(testContext, userList[i], int64(99), int64(100))
	}

	ctOut := ctListsk[0].CopyNew()
	msg = msgListsk[0]
	msg3Out := msgListsk[0]

	skOut := sk[0].CopyNew()
	for i := range sk {
		if i != 0 {
			params.RingQP().AddLvl(levelQ, levelP, skOut.Value, sk[i].Value, skOut.Value)
		}
	}

	ctpk := testContext.encryptor.EncryptMsgNew(msg, gpk) // testContext.pkSet.GetPublicKey("group0"))
	msg1Out := testContext.decryptor.DecryptSk(ctpk, skOut)
	_ = msg1Out

	ctsk = testContext.encryptor.EncryptSkMsgNew(msg, sk[0]) //testContext.skSet.GetSecretKey("group0"))
	ctskorigin := ctsk.CopyNew()
	msg2Out := testContext.decryptor.DecryptSk(ctsk, sk[0])
	_ = msg2Out
	eval.ksw.KS(ctsk.Ciphertext, swk[0], swkhead[0], ctOut.Ciphertext)

	// Partial Decrypt
	ptxt := testContext.decryptor.ptxtPool
	ctdecList := make([]*Ciphertext, numUsers)
	level := utils.MinInt(ctOut.Level(), ptxt.Plaintext.Level())
	ptxt.Plaintext.Value.Coeffs = ptxt.Plaintext.Value.Coeffs[:level+1]

	for p := range sk {
		ctdecList[p] = ctOut.CopyNew()
	}

	for p := range sk {
		testContext.decryptor.PartialDecryptIP(ctdecList[p], sk[p])
	}
	for p := range sk {
		if p != 0 {
			testContext.ringQ.AddLvl(level, ctdecList[p].Value["group0"], ctdecList[0].Value["group0"], ctdecList[0].Value["group0"])
		}
	}

	testContext.ringQ.AddLvl(level, ctdecList[0].Value["0"], ctdecList[0].Value["group0"], ctdecList[0].Value["0"])
	testContext.decryptor.ptxtPool.Value = ctdecList[0].Value["0"]
	testContext.decryptor.encoder.DecodeInt(ptxt, msg3Out.Value)
	fmt.Print("After Switch + Partial Dec = ", msg3Out.Value[0], "\n")

	for i := range msg.Value {
		delta := msg.Value[i] - msg3Out.Value[i]
		require.Equal(t, int64(0), delta, fmt.Sprintf("%v vs %v", msg.Value[i], msg3Out.Value[i]))
	}
	require.Equal(t, 0, 0)

	ctsk = ctskorigin

	msg2Out = testContext.decryptor.DecryptSk(ctOut, gsk)
	fmt.Print("Dec TEST = ", msg2Out.Value[0], "\n")
	_ = msg2Out
	return msg, ctOut, ctsk
}

func testKSAfterJoin(testContext *testParams, userList []string, msg *Message, ctxt *Ciphertext, ctsk *Ciphertext, gsk *mkrlwe.SecretKey, gsk2 *mkrlwe.SecretKey, gpk *mkrlwe.PublicKey, gpk2 *mkrlwe.PublicKey, sk []*mkrlwe.SecretKey, pk []*mkrlwe.PublicKey, swk []*mkrlwe.SWK, swkhead []*mkrlwe.SWK, jk *mkrlwe.SWK, jkhead *mkrlwe.SWK, uaux *mkrlwe.SWK, uauxhead *mkrlwe.SWK, ctxtList []*Ciphertext, t *testing.T) {

	eval := testContext.evaluator

	msg2Out := testContext.decryptor.DecryptSk(ctxt, gsk)
	fmt.Print("Dec TEST2 = ", msg2Out.Value[0], "\n")
	_ = msg2Out

	// If generate jk
	ctOut := eval.KSNew(ctxt, jk, jkhead)
	msgOut := testContext.decryptor.DecryptSk(ctOut, gsk2)
	fmt.Print("After Switch + Extend = ", msgOut.Value[0], "\n")

	ctOut2 := eval.KSNew(ctsk, swk[0], swkhead[0])
	msg3Out := testContext.decryptor.DecryptSk(ctOut2, gsk2)
	// fmt.Print("Test updated swk_i = ", msg3Out.Value[0], "\n")
	_ = msg3Out

	msg11Out := testContext.decryptor.DecryptSk(ctxtList[0], gsk2)
	// fmt.Print("Test updated (Join) ctxt = ", msg11Out.Value[0], "\n")
	_ = msg11Out

	require.Equal(t, 0, 0)
}

func newTestVectors(testContext *testParams, id string, a, b int64) (msg *Message, ciphertext *Ciphertext) {

	params := testContext.params
	msg = NewMessage(params)

	for i := 0; i < params.N(); i++ {
		msg.Value[i] = int64(utils.RandUint64()/2)%(b-a) + a
	}

	if testContext.encryptor != nil {
		ciphertext = testContext.encryptor.EncryptMsgNew(msg, testContext.pkSet.GetPublicKey(id))
	} else {
		panic("cannot newTestVectors: encryptor is not initialized!")
	}

	return msg, ciphertext
}

func testEncAndDec(testContext *testParams, userList []string, t *testing.T) {
	params := testContext.params
	numUsers := len(userList)
	msgList := make([]*Message, numUsers)
	ctList := make([]*Ciphertext, numUsers)

	skSet := testContext.skSet
	dec := testContext.decryptor

	for i := range userList {
		msgList[i], ctList[i] = newTestVectors(testContext, userList[i], -int64(params.T())/4, int64(params.T())/4)
	}

	t.Run(GetTestName(testContext.params, "MKBFVEncAndDec: "+strconv.Itoa(numUsers)+"/ "), func(t *testing.T) {

		for i := range userList {
			msgOut := dec.Decrypt(ctList[i], skSet)
			for j := range msgList[i].Value {
				delta := msgList[i].Value[j] - msgOut.Value[j]
				require.Equal(t, int64(0), delta, fmt.Sprintf("%v vs %v", msgList[i].Value[j], msgOut.Value[j]))
			}
		}
	})

}

func testEvaluatorAdd(testContext *testParams, userList []string, t *testing.T) {
	t.Run(GetTestName(testContext.params, "Evaluator/Add/CtCt/"), func(t *testing.T) {
		params := testContext.params
		msg3 := NewMessage(params)

		numUsers := len(userList)
		msgList := make([]*Message, numUsers)
		ctList := make([]*Ciphertext, numUsers)

		eval := testContext.evaluator

		for i := range userList {
			msgList[i], ctList[i] = newTestVectors(testContext, userList[i], -100, -20)
		}

		ct := ctList[0]
		msg := msgList[0]

		for i := range userList {
			ct = eval.AddNew(ct, ctList[i])

			for j := range msg.Value {
				msg.Value[j] += msgList[i].Value[j]
			}
		}

		for i := range msg3.Value {
			msg3.Value[i] = msg.Value[i] + msg.Value[i]
		}

		Addstart := time.Now()
		ct3 := testContext.evaluator.AddNew(ct, ct)
		Addend := time.Since(Addstart)
		fmt.Print("Add time = ", Addend, "\n")

		msg1Out := testContext.decryptor.Decrypt(ct, testContext.skSet)
		msg2Out := testContext.decryptor.Decrypt(ct, testContext.skSet)
		msg3Out := testContext.decryptor.Decrypt(ct3, testContext.skSet)

		for i := range msg1Out.Value {
			delta := msg.Value[i] - msg1Out.Value[i]
			require.Equal(t, int64(0), delta, fmt.Sprintf("%v: %v vs %v", i, msg1Out.Value[i], msg.Value[i]))
		}

		for i := range msg2Out.Value {
			delta := msg.Value[i] - msg2Out.Value[i]
			require.Equal(t, int64(0), delta, fmt.Sprintf("%v: %v vs %v", i, msg2Out.Value[i], msg.Value[i]))
		}

		for i := range msg3Out.Value {
			delta := msg3.Value[i] - msg3Out.Value[i]
			require.Equal(t, int64(0), delta, fmt.Sprintf("%v: %v vs %v", i, msg3Out.Value[i], msg.Value[i]))
		}
		require.Equal(t, 0, 0)
	})

}

func testEvaluatorSub(testContext *testParams, userList []string, t *testing.T) {

	numUsers := len(userList)
	msgList := make([]*Message, numUsers)
	ctList := make([]*Ciphertext, numUsers)

	eval := testContext.evaluator

	for i := range userList {
		msgList[i], ctList[i] = newTestVectors(testContext, userList[i], -2, 2)
	}

	ct := ctList[0]
	msg := msgList[0]

	for i := range userList {
		ct = eval.SubNew(ct, ctList[i])

		for j := range msg.Value {
			msg.Value[j] -= msgList[i].Value[j]
		}
	}

	t.Run(GetTestName(testContext.params, "MKBFVSub: "+strconv.Itoa(numUsers)+"/ "), func(t *testing.T) {
		ctRes := ct
		msgRes := testContext.decryptor.Decrypt(ctRes, testContext.skSet)

		for i := range msgRes.Value {
			delta := msgRes.Value[i] - msg.Value[i]
			require.Equal(t, int64(0), delta, fmt.Sprintf("%v vs %v", msgRes.Value[i], msg.Value[i]))
		}
	})

}

func testEvaluatorMul(testContext *testParams, userList []string, t *testing.T) {

	numUsers := len(userList)
	msgList := make([]*Message, numUsers)
	ctList := make([]*Ciphertext, numUsers)

	rlkSet := testContext.rlkSet
	eval := testContext.evaluator

	for i := range userList {
		msgList[i], ctList[i] = newTestVectors(testContext, userList[i], 0, 2)
	}

	ct := ctList[0]
	msg := msgList[0]

	for i := range userList {
		ct = eval.AddNew(ct, ctList[i])

		for j := range msg.Value {
			msg.Value[j] += msgList[i].Value[j]
		}
	}

	for j := range msg.Value {
		msg.Value[j] *= msg.Value[j]
	}

	ptxt := testContext.decryptor.DecryptToPtxt(ct, testContext.skSet)
	ptxt2 := testContext.decryptor.DecryptToPtxt(ct, testContext.skSet)
	ptxtR := testContext.ringR.NewPoly()
	ptxt2R := testContext.ringR.NewPoly()

	testContext.evaluator.conv.ModUpQtoR(ptxt, ptxtR)
	testContext.evaluator.conv.Rescale(ptxt2, ptxt2R)

	testContext.ringR.NTT(ptxtR, ptxtR)
	testContext.ringR.MForm(ptxtR, ptxtR)
	testContext.ringR.NTT(ptxt2R, ptxt2R)
	testContext.ringR.MulCoeffsMontgomery(ptxtR, ptxt2R, ptxtR)
	testContext.evaluator.conv.Quantize(ptxtR, ptxt, testContext.params.T())

	t.Run(GetTestName(testContext.params, "MKMulAndRelin: "+strconv.Itoa(numUsers)+"/ "), func(t *testing.T) {
		ctMulstart := time.Now()
		ctRes := eval.MulRelinNew(ct, ct, rlkSet)
		ctMulend := time.Since(ctMulstart)
		fmt.Print("Mult time = ", ctMulend, "\n")

		msgRes := testContext.decryptor.Decrypt(ctRes, testContext.skSet)
		ptxtRes := testContext.decryptor.DecryptToPtxt(ctRes, testContext.skSet)

		testContext.ringQ.Sub(ptxtRes, ptxt, ptxtRes)

		for i := range msgRes.Value {
			delta := msgRes.Value[i] - msg.Value[i]
			require.Equal(t, int64(0), delta, fmt.Sprintf("%v: %v vs %v", i, msgRes.Value[i], msg.Value[i]))
		}

	})

}

func testEvaluatorRot(testContext *testParams, userList []string, t *testing.T) {

	// params := testContext.params
	numUsers := len(userList)
	msgList := make([]*Message, numUsers)
	ctList := make([]*Ciphertext, numUsers)

	rtkSet := testContext.rtkSet
	eval := testContext.evaluator
	slots := eval.params.N() / 2

	for i := range userList {
		msgList[i], ctList[i] = newTestVectors(testContext, userList[i], 0, 2)
	}

	ct := ctList[0]
	msg := msgList[0]
	rot := int(1)

	for i := range userList {
		ct = eval.AddNew(ct, ctList[i])

		for j := range msg.Value {
			msg.Value[j] += msgList[i].Value[j]
		}
	}

	msgRes := testContext.decryptor.Decrypt(ct, testContext.skSet)
	fmt.Print("Rot test = ", msgRes.Value[:10], "\n")

	t.Run(GetTestName(testContext.params, "MKRotate: "+strconv.Itoa(numUsers)+"/ "), func(t *testing.T) {
		Rotstart := time.Now()
		ctRes := eval.RotateNew(ct, rot, rtkSet)
		Rotend := time.Since(Rotstart)
		fmt.Print("Rot time = ", Rotend, "\n")
		msgRes := testContext.decryptor.Decrypt(ctRes, testContext.skSet)
		fmt.Print("Rot test after = ", msgRes.Value[:10], "\n")

		for i := 0; i < slots; i++ {
			var delta int64
			if rot > 0 {
				delta = msgRes.Value[i] - msg.Value[(i+rot)%slots]
			} else {
				delta = msg.Value[i] - msgRes.Value[(i-rot)%slots]
			}
			require.Equal(t, int64(0), delta)
		}

		for i := 0; i < slots; i++ {
			var delta int64
			if rot > 0 {
				delta = msgRes.Value[i+slots] - msg.Value[(i+rot)%slots+slots]
			} else {
				delta = msg.Value[i+slots] - msgRes.Value[(i-rot)%slots+slots]
			}
			require.Equal(t, int64(0), delta)
		}

	})

}

func testEvaluatorConj(testContext *testParams, userList []string, t *testing.T) {

	numUsers := len(userList)
	msgList := make([]*Message, numUsers)
	ctList := make([]*Ciphertext, numUsers)

	cjkSet := testContext.cjkSet
	eval := testContext.evaluator
	slots := eval.params.N() / 2

	for i := range userList {
		msgList[i], ctList[i] = newTestVectors(testContext, userList[i], 0, 2)
	}

	ct := ctList[0]
	msg := msgList[0]

	for i := range userList {
		ct = eval.AddNew(ct, ctList[i])

		for j := range msg.Value {
			msg.Value[j] += msgList[i].Value[j]
		}
	}

	t.Run(GetTestName(testContext.params, "MKConjugate: "+strconv.Itoa(numUsers)+"/ "), func(t *testing.T) {
		ctRes := eval.ConjugateNew(ct, cjkSet)
		msgRes := testContext.decryptor.Decrypt(ctRes, testContext.skSet)

		for i := 0; i < slots; i++ {
			delta := msgRes.Value[i] - msg.Value[(i+slots)]
			require.Equal(t, int64(0), delta)
		}

		for i := 0; i < slots; i++ {
			delta := msgRes.Value[i+slots] - msg.Value[i]
			require.Equal(t, int64(0), delta)
		}

	})

}

func MPgenSWK(
	testContext *testParams,
	gsk *mkrlwe.SecretKey,
	gpk *mkrlwe.PublicKey,
	sk []*mkrlwe.SecretKey,
	groupIdSet *mkrlwe.IDSet,
	numParties int,
) (
	testContext2 *testParams,
	err error,
	swksumup *mkrlwe.SWK,
	swkheadsumup *mkrlwe.SWK,
) {

	testContext2 = testContext

	// --------------------------------------------
	// 1) initialize swk sets
	// --------------------------------------------
	for p := 0; p < numParties; p++ {
		testContext2.swkSet[p] = mkrlwe.NewSWKSet()
		testContext2.swkheadSet[p] = mkrlwe.NewSWKSet()
	}

	for p := 0; p < numParties; p++ {

		swk, swkhead := testContext.kgen.GenSWK(sk[p], gpk)

		testContext2.swkSet[p].AddSWK(swk)
		testContext2.swkheadSet[p].AddSWK(swkhead)
	}

	// --------------------------------------------
	// 3) aggregate SWKs
	// --------------------------------------------
	swksum := mkrlwe.NewSWK(testContext2.params.Parameters, "group0")
	swkheadsum := mkrlwe.NewSWK(testContext2.params.Parameters, "group0")

	// --------------------------------------------
	// 4) finalize
	// --------------------------------------------
	if testContext2.prng, err = utils.NewPRNG(); err != nil {
		return nil, err, nil, nil
	}

	return testContext2, nil, swksum, swkheadsum
}

func Join_dMPHE(testContext *testParams,
	gsk *mkrlwe.SecretKey, gpk *mkrlwe.PublicKey,
	grlk *RelinearizationKey, gcjk *mkrlwe.ConjugationKey, grtk *mkrlwe.RotationKey,
	jk *mkrlwe.SWK, jkhead *mkrlwe.SWK, uaux *mkrlwe.SWK, uauxhead *mkrlwe.SWK,
	groupIdSet *mkrlwe.IDSet, numParties int, JoiningParties int,
	ctxtList []*Ciphertext, t *testing.T,
) (testContext2 *testParams, err error,
	gskup *mkrlwe.SecretKey, gpkup *mkrlwe.PublicKey,
	grlkup *RelinearizationKey, gcjkup *mkrlwe.ConjugationKey, grtkup *mkrlwe.RotationKey,
	jkup *mkrlwe.SWK, jkheadup *mkrlwe.SWK,
	uauxup *mkrlwe.SWK, uauxheadup *mkrlwe.SWK,
	ctxtListup []*Ciphertext, ExtGentemp, ExtCttemp time.Duration) {

	Update_KG_start := time.Now()
	testContext2 = testContext

	params := testContext.params
	levelQ := params.QCount() - 1
	levelP := params.PCount() - 1
	beta := params.Beta(levelQ)
	ringQP := params.RingQP()

	// Save pre-update copies
	gskpre := gsk.CopyNew()
	gpkpre := gpk.CopyNew()

	skNewList := make([]*mkrlwe.SecretKey, JoiningParties)
	var lastSk *mkrlwe.SecretKey

	// === Generate & integrate keys for joining parties (no appends) ===
	for p := 0; p < JoiningParties; p++ {
		// 1) local key
		skNew, pkNew := testContext2.kgen.GenKeyPair("group0")
		rlkNew := testContext2.kgen.GenRelinearizationKey(skNew)
		cjkNew := testContext2.kgen.GenConjugationKey(skNew)
		rtkNew := testContext2.kgen.GenDefaultRotationKeys(skNew)

		// New sk list
		skNewList[p] = skNew

		// 2) global secret key update: gsk := gsk + skNew
		ringQP.AddLvl(levelQ, levelP, gsk.Value, skNew.Value, gsk.Value)
		testContext2.skSet.AddSecretKey(gsk)

		// 3) global public key update: gpk := gpk + pkNew
		ringQP.AddLvl(levelQ, levelP, gpk.Value[0], pkNew.Value[0], gpk.Value[0])
		testContext2.pkSet.AddPublicKey(gpk)

		// 4) rotation keys update
		for idx := range rtkNew {
			rtkCur := testContext.rtkSet.Value["group0"][idx]
			for i := 0; i < beta; i++ {
				ringQP.AddLvl(levelQ, levelP,
					rtkCur.Value.Value[i],
					rtkNew[idx].Value.Value[i],
					rtkCur.Value.Value[i])
			}
			testContext2.rtkSet.AddRotationKey(rtkCur)
		}

		// 5) relinearization & conjugation update
		for i := 0; i < beta; i++ {
			ringQP.AddLvl(levelQ, levelP,
				grlk.Value[0].Value[0].Value[i],
				rlkNew.Value[0].Value[0].Value[i],
				grlk.Value[0].Value[0].Value[i])
			ringQP.AddLvl(levelQ, levelP,
				grlk.Value[0].Value[1].Value[i],
				rlkNew.Value[0].Value[1].Value[i],
				grlk.Value[0].Value[1].Value[i])
			ringQP.AddLvl(levelQ, levelP,
				grlk.Value[0].Value[2].Value[i],
				rlkNew.Value[0].Value[2].Value[i],
				grlk.Value[0].Value[2].Value[i])

			ringQP.AddLvl(levelQ, levelP,
				grlk.Value[1].Value[0].Value[i],
				rlkNew.Value[1].Value[0].Value[i],
				grlk.Value[1].Value[0].Value[i])
			ringQP.AddLvl(levelQ, levelP,
				grlk.Value[1].Value[1].Value[i],
				rlkNew.Value[1].Value[1].Value[i],
				grlk.Value[1].Value[1].Value[i])

			ringQP.AddLvl(levelQ, levelP,
				gcjk.Value.Value[i],
				cjkNew.Value.Value[i],
				gcjk.Value.Value[i])
		}
		testContext2.rlkSet.AddRelinearizationKey(grlk)
		testContext2.cjkSet.AddConjugationKey(gcjk)
	}

	// key generation extend time
	ExtGentemp = time.Since(Update_KG_start)
	fmt.Print("Extend (key) Generation time = ", ExtGentemp, "\n")

	// === jk generation ===
	// New sk's summation
	lastSk = skNewList[0]
	for p := 1; p < JoiningParties; p++ {
		ringQP.AddLvl(levelQ, levelP, lastSk.Value, skNewList[p].Value, lastSk.Value)
	}

	if lastSk != nil {
		jkhead, jk = testContext.kgen.GenExtKey(gpkpre, lastSk, gskpre)
	}

	// === Update ciphertexts ===
	msgRes := testContext.decryptor.DecryptSk(ctxtList[0], gskpre)
	fmt.Print("ctxt before Extend = ", msgRes.Value[:2], "\n")

	Update_ctxt_start := time.Now()
	ctxtListup = make([]*Ciphertext, len(ctxtList))
	for k := range ctxtList {
		ctxtListup[k] = testContext2.evaluator.KSNew(ctxtList[k], jk, jkhead)
	}
	ExtCttemp = time.Since(Update_ctxt_start)
	fmt.Print("Extend (ctxt) time = ", ExtCttemp, "\n")

	msgRes2 := testContext.decryptor.DecryptSk(ctxtListup[0], gsk)
	fmt.Print("ctxt after Extend = ", msgRes2.Value[:2], "\n")

	if testContext2.prng, err = utils.NewPRNG(); err != nil {
		return nil, err, gskpre, gpk, grlk, gcjk, grtk, jk, jkhead, uaux, uauxhead, ctxtListup, ExtGentemp, ExtCttemp
	}

	testContext2.encryptor = testContext.encryptor
	testContext2.decryptor = testContext.decryptor
	testContext2.evaluator = testContext.evaluator
	testContext2.ringP = testContext.ringP
	testContext2.ringQ = testContext.ringQ

	return testContext2, nil, gsk, gpk, grlk, gcjk, grtk, jk, jkhead, uaux, uauxhead, ctxtListup, ExtGentemp, ExtCttemp
}

func Join_rdMPHE(testContext *testParams,
	gsk *mkrlwe.SecretKey, gpk *mkrlwe.PublicKey,
	grlk *RelinearizationKey, gcjk *mkrlwe.ConjugationKey, grtk *mkrlwe.RotationKey,
	sk []*mkrlwe.SecretKey, jk *mkrlwe.SWK, jkhead *mkrlwe.SWK, uaux *mkrlwe.SWK, uauxhead *mkrlwe.SWK,
	groupIdSet *mkrlwe.IDSet, numParties int, JoiningParties int,
	ctxtList []*Ciphertext, t *testing.T,
) (testContext2 *testParams, err error,
	gskup *mkrlwe.SecretKey, gpkup *mkrlwe.PublicKey,
	grlkup *RelinearizationKey, gcjkup *mkrlwe.ConjugationKey, grtkup *mkrlwe.RotationKey, skup []*mkrlwe.SecretKey,
	jkup *mkrlwe.SWK, jkheadup *mkrlwe.SWK,
	uauxup *mkrlwe.SWK, uauxheadup *mkrlwe.SWK,
	ctxtListup []*Ciphertext, ExtGentemp, ExtCttemp time.Duration) {

	Update_KG_start := time.Now()
	testContext2 = testContext

	params := testContext.params
	levelQ := params.QCount() - 1
	levelP := params.PCount() - 1
	beta := params.Beta(levelQ)
	ringQP := params.RingQP()

	// Save pre-update copies
	gskpre := gsk.CopyNew()
	gpkpre := gpk.CopyNew()

	skNewList := make([]*mkrlwe.SecretKey, JoiningParties)
	skup = make([]*mkrlwe.SecretKey, len(sk)+JoiningParties)

	var lastSk *mkrlwe.SecretKey

	// === Generate & integrate keys for joining parties (no appends) ===
	for p := 0; p < JoiningParties; p++ {
		// 1) local key
		skNew, pkNew := testContext2.kgen.GenKeyPair("group0")
		rlkNew := testContext2.kgen.GenRelinearizationKey(skNew)
		cjkNew := testContext2.kgen.GenConjugationKey(skNew)
		rtkNew := testContext2.kgen.GenDefaultRotationKeys(skNew)

		// New sk list
		skNewList[p] = skNew

		// 2) global secret key update: gsk := gsk + skNew
		ringQP.AddLvl(levelQ, levelP, gsk.Value, skNew.Value, gsk.Value)
		testContext2.skSet.AddSecretKey(gsk)

		// 3) global public key update: gpk := gpk + pkNew
		ringQP.AddLvl(levelQ, levelP, gpk.Value[0], pkNew.Value[0], gpk.Value[0])
		testContext2.pkSet.AddPublicKey(gpk)

		// 4) rotation keys update
		for idx := range rtkNew {
			rtkCur := testContext.rtkSet.Value["group0"][idx]
			for i := 0; i < beta; i++ {
				ringQP.AddLvl(levelQ, levelP,
					rtkCur.Value.Value[i],
					rtkNew[idx].Value.Value[i],
					rtkCur.Value.Value[i])
			}
			testContext2.rtkSet.AddRotationKey(rtkCur)
		}

		// 5) relinearization & conjugation update
		for i := 0; i < beta; i++ {
			ringQP.AddLvl(levelQ, levelP,
				grlk.Value[0].Value[0].Value[i],
				rlkNew.Value[0].Value[0].Value[i],
				grlk.Value[0].Value[0].Value[i])
			ringQP.AddLvl(levelQ, levelP,
				grlk.Value[0].Value[1].Value[i],
				rlkNew.Value[0].Value[1].Value[i],
				grlk.Value[0].Value[1].Value[i])
			ringQP.AddLvl(levelQ, levelP,
				grlk.Value[0].Value[2].Value[i],
				rlkNew.Value[0].Value[2].Value[i],
				grlk.Value[0].Value[2].Value[i])

			ringQP.AddLvl(levelQ, levelP,
				grlk.Value[1].Value[0].Value[i],
				rlkNew.Value[1].Value[0].Value[i],
				grlk.Value[1].Value[0].Value[i])
			ringQP.AddLvl(levelQ, levelP,
				grlk.Value[1].Value[1].Value[i],
				rlkNew.Value[1].Value[1].Value[i],
				grlk.Value[1].Value[1].Value[i])

			ringQP.AddLvl(levelQ, levelP,
				gcjk.Value.Value[i],
				cjkNew.Value.Value[i],
				gcjk.Value.Value[i])
		}
		testContext2.rlkSet.AddRelinearizationKey(grlk)
		testContext2.cjkSet.AddConjugationKey(gcjk)

		// 6) swkSet / swkheadSet length extension (index = numParties + p) 				6~8) DELETE FOR dMPHE !!!!
		idx := numParties + p

		if testContext2.swkSet[idx] == nil {
			testContext2.swkSet[idx] = mkrlwe.NewSWKSet()
		}
		if testContext2.swkheadSet[idx] == nil {
			testContext2.swkheadSet[idx] = mkrlwe.NewSWKSet()
		}

		// 7) swk gen
		swkNew, swkheadNew := testContext.kgen.GenSWK(skNew, gpk)
		testContext2.swkSet[idx].AddSWK(swkNew)
		testContext2.swkheadSet[idx].AddSWK(swkheadNew)

	}

	// key generation extend time
	ExtGentemp = time.Since(Update_KG_start)
	fmt.Print("Extend (key) Generation time = ", ExtGentemp, "\n")

	// === jk generation ===
	// New sk's summation
	lastSk = skNewList[0]
	for p := 1; p < JoiningParties; p++ {
		ringQP.AddLvl(levelQ, levelP, lastSk.Value, skNewList[p].Value, lastSk.Value)
	}

	if lastSk != nil {
		jkhead, jk = testContext.kgen.GenExtKey(gpkpre, lastSk, gskpre)
	}

	// === Update ciphertexts ===
	msgRes := testContext.decryptor.DecryptSk(ctxtList[0], gskpre)
	fmt.Print("ctxt before Extend = ", msgRes.Value[:2], "\n")

	Update_ctxt_start := time.Now()
	ctxtListup = make([]*Ciphertext, len(ctxtList))
	for k := range ctxtList {
		ctxtListup[k] = testContext2.evaluator.KSNew(ctxtList[k], jk, jkhead)
	}
	ExtCttemp = time.Since(Update_ctxt_start)
	fmt.Print("Extend (ctxt) time = ", ExtCttemp, "\n")

	msgRes2 := testContext.decryptor.DecryptSk(ctxtListup[0], gsk)
	fmt.Print("ctxt after Extend = ", msgRes2.Value[:2], "\n")

	for k := 0; k < len(sk); k++ {
		skup[k] = sk[k]
	}
	for k := 0; k < JoiningParties; k++ {
		skup[len(sk)+k] = skNewList[k]
	}

	if testContext2.prng, err = utils.NewPRNG(); err != nil {
		return nil, err, gskpre, gpk, grlk, gcjk, grtk, skup, jk, jkhead, uaux, uauxhead, ctxtListup, ExtGentemp, ExtCttemp
	}

	testContext2.encryptor = testContext.encryptor
	testContext2.decryptor = testContext.decryptor
	testContext2.evaluator = testContext.evaluator
	testContext2.ringP = testContext.ringP
	testContext2.ringQ = testContext.ringQ

	return testContext2, nil, gsk, gpk, grlk, gcjk, grtk, skup, jk, jkhead, uaux, uauxhead, ctxtListup, ExtGentemp, ExtCttemp
}

func testJoinPartyMK(
	testContext *testParams,
	groupIdSet *mkrlwe.IDSet,
	groupList []string,
	numParties int,
	JoiningParties int,
	t *testing.T,
) (
	testContextout *testParams,
	groupIdSetup *mkrlwe.IDSet,
	err error,
) {

	// -------------------------------------------------
	// 1) Extend group list & ID set
	// -------------------------------------------------
	groupListup := make([]string, len(groupList)+JoiningParties)
	idsetup := mkrlwe.NewIDSet()

	for i := range groupList {
		groupListup[i] = groupList[i]
		idsetup.Add(groupListup[i])
	}

	for i := len(groupList); i < len(groupList)+JoiningParties; i++ {
		groupListup[i] = "group" + strconv.Itoa(i)
		idsetup.Add(groupListup[i])
	}

	// -------------------------------------------------
	// 2) Generate keys for joining parties
	// -------------------------------------------------
	for i := len(groupList); i < len(groupList)+JoiningParties; i++ {

		groupId := groupListup[i]

		// local keys
		skNew, pkNew := testContext.kgen.GenKeyPair(groupId)
		rlkNew := testContext.kgen.GenRelinearizationKey(skNew)
		cjkNew := testContext.kgen.GenConjugationKey(skNew)
		rtksNew := testContext.kgen.GenDefaultRotationKeys(skNew)

		// register to context (global sets)
		testContext.skSet.AddSecretKey(skNew)
		testContext.pkSet.AddPublicKey(pkNew)
		testContext.rlkSet.AddRelinearizationKey(rlkNew)
		testContext.cjkSet.AddConjugationKey(cjkNew)

		for _, rtk := range rtksNew {
			testContext.rtkSet.AddRotationKey(rtk)
		}
	}

	// -------------------------------------------------
	// 3) finalize
	// -------------------------------------------------
	testContextout = testContext
	groupIdSetup = idsetup

	if testContext.prng, err = utils.NewPRNG(); err != nil {
		return nil, idsetup, err
	}

	return testContextout, idsetup, nil
}

func Error(
	testContext *testParams,
	msgVals []int64,
	ct *Ciphertext,
) (logInfAbsErr float64, Noisebudget float64) {

	params := testContext.params
	ringQ := params.RingQ()
	level := ct.Level()

	// --------------------------------------------------
	// 1) Encode message (ALREADY in RingQ, scaled by Delta)
	// --------------------------------------------------
	ptEnc := testContext.decryptor.ptxtPool
	testContext.decryptor.encoder.EncodeInt(msgVals, ptEnc)

	// --------------------------------------------------
	// 2) Decrypt ONLY (NO Decode, NO rounding)
	// --------------------------------------------------
	ptDec := rlwe.NewPlaintext(params.Parameters.Parameters, level)
	testContext.decryptor.Decryptor.Decrypt(
		ct.Ciphertext,
		testContext.skSet,
		ptDec,
	)

	// --------------------------------------------------
	// 3) v = decrypted - encoded   (mod Q)
	// --------------------------------------------------
	vPoly := ringQ.NewPoly()
	ringQ.Sub(ptDec.Value, ptEnc.Value, vPoly)

	// --------------------------------------------------
	// 4) Convert v to centered BigInt coefficients
	// --------------------------------------------------
	coeffs := make([]*big.Int, ringQ.N)
	for i := range coeffs {
		coeffs[i] = new(big.Int)
	}
	ringQ.PolyToBigintCenteredLvl(level, vPoly, coeffs)

	// --------------------------------------------------
	// 5) Infinity norm
	// --------------------------------------------------
	maxAbs := new(big.Int)
	for _, c := range coeffs {
		abs := new(big.Int).Abs(c)
		if abs.Cmp(maxAbs) > 0 {
			maxAbs.Set(abs)
		}
	}

	// --------------------------------------------------
	// 6) Print error bits vs Q
	// --------------------------------------------------
	Qbig := params.QBigInt()
	errBits := maxAbs.BitLen()
	QBits := Qbig.BitLen()

	fmt.Printf("============================================\n")
	fmt.Printf(" BFV Ciphertext Error (RingQ, pre-round)\n")
	fmt.Printf("--------------------------------------------\n")
	fmt.Printf(" ||v||_∞           : %s\n", maxAbs.String())
	fmt.Printf(" log2(||v||_∞)     : %d bits\n", errBits)
	fmt.Printf(" log2(Q)           : %d bits\n", QBits)
	fmt.Printf(" Remaining margin  : %d bits\n", QBits-errBits)
	fmt.Printf("============================================\n")

	logInfAbsErr = float64(errBits)
	Noisebudget = float64(QBits - errBits)

	return logInfAbsErr, Noisebudget
}
