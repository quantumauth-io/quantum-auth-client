// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package quantumauthaccount

import (
	"errors"
	"math/big"
	"strings"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
)

// Reference imports to suppress errors if they are not otherwise used.
var (
	_ = errors.New
	_ = big.NewInt
	_ = strings.NewReader
	_ = ethereum.NotFound
	_ = bind.Bind
	_ = common.Big1
	_ = types.BloomLookup
	_ = event.NewSubscription
	_ = abi.ConvertType
)

// BaseAccountCall is an auto generated low-level Go binding around an user-defined struct.
type BaseAccountCall struct {
	Target common.Address
	Value  *big.Int
	Data   []byte
}

// PackedUserOperation is an auto generated low-level Go binding around an user-defined struct.
type PackedUserOperation struct {
	Sender             common.Address
	Nonce              *big.Int
	InitCode           []byte
	CallData           []byte
	AccountGasLimits   [32]byte
	PreVerificationGas *big.Int
	GasFees            [32]byte
	PaymasterAndData   []byte
	Signature          []byte
}

// QuantumAuthAccountMetaData contains all meta data concerning the QuantumAuthAccount contract.
var QuantumAuthAccountMetaData = &bind.MetaData{
	ABI: "[{\"type\":\"constructor\",\"inputs\":[{\"name\":\"entryPoint_\",\"type\":\"address\",\"internalType\":\"contractIEntryPoint\"},{\"name\":\"eoa1_\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"eoa2_\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"tpmVerifier_\",\"type\":\"address\",\"internalType\":\"contractITPMVerifier\"},{\"name\":\"tpmKeyId_\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"stateMutability\":\"nonpayable\"},{\"type\":\"receive\",\"stateMutability\":\"payable\"},{\"type\":\"function\",\"name\":\"EOA1\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"EOA2\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"TPM_KEY_ID\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"TPM_VERIFIER\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"contractITPMVerifier\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"entryPoint\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"contractIEntryPoint\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"execute\",\"inputs\":[{\"name\":\"target\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"value\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"data\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"executeBatch\",\"inputs\":[{\"name\":\"calls\",\"type\":\"tuple[]\",\"internalType\":\"structBaseAccount.Call[]\",\"components\":[{\"name\":\"target\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"value\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"data\",\"type\":\"bytes\",\"internalType\":\"bytes\"}]}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"getNonce\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"validateUserOp\",\"inputs\":[{\"name\":\"userOp\",\"type\":\"tuple\",\"internalType\":\"structPackedUserOperation\",\"components\":[{\"name\":\"sender\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"nonce\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"initCode\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"callData\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"accountGasLimits\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"preVerificationGas\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"gasFees\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"paymasterAndData\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"signature\",\"type\":\"bytes\",\"internalType\":\"bytes\"}]},{\"name\":\"userOpHash\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"missingAccountFunds\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"validationData\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"nonpayable\"},{\"type\":\"error\",\"name\":\"ECDSAInvalidSignature\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"ECDSAInvalidSignatureLength\",\"inputs\":[{\"name\":\"length\",\"type\":\"uint256\",\"internalType\":\"uint256\"}]},{\"type\":\"error\",\"name\":\"ECDSAInvalidSignatureS\",\"inputs\":[{\"name\":\"s\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}]},{\"type\":\"error\",\"name\":\"ExecuteError\",\"inputs\":[{\"name\":\"index\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"error\",\"type\":\"bytes\",\"internalType\":\"bytes\"}]},{\"type\":\"error\",\"name\":\"InvalidEOA\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"InvalidMode\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"InvalidTPMVerifier\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"NotAuthorized\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"NotFromEntryPoint\",\"inputs\":[{\"name\":\"msgSender\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"entity\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"entryPoint\",\"type\":\"address\",\"internalType\":\"address\"}]},{\"type\":\"error\",\"name\":\"OnlyEntryPoint\",\"inputs\":[]}]",
	Bin: "0x6101203461016c57601f610cf038819003918201601f19168301916001600160401b038311848410176101705780849260a09460405283398101031261016c5780516001600160a01b038116810361016c5761005d60208301610184565b61006960408401610184565b9060608401519260018060a01b0384169485850361016c5760800151946001600160a01b038316801590811561015a575b8115610147575b5061013857156101295760805260a05260c05260e05261010052604051610b579081610199823960805181818161022c0152818161034d015281816105e00152610688015260a0518181816102ed01526107f9015260c0518181816101e80152610822015260e0518181816101a401526108e00152610100518181816103df01526108b40152f35b633c4ac85360e21b5f5260045ffd5b6303602a5960e51b5f5260045ffd5b6001600160a01b0386161490505f6100a1565b6001600160a01b03861615915061009a565b5f80fd5b634e487b7160e01b5f52604160045260245ffd5b51906001600160a01b038216820361016c5756fe6080604052600436101561001a575b3615610018575f80fd5b005b5f3560e01c806319822f7c146100a957806334fcd5be146100a45780637e8ee8141461009f578063a6b18bc01461009a578063b0d691fe14610095578063b61d27f614610090578063bfbbda751461008b578063d087d288146100865763d9260ecf0361000e576103c8565b61031c565b6102d8565b61026c565b610217565b6101d3565b61018f565b610132565b3461012e57606036600319011261012e5760043567ffffffffffffffff811161012e57610120600319823603011261012e57610112906100fa604435916100ee610686565b6024359060040161079c565b9080610116575b506040519081529081906020820190565b0390f35b5f80808093335af15061012761064c565b5082610101565b5f80fd5b3461012e57602036600319011261012e5760043567ffffffffffffffff811161012e573660238201121561012e57806004013567ffffffffffffffff811161012e573660248260051b8401011161012e5760246100189201610540565b3461012e575f36600319011261012e576040517f00000000000000000000000000000000000000000000000000000000000000006001600160a01b03168152602090f35b3461012e575f36600319011261012e576040517f00000000000000000000000000000000000000000000000000000000000000006001600160a01b03168152602090f35b3461012e575f36600319011261012e576040517f00000000000000000000000000000000000000000000000000000000000000006001600160a01b03168152602090f35b6001600160a01b0381160361012e57565b3461012e57606036600319011261012e576004356102898161025b565b6024356044359167ffffffffffffffff831161012e573660238401121561012e5782600401359167ffffffffffffffff831161012e57366024848601011161012e5760246100189401916105dc565b3461012e575f36600319011261012e576040517f00000000000000000000000000000000000000000000000000000000000000006001600160a01b03168152602090f35b3461012e575f36600319011261012e57604051631aab3f0d60e11b81523060048201525f60248201526020816044817f00000000000000000000000000000000000000000000000000000000000000006001600160a01b03165afa80156103c3575f9061038f575b604051908152602090f35b506020813d6020116103bb575b816103a96020938361048c565b8101031261012e576101129051610384565b3d915061039c565b61067b565b3461012e575f36600319011261012e5760206040517f00000000000000000000000000000000000000000000000000000000000000008152f35b91908110156104245760051b81013590605e198136030182121561012e570190565b634e487b7160e01b5f52603260045260245ffd5b356104428161025b565b90565b903590601e198136030182121561012e570180359067ffffffffffffffff821161012e5760200191813603831361012e57565b634e487b7160e01b5f52604160045260245ffd5b90601f8019910116810190811067ffffffffffffffff8211176104ae57604052565b610478565b67ffffffffffffffff81116104ae57601f01601f191660200190565b9291926104db826104b3565b916104e9604051938461048c565b82948184528183011161012e578281602093845f960137010152565b805180835260209291819084018484015e5f828201840152601f01601f1916010190565b604090610442939281528160208201520190610505565b90610549610686565b5f5b81811061055757505050565b61059d61059961059361056b848688610402565b61057481610438565b906105886020820135916040810190610445565b93905a9436916104cf565b9161095f565b1590565b6105a95760010161054b565b600182145f0361098b576105bb610971565b604051635a15467560e01b81529182916105d89160048401610529565b0390fd5b90927f00000000000000000000000000000000000000000000000000000000000000006001600160a01b0316330361063d575f938493826040519384928337810185815203925af161062c61064c565b90156106355750565b602081519101fd5b63bd07c55160e01b5f5260045ffd5b3d15610676573d9061065d826104b3565b9161066b604051938461048c565b82523d5f602084013e565b606090565b6040513d5f823e3d90fd5b7f00000000000000000000000000000000000000000000000000000000000000006001600160a01b0316338190036106bb5750565b63fe34a6d360e01b5f52336004523060245260445260645ffd5b9080601f8301121561012e57816020610442933591016104cf565b9060808282031261012e57813560ff8116810361012e5792602083013567ffffffffffffffff811161012e57826107289185016106d5565b92604081013567ffffffffffffffff811161012e57836107499183016106d5565b92606082013567ffffffffffffffff811161012e5761044292016106d5565b9081602091031261012e5751801515810361012e5790565b6104429392606092825260208201528160408201520190610505565b610847916107bc6107b460ff93610100810190610445565b8101906106f0565b92949161081f6107f6869893987f19457468657265756d205369676e6564204d6573736167653a0a3332000000005f52601c52603c5f2090565b917f00000000000000000000000000000000000000000000000000000000000000009083610993565b967f000000000000000000000000000000000000000000000000000000000000000091610993565b93169182156108855750506001146108685763a0042b1760e01b5f5260045ffd5b8161087d575b5015610878575f90565b600190565b90505f61086e565b9290938092509115610957575b5015610950576040516303784b1960e61b815291602091839182916108dc91907f000000000000000000000000000000000000000000000000000000000000000060048501610780565b03817f00000000000000000000000000000000000000000000000000000000000000006001600160a01b03165afa9081156103c3575f91610921575015610878575f90565b610943915060203d602011610949575b61093b818361048c565b810190610768565b5f61086e565b503d610931565b5050600190565b90505f610892565b925f939184939260208451940192f190565b3d604051906020818301016040528082525f602083013e90565b610635610971565b9190918251156109c4576109b3926109aa916109cb565b90939193610a23565b6001600160a01b0391821691161490565b5050505f90565b81519190604183036109fb576109f49250602082015190606060408401519301515f1a90610a9f565b9192909190565b50505f9160029190565b60041115610a0f57565b634e487b7160e01b5f52602160045260245ffd5b610a2c81610a05565b80610a35575050565b610a3e81610a05565b60018103610a555763f645eedf60e01b5f5260045ffd5b610a5e81610a05565b60028103610a79575063fce698f760e01b5f5260045260245ffd5b80610a85600392610a05565b14610a8d5750565b6335e2f38360e21b5f5260045260245ffd5b91907f7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a08411610b16579160209360809260ff5f9560405194855216868401526040830152606082015282805260015afa156103c3575f516001600160a01b03811615610b0c57905f905f90565b505f906001905f90565b5050505f916003919056fea2646970667358221220e4ae55a0edb65eef9595c750ad0f549c7dcc5849412953f246a37210b5377d0e64736f6c634300081c0033",
}

// QuantumAuthAccountABI is the input ABI used to generate the binding from.
// Deprecated: Use QuantumAuthAccountMetaData.ABI instead.
var QuantumAuthAccountABI = QuantumAuthAccountMetaData.ABI

// QuantumAuthAccountBin is the compiled bytecode used for deploying new contracts.
// Deprecated: Use QuantumAuthAccountMetaData.Bin instead.
var QuantumAuthAccountBin = QuantumAuthAccountMetaData.Bin

// DeployQuantumAuthAccount deploys a new Ethereum contract, binding an instance of QuantumAuthAccount to it.
func DeployQuantumAuthAccount(auth *bind.TransactOpts, backend bind.ContractBackend, entryPoint_ common.Address, eoa1_ common.Address, eoa2_ common.Address, tpmVerifier_ common.Address, tpmKeyId_ [32]byte) (common.Address, *types.Transaction, *QuantumAuthAccount, error) {
	parsed, err := QuantumAuthAccountMetaData.GetAbi()
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	if parsed == nil {
		return common.Address{}, nil, nil, errors.New("GetABI returned nil")
	}

	address, tx, contract, err := bind.DeployContract(auth, *parsed, common.FromHex(QuantumAuthAccountBin), backend, entryPoint_, eoa1_, eoa2_, tpmVerifier_, tpmKeyId_)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &QuantumAuthAccount{QuantumAuthAccountCaller: QuantumAuthAccountCaller{contract: contract}, QuantumAuthAccountTransactor: QuantumAuthAccountTransactor{contract: contract}, QuantumAuthAccountFilterer: QuantumAuthAccountFilterer{contract: contract}}, nil
}

// QuantumAuthAccount is an auto generated Go binding around an Ethereum contract.
type QuantumAuthAccount struct {
	QuantumAuthAccountCaller     // Read-only binding to the contract
	QuantumAuthAccountTransactor // Write-only binding to the contract
	QuantumAuthAccountFilterer   // Log filterer for contract events
}

// QuantumAuthAccountCaller is an auto generated read-only Go binding around an Ethereum contract.
type QuantumAuthAccountCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// QuantumAuthAccountTransactor is an auto generated write-only Go binding around an Ethereum contract.
type QuantumAuthAccountTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// QuantumAuthAccountFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type QuantumAuthAccountFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// QuantumAuthAccountSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type QuantumAuthAccountSession struct {
	Contract     *QuantumAuthAccount // Generic contract binding to set the session for
	CallOpts     bind.CallOpts       // Call options to use throughout this session
	TransactOpts bind.TransactOpts   // Transaction auth options to use throughout this session
}

// QuantumAuthAccountCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type QuantumAuthAccountCallerSession struct {
	Contract *QuantumAuthAccountCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts             // Call options to use throughout this session
}

// QuantumAuthAccountTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type QuantumAuthAccountTransactorSession struct {
	Contract     *QuantumAuthAccountTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts             // Transaction auth options to use throughout this session
}

// QuantumAuthAccountRaw is an auto generated low-level Go binding around an Ethereum contract.
type QuantumAuthAccountRaw struct {
	Contract *QuantumAuthAccount // Generic contract binding to access the raw methods on
}

// QuantumAuthAccountCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type QuantumAuthAccountCallerRaw struct {
	Contract *QuantumAuthAccountCaller // Generic read-only contract binding to access the raw methods on
}

// QuantumAuthAccountTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type QuantumAuthAccountTransactorRaw struct {
	Contract *QuantumAuthAccountTransactor // Generic write-only contract binding to access the raw methods on
}

// NewQuantumAuthAccount creates a new instance of QuantumAuthAccount, bound to a specific deployed contract.
func NewQuantumAuthAccount(address common.Address, backend bind.ContractBackend) (*QuantumAuthAccount, error) {
	contract, err := bindQuantumAuthAccount(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &QuantumAuthAccount{QuantumAuthAccountCaller: QuantumAuthAccountCaller{contract: contract}, QuantumAuthAccountTransactor: QuantumAuthAccountTransactor{contract: contract}, QuantumAuthAccountFilterer: QuantumAuthAccountFilterer{contract: contract}}, nil
}

// NewQuantumAuthAccountCaller creates a new read-only instance of QuantumAuthAccount, bound to a specific deployed contract.
func NewQuantumAuthAccountCaller(address common.Address, caller bind.ContractCaller) (*QuantumAuthAccountCaller, error) {
	contract, err := bindQuantumAuthAccount(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &QuantumAuthAccountCaller{contract: contract}, nil
}

// NewQuantumAuthAccountTransactor creates a new write-only instance of QuantumAuthAccount, bound to a specific deployed contract.
func NewQuantumAuthAccountTransactor(address common.Address, transactor bind.ContractTransactor) (*QuantumAuthAccountTransactor, error) {
	contract, err := bindQuantumAuthAccount(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &QuantumAuthAccountTransactor{contract: contract}, nil
}

// NewQuantumAuthAccountFilterer creates a new log filterer instance of QuantumAuthAccount, bound to a specific deployed contract.
func NewQuantumAuthAccountFilterer(address common.Address, filterer bind.ContractFilterer) (*QuantumAuthAccountFilterer, error) {
	contract, err := bindQuantumAuthAccount(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &QuantumAuthAccountFilterer{contract: contract}, nil
}

// bindQuantumAuthAccount binds a generic wrapper to an already deployed contract.
func bindQuantumAuthAccount(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := QuantumAuthAccountMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_QuantumAuthAccount *QuantumAuthAccountRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _QuantumAuthAccount.Contract.QuantumAuthAccountCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_QuantumAuthAccount *QuantumAuthAccountRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _QuantumAuthAccount.Contract.QuantumAuthAccountTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_QuantumAuthAccount *QuantumAuthAccountRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _QuantumAuthAccount.Contract.QuantumAuthAccountTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_QuantumAuthAccount *QuantumAuthAccountCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _QuantumAuthAccount.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_QuantumAuthAccount *QuantumAuthAccountTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _QuantumAuthAccount.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_QuantumAuthAccount *QuantumAuthAccountTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _QuantumAuthAccount.Contract.contract.Transact(opts, method, params...)
}

// EOA1 is a free data retrieval call binding the contract method 0xbfbbda75.
//
// Solidity: function EOA1() view returns(address)
func (_QuantumAuthAccount *QuantumAuthAccountCaller) EOA1(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _QuantumAuthAccount.contract.Call(opts, &out, "EOA1")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// EOA1 is a free data retrieval call binding the contract method 0xbfbbda75.
//
// Solidity: function EOA1() view returns(address)
func (_QuantumAuthAccount *QuantumAuthAccountSession) EOA1() (common.Address, error) {
	return _QuantumAuthAccount.Contract.EOA1(&_QuantumAuthAccount.CallOpts)
}

// EOA1 is a free data retrieval call binding the contract method 0xbfbbda75.
//
// Solidity: function EOA1() view returns(address)
func (_QuantumAuthAccount *QuantumAuthAccountCallerSession) EOA1() (common.Address, error) {
	return _QuantumAuthAccount.Contract.EOA1(&_QuantumAuthAccount.CallOpts)
}

// EOA2 is a free data retrieval call binding the contract method 0xa6b18bc0.
//
// Solidity: function EOA2() view returns(address)
func (_QuantumAuthAccount *QuantumAuthAccountCaller) EOA2(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _QuantumAuthAccount.contract.Call(opts, &out, "EOA2")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// EOA2 is a free data retrieval call binding the contract method 0xa6b18bc0.
//
// Solidity: function EOA2() view returns(address)
func (_QuantumAuthAccount *QuantumAuthAccountSession) EOA2() (common.Address, error) {
	return _QuantumAuthAccount.Contract.EOA2(&_QuantumAuthAccount.CallOpts)
}

// EOA2 is a free data retrieval call binding the contract method 0xa6b18bc0.
//
// Solidity: function EOA2() view returns(address)
func (_QuantumAuthAccount *QuantumAuthAccountCallerSession) EOA2() (common.Address, error) {
	return _QuantumAuthAccount.Contract.EOA2(&_QuantumAuthAccount.CallOpts)
}

// TPMKEYID is a free data retrieval call binding the contract method 0xd9260ecf.
//
// Solidity: function TPM_KEY_ID() view returns(bytes32)
func (_QuantumAuthAccount *QuantumAuthAccountCaller) TPMKEYID(opts *bind.CallOpts) ([32]byte, error) {
	var out []interface{}
	err := _QuantumAuthAccount.contract.Call(opts, &out, "TPM_KEY_ID")

	if err != nil {
		return *new([32]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)

	return out0, err

}

// TPMKEYID is a free data retrieval call binding the contract method 0xd9260ecf.
//
// Solidity: function TPM_KEY_ID() view returns(bytes32)
func (_QuantumAuthAccount *QuantumAuthAccountSession) TPMKEYID() ([32]byte, error) {
	return _QuantumAuthAccount.Contract.TPMKEYID(&_QuantumAuthAccount.CallOpts)
}

// TPMKEYID is a free data retrieval call binding the contract method 0xd9260ecf.
//
// Solidity: function TPM_KEY_ID() view returns(bytes32)
func (_QuantumAuthAccount *QuantumAuthAccountCallerSession) TPMKEYID() ([32]byte, error) {
	return _QuantumAuthAccount.Contract.TPMKEYID(&_QuantumAuthAccount.CallOpts)
}

// TPMVERIFIER is a free data retrieval call binding the contract method 0x7e8ee814.
//
// Solidity: function TPM_VERIFIER() view returns(address)
func (_QuantumAuthAccount *QuantumAuthAccountCaller) TPMVERIFIER(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _QuantumAuthAccount.contract.Call(opts, &out, "TPM_VERIFIER")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// TPMVERIFIER is a free data retrieval call binding the contract method 0x7e8ee814.
//
// Solidity: function TPM_VERIFIER() view returns(address)
func (_QuantumAuthAccount *QuantumAuthAccountSession) TPMVERIFIER() (common.Address, error) {
	return _QuantumAuthAccount.Contract.TPMVERIFIER(&_QuantumAuthAccount.CallOpts)
}

// TPMVERIFIER is a free data retrieval call binding the contract method 0x7e8ee814.
//
// Solidity: function TPM_VERIFIER() view returns(address)
func (_QuantumAuthAccount *QuantumAuthAccountCallerSession) TPMVERIFIER() (common.Address, error) {
	return _QuantumAuthAccount.Contract.TPMVERIFIER(&_QuantumAuthAccount.CallOpts)
}

// EntryPoint is a free data retrieval call binding the contract method 0xb0d691fe.
//
// Solidity: function entryPoint() view returns(address)
func (_QuantumAuthAccount *QuantumAuthAccountCaller) EntryPoint(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _QuantumAuthAccount.contract.Call(opts, &out, "entryPoint")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// EntryPoint is a free data retrieval call binding the contract method 0xb0d691fe.
//
// Solidity: function entryPoint() view returns(address)
func (_QuantumAuthAccount *QuantumAuthAccountSession) EntryPoint() (common.Address, error) {
	return _QuantumAuthAccount.Contract.EntryPoint(&_QuantumAuthAccount.CallOpts)
}

// EntryPoint is a free data retrieval call binding the contract method 0xb0d691fe.
//
// Solidity: function entryPoint() view returns(address)
func (_QuantumAuthAccount *QuantumAuthAccountCallerSession) EntryPoint() (common.Address, error) {
	return _QuantumAuthAccount.Contract.EntryPoint(&_QuantumAuthAccount.CallOpts)
}

// GetNonce is a free data retrieval call binding the contract method 0xd087d288.
//
// Solidity: function getNonce() view returns(uint256)
func (_QuantumAuthAccount *QuantumAuthAccountCaller) GetNonce(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _QuantumAuthAccount.contract.Call(opts, &out, "getNonce")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// GetNonce is a free data retrieval call binding the contract method 0xd087d288.
//
// Solidity: function getNonce() view returns(uint256)
func (_QuantumAuthAccount *QuantumAuthAccountSession) GetNonce() (*big.Int, error) {
	return _QuantumAuthAccount.Contract.GetNonce(&_QuantumAuthAccount.CallOpts)
}

// GetNonce is a free data retrieval call binding the contract method 0xd087d288.
//
// Solidity: function getNonce() view returns(uint256)
func (_QuantumAuthAccount *QuantumAuthAccountCallerSession) GetNonce() (*big.Int, error) {
	return _QuantumAuthAccount.Contract.GetNonce(&_QuantumAuthAccount.CallOpts)
}

// Execute is a paid mutator transaction binding the contract method 0xb61d27f6.
//
// Solidity: function execute(address target, uint256 value, bytes data) returns()
func (_QuantumAuthAccount *QuantumAuthAccountTransactor) Execute(opts *bind.TransactOpts, target common.Address, value *big.Int, data []byte) (*types.Transaction, error) {
	return _QuantumAuthAccount.contract.Transact(opts, "execute", target, value, data)
}

// Execute is a paid mutator transaction binding the contract method 0xb61d27f6.
//
// Solidity: function execute(address target, uint256 value, bytes data) returns()
func (_QuantumAuthAccount *QuantumAuthAccountSession) Execute(target common.Address, value *big.Int, data []byte) (*types.Transaction, error) {
	return _QuantumAuthAccount.Contract.Execute(&_QuantumAuthAccount.TransactOpts, target, value, data)
}

// Execute is a paid mutator transaction binding the contract method 0xb61d27f6.
//
// Solidity: function execute(address target, uint256 value, bytes data) returns()
func (_QuantumAuthAccount *QuantumAuthAccountTransactorSession) Execute(target common.Address, value *big.Int, data []byte) (*types.Transaction, error) {
	return _QuantumAuthAccount.Contract.Execute(&_QuantumAuthAccount.TransactOpts, target, value, data)
}

// ExecuteBatch is a paid mutator transaction binding the contract method 0x34fcd5be.
//
// Solidity: function executeBatch((address,uint256,bytes)[] calls) returns()
func (_QuantumAuthAccount *QuantumAuthAccountTransactor) ExecuteBatch(opts *bind.TransactOpts, calls []BaseAccountCall) (*types.Transaction, error) {
	return _QuantumAuthAccount.contract.Transact(opts, "executeBatch", calls)
}

// ExecuteBatch is a paid mutator transaction binding the contract method 0x34fcd5be.
//
// Solidity: function executeBatch((address,uint256,bytes)[] calls) returns()
func (_QuantumAuthAccount *QuantumAuthAccountSession) ExecuteBatch(calls []BaseAccountCall) (*types.Transaction, error) {
	return _QuantumAuthAccount.Contract.ExecuteBatch(&_QuantumAuthAccount.TransactOpts, calls)
}

// ExecuteBatch is a paid mutator transaction binding the contract method 0x34fcd5be.
//
// Solidity: function executeBatch((address,uint256,bytes)[] calls) returns()
func (_QuantumAuthAccount *QuantumAuthAccountTransactorSession) ExecuteBatch(calls []BaseAccountCall) (*types.Transaction, error) {
	return _QuantumAuthAccount.Contract.ExecuteBatch(&_QuantumAuthAccount.TransactOpts, calls)
}

// ValidateUserOp is a paid mutator transaction binding the contract method 0x19822f7c.
//
// Solidity: function validateUserOp((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes) userOp, bytes32 userOpHash, uint256 missingAccountFunds) returns(uint256 validationData)
func (_QuantumAuthAccount *QuantumAuthAccountTransactor) ValidateUserOp(opts *bind.TransactOpts, userOp PackedUserOperation, userOpHash [32]byte, missingAccountFunds *big.Int) (*types.Transaction, error) {
	return _QuantumAuthAccount.contract.Transact(opts, "validateUserOp", userOp, userOpHash, missingAccountFunds)
}

// ValidateUserOp is a paid mutator transaction binding the contract method 0x19822f7c.
//
// Solidity: function validateUserOp((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes) userOp, bytes32 userOpHash, uint256 missingAccountFunds) returns(uint256 validationData)
func (_QuantumAuthAccount *QuantumAuthAccountSession) ValidateUserOp(userOp PackedUserOperation, userOpHash [32]byte, missingAccountFunds *big.Int) (*types.Transaction, error) {
	return _QuantumAuthAccount.Contract.ValidateUserOp(&_QuantumAuthAccount.TransactOpts, userOp, userOpHash, missingAccountFunds)
}

// ValidateUserOp is a paid mutator transaction binding the contract method 0x19822f7c.
//
// Solidity: function validateUserOp((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes) userOp, bytes32 userOpHash, uint256 missingAccountFunds) returns(uint256 validationData)
func (_QuantumAuthAccount *QuantumAuthAccountTransactorSession) ValidateUserOp(userOp PackedUserOperation, userOpHash [32]byte, missingAccountFunds *big.Int) (*types.Transaction, error) {
	return _QuantumAuthAccount.Contract.ValidateUserOp(&_QuantumAuthAccount.TransactOpts, userOp, userOpHash, missingAccountFunds)
}

// Receive is a paid mutator transaction binding the contract receive function.
//
// Solidity: receive() payable returns()
func (_QuantumAuthAccount *QuantumAuthAccountTransactor) Receive(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _QuantumAuthAccount.contract.RawTransact(opts, nil) // calldata is disallowed for receive function
}

// Receive is a paid mutator transaction binding the contract receive function.
//
// Solidity: receive() payable returns()
func (_QuantumAuthAccount *QuantumAuthAccountSession) Receive() (*types.Transaction, error) {
	return _QuantumAuthAccount.Contract.Receive(&_QuantumAuthAccount.TransactOpts)
}

// Receive is a paid mutator transaction binding the contract receive function.
//
// Solidity: receive() payable returns()
func (_QuantumAuthAccount *QuantumAuthAccountTransactorSession) Receive() (*types.Transaction, error) {
	return _QuantumAuthAccount.Contract.Receive(&_QuantumAuthAccount.TransactOpts)
}
