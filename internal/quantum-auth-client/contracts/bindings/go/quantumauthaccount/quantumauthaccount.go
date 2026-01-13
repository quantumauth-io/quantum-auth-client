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
	Bin: "0x6101203461016c57601f61106838819003918201601f19168301916001600160401b038311848410176101705780849260a09460405283398101031261016c5780516001600160a01b038116810361016c5761005d60208301610184565b61006960408401610184565b9060608401519260018060a01b0384169485850361016c5760800151946001600160a01b038316801590811561015a575b8115610147575b5061013857156101295760805260a05260c05260e05261010052604051610ecf9081610199823960805181818161030f015281816104c6015281816108670152610935015260a0518181816104250152610ab6015260c0518181816102a10152610adf015260e0518181816102330152610be301526101005181818161056e0152610ba20152f35b633c4ac85360e21b5f5260045ffd5b6303602a5960e51b5f5260045ffd5b6001600160a01b0386161490505f6100a1565b6001600160a01b03861615915061009a565b5f80fd5b634e487b7160e01b5f52604160045260245ffd5b51906001600160a01b038216820361016c5756fe6080604052600436101561001a575b3615610018575f80fd5b005b5f3560e01c806319822f7c146100a957806334fcd5be146100a45780637e8ee8141461009f578063a6b18bc01461009a578063b0d691fe14610095578063b61d27f614610090578063bfbbda751461008b578063d087d288146100865763d9260ecf0361000e57610539565b610449565b6103db565b610351565b6102c5565b610257565b6101e9565b61016e565b3461016a5760607ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc36011261016a5760043567ffffffffffffffff811161016a576101207ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc823603011261016a5761014e906101366044359161012a61091e565b60243590600401610a59565b9080610152575b506040519081529081906020820190565b0390f35b5f80808093335af1506101636108e4565b508261013d565b5f80fd5b3461016a5760207ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc36011261016a5760043567ffffffffffffffff811161016a573660238201121561016a57806004013567ffffffffffffffff811161016a573660248260051b8401011161016a5760246100189201610799565b3461016a575f7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc36011261016a57602060405173ffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000168152f35b3461016a575f7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc36011261016a57602060405173ffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000168152f35b3461016a575f7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc36011261016a57602060405173ffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000168152f35b73ffffffffffffffffffffffffffffffffffffffff81160361016a57565b3461016a5760607ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc36011261016a5760043561038c81610333565b6024356044359167ffffffffffffffff831161016a573660238401121561016a5782600401359167ffffffffffffffff831161016a57366024848601011161016a57602461001894019161084e565b3461016a575f7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc36011261016a57602060405173ffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000168152f35b3461016a575f7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc36011261016a576040517f35567e1a0000000000000000000000000000000000000000000000000000000081523060048201525f602482015260208160448173ffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000165afa8015610534575f90610500575b604051908152602090f35b506020813d60201161052c575b8161051a60209383610689565b8101031261016a5761014e90516104f5565b3d915061050d565b610913565b3461016a575f7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc36011261016a5760206040517f00000000000000000000000000000000000000000000000000000000000000008152f35b91908110156105d15760051b810135907fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa18136030182121561016a570190565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52603260045260245ffd5b3561060881610333565b90565b9035907fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe18136030182121561016a570180359067ffffffffffffffff821161016a5760200191813603831361016a57565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52604160045260245ffd5b90601f7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0910116810190811067ffffffffffffffff8211176106ca57604052565b61065c565b67ffffffffffffffff81116106ca57601f017fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe01660200190565b929192610715826106cf565b916107236040519384610689565b82948184528183011161016a578281602093845f960137010152565b907fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0601f602080948051918291828752018686015e5f8582860101520116010190565b60409061060893928152816020820152019061073f565b906107a261091e565b5f5b8181106107b057505050565b6107f66107f26107ec6107c4848688610591565b6107cd816105fe565b906107e1602082013591604081019061060b565b93905a943691610709565b91610c5a565b1590565b610802576001016107a4565b600182145f03610c8657610814610c6c565b9061084a6040519283927f5a15467500000000000000000000000000000000000000000000000000000000845260048401610782565b0390fd5b909273ffffffffffffffffffffffffffffffffffffffff7f00000000000000000000000000000000000000000000000000000000000000001633036108bc575f938493826040519384928337810185815203925af16108ab6108e4565b90156108b45750565b602081519101fd5b7fbd07c551000000000000000000000000000000000000000000000000000000005f5260045ffd5b3d1561090e573d906108f5826106cf565b916109036040519384610689565b82523d5f602084013e565b606090565b6040513d5f823e3d90fd5b73ffffffffffffffffffffffffffffffffffffffff7f00000000000000000000000000000000000000000000000000000000000000001680330361095f5750565b7ffe34a6d3000000000000000000000000000000000000000000000000000000005f52336004523060245260445260645ffd5b9080601f8301121561016a5781602061060893359101610709565b9060808282031261016a57813560ff8116810361016a5792602083013567ffffffffffffffff811161016a57826109e5918501610992565b92604081013567ffffffffffffffff811161016a5783610a06918301610992565b92606082013567ffffffffffffffff811161016a576106089201610992565b9081602091031261016a5751801515810361016a5790565b610608939260609282526020820152816040820152019061073f565b610b0491610a79610a7160ff9361010081019061060b565b8101906109ad565b929491610adc610ab3869893987f19457468657265756d205369676e6564204d6573736167653a0a3332000000005f52601c52603c5f2090565b917f00000000000000000000000000000000000000000000000000000000000000009083610c8e565b967f000000000000000000000000000000000000000000000000000000000000000091610c8e565b9316918215610b5b575050600114610b3e577fa0042b17000000000000000000000000000000000000000000000000000000005f5260045ffd5b81610b53575b5015610b4e575f90565b600190565b90505f610b44565b9290938092509115610c52575b5015610c4b57610bca9160209160405193849283927fde12c6400000000000000000000000000000000000000000000000000000000084527f000000000000000000000000000000000000000000000000000000000000000060048501610a3d565b038173ffffffffffffffffffffffffffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000165afa908115610534575f91610c1c575015610b4e575f90565b610c3e915060203d602011610c44575b610c368183610689565b810190610a25565b5f610b44565b503d610c2c565b5050600190565b90505f610b68565b925f939184939260208451940192f190565b3d604051906020818301016040528082525f602083013e90565b6108b4610c6c565b90805115610ccb57610cc492610cbb73ffffffffffffffffffffffffffffffffffffffff93928493610cd2565b90959195610d43565b1691161490565b5050505f90565b8151919060418303610d0257610cfb9250602082015190606060408401519301515f1a90610e0a565b9192909190565b50505f9160029190565b60041115610d1657565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52602160045260245ffd5b610d4c81610d0c565b80610d55575050565b610d5e81610d0c565b60018103610d8e577ff645eedf000000000000000000000000000000000000000000000000000000005f5260045ffd5b610d9781610d0c565b60028103610dcb57507ffce698f7000000000000000000000000000000000000000000000000000000005f5260045260245ffd5b80610dd7600392610d0c565b14610ddf5750565b7fd78bce0c000000000000000000000000000000000000000000000000000000005f5260045260245ffd5b91907f7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a08411610e8e579160209360809260ff5f9560405194855216868401526040830152606082015282805260015afa15610534575f5173ffffffffffffffffffffffffffffffffffffffff811615610e8457905f905f90565b505f906001905f90565b5050505f916003919056fea2646970667358221220230c193b47b9b1765975613b633590030674692b77a4c4344b5cb1605d63269f64736f6c634300081c0033",
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
