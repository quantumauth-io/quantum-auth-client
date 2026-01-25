// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package tpmverifiersecp256k1

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

// TPMVerifierSecp256k1MetaData contains all meta data concerning the TPMVerifierSecp256k1 contract.
var TPMVerifierSecp256k1MetaData = &bind.MetaData{
	ABI: "[{\"type\":\"function\",\"name\":\"verify\",\"inputs\":[{\"name\":\"keyId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"messageHash\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"signature\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[{\"name\":\"ok\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"pure\"},{\"type\":\"error\",\"name\":\"BadSigLength\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"InvalidKeyId\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"InvalidSig\",\"inputs\":[]}]",
	Bin: "0x608080604052346015576101ab908161001a8239f35b5f80fdfe60806040526004361015610011575f80fd5b5f3560e01c63de12c64014610024575f80fd5b346100925760603660031901126100925760443567ffffffffffffffff811161009257366023820112156100925780600401359067ffffffffffffffff82116100925736602483830101116100925760209160246100889201602435600435610096565b6040519015158152f35b5f80fd5b6001600160a01b031692909190831561016d576041036101665760408101355f1a601b8110610140575b602092835f938360ff60809516601b8114159081610134575b5061012d575b60ff906040519485521682840152803560408401520135606082015282805260015afa15610122575f516001600160a01b0316801561011c571490565b50505f90565b6040513d5f823e3d90fd5b50846100df565b601c915014155f6100d9565b601b019060ff821161015257906100c0565b634e487b7160e01b5f52601160045260245ffd5b5050505f90565b505050505f9056fea26469706673582212209a71a53233c0390ce1b93a4f3013899c212cb8ea5c82f51fa548efbfd2e55cbb64736f6c634300081c0033",
}

// TPMVerifierSecp256k1ABI is the input ABI used to generate the binding from.
// Deprecated: Use TPMVerifierSecp256k1MetaData.ABI instead.
var TPMVerifierSecp256k1ABI = TPMVerifierSecp256k1MetaData.ABI

// TPMVerifierSecp256k1Bin is the compiled bytecode used for deploying new contracts.
// Deprecated: Use TPMVerifierSecp256k1MetaData.Bin instead.
var TPMVerifierSecp256k1Bin = TPMVerifierSecp256k1MetaData.Bin

// DeployTPMVerifierSecp256k1 deploys a new Ethereum contract, binding an instance of TPMVerifierSecp256k1 to it.
func DeployTPMVerifierSecp256k1(auth *bind.TransactOpts, backend bind.ContractBackend) (common.Address, *types.Transaction, *TPMVerifierSecp256k1, error) {
	parsed, err := TPMVerifierSecp256k1MetaData.GetAbi()
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	if parsed == nil {
		return common.Address{}, nil, nil, errors.New("GetABI returned nil")
	}

	address, tx, contract, err := bind.DeployContract(auth, *parsed, common.FromHex(TPMVerifierSecp256k1Bin), backend)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &TPMVerifierSecp256k1{TPMVerifierSecp256k1Caller: TPMVerifierSecp256k1Caller{contract: contract}, TPMVerifierSecp256k1Transactor: TPMVerifierSecp256k1Transactor{contract: contract}, TPMVerifierSecp256k1Filterer: TPMVerifierSecp256k1Filterer{contract: contract}}, nil
}

// TPMVerifierSecp256k1 is an auto generated Go binding around an Ethereum contract.
type TPMVerifierSecp256k1 struct {
	TPMVerifierSecp256k1Caller     // Read-only binding to the contract
	TPMVerifierSecp256k1Transactor // Write-only binding to the contract
	TPMVerifierSecp256k1Filterer   // Log filterer for contract events
}

// TPMVerifierSecp256k1Caller is an auto generated read-only Go binding around an Ethereum contract.
type TPMVerifierSecp256k1Caller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// TPMVerifierSecp256k1Transactor is an auto generated write-only Go binding around an Ethereum contract.
type TPMVerifierSecp256k1Transactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// TPMVerifierSecp256k1Filterer is an auto generated log filtering Go binding around an Ethereum contract events.
type TPMVerifierSecp256k1Filterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// TPMVerifierSecp256k1Session is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type TPMVerifierSecp256k1Session struct {
	Contract     *TPMVerifierSecp256k1 // Generic contract binding to set the session for
	CallOpts     bind.CallOpts         // Call options to use throughout this session
	TransactOpts bind.TransactOpts     // Transaction auth options to use throughout this session
}

// TPMVerifierSecp256k1CallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type TPMVerifierSecp256k1CallerSession struct {
	Contract *TPMVerifierSecp256k1Caller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts               // Call options to use throughout this session
}

// TPMVerifierSecp256k1TransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type TPMVerifierSecp256k1TransactorSession struct {
	Contract     *TPMVerifierSecp256k1Transactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts               // Transaction auth options to use throughout this session
}

// TPMVerifierSecp256k1Raw is an auto generated low-level Go binding around an Ethereum contract.
type TPMVerifierSecp256k1Raw struct {
	Contract *TPMVerifierSecp256k1 // Generic contract binding to access the raw methods on
}

// TPMVerifierSecp256k1CallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type TPMVerifierSecp256k1CallerRaw struct {
	Contract *TPMVerifierSecp256k1Caller // Generic read-only contract binding to access the raw methods on
}

// TPMVerifierSecp256k1TransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type TPMVerifierSecp256k1TransactorRaw struct {
	Contract *TPMVerifierSecp256k1Transactor // Generic write-only contract binding to access the raw methods on
}

// NewTPMVerifierSecp256k1 creates a new instance of TPMVerifierSecp256k1, bound to a specific deployed contract.
func NewTPMVerifierSecp256k1(address common.Address, backend bind.ContractBackend) (*TPMVerifierSecp256k1, error) {
	contract, err := bindTPMVerifierSecp256k1(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &TPMVerifierSecp256k1{TPMVerifierSecp256k1Caller: TPMVerifierSecp256k1Caller{contract: contract}, TPMVerifierSecp256k1Transactor: TPMVerifierSecp256k1Transactor{contract: contract}, TPMVerifierSecp256k1Filterer: TPMVerifierSecp256k1Filterer{contract: contract}}, nil
}

// NewTPMVerifierSecp256k1Caller creates a new read-only instance of TPMVerifierSecp256k1, bound to a specific deployed contract.
func NewTPMVerifierSecp256k1Caller(address common.Address, caller bind.ContractCaller) (*TPMVerifierSecp256k1Caller, error) {
	contract, err := bindTPMVerifierSecp256k1(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &TPMVerifierSecp256k1Caller{contract: contract}, nil
}

// NewTPMVerifierSecp256k1Transactor creates a new write-only instance of TPMVerifierSecp256k1, bound to a specific deployed contract.
func NewTPMVerifierSecp256k1Transactor(address common.Address, transactor bind.ContractTransactor) (*TPMVerifierSecp256k1Transactor, error) {
	contract, err := bindTPMVerifierSecp256k1(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &TPMVerifierSecp256k1Transactor{contract: contract}, nil
}

// NewTPMVerifierSecp256k1Filterer creates a new log filterer instance of TPMVerifierSecp256k1, bound to a specific deployed contract.
func NewTPMVerifierSecp256k1Filterer(address common.Address, filterer bind.ContractFilterer) (*TPMVerifierSecp256k1Filterer, error) {
	contract, err := bindTPMVerifierSecp256k1(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &TPMVerifierSecp256k1Filterer{contract: contract}, nil
}

// bindTPMVerifierSecp256k1 binds a generic wrapper to an already deployed contract.
func bindTPMVerifierSecp256k1(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := TPMVerifierSecp256k1MetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_TPMVerifierSecp256k1 *TPMVerifierSecp256k1Raw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _TPMVerifierSecp256k1.Contract.TPMVerifierSecp256k1Caller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_TPMVerifierSecp256k1 *TPMVerifierSecp256k1Raw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _TPMVerifierSecp256k1.Contract.TPMVerifierSecp256k1Transactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_TPMVerifierSecp256k1 *TPMVerifierSecp256k1Raw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _TPMVerifierSecp256k1.Contract.TPMVerifierSecp256k1Transactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_TPMVerifierSecp256k1 *TPMVerifierSecp256k1CallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _TPMVerifierSecp256k1.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_TPMVerifierSecp256k1 *TPMVerifierSecp256k1TransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _TPMVerifierSecp256k1.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_TPMVerifierSecp256k1 *TPMVerifierSecp256k1TransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _TPMVerifierSecp256k1.Contract.contract.Transact(opts, method, params...)
}

// Verify is a free data retrieval call binding the contract method 0xde12c640.
//
// Solidity: function verify(bytes32 keyId, bytes32 messageHash, bytes signature) pure returns(bool ok)
func (_TPMVerifierSecp256k1 *TPMVerifierSecp256k1Caller) Verify(opts *bind.CallOpts, keyId [32]byte, messageHash [32]byte, signature []byte) (bool, error) {
	var out []interface{}
	err := _TPMVerifierSecp256k1.contract.Call(opts, &out, "verify", keyId, messageHash, signature)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// Verify is a free data retrieval call binding the contract method 0xde12c640.
//
// Solidity: function verify(bytes32 keyId, bytes32 messageHash, bytes signature) pure returns(bool ok)
func (_TPMVerifierSecp256k1 *TPMVerifierSecp256k1Session) Verify(keyId [32]byte, messageHash [32]byte, signature []byte) (bool, error) {
	return _TPMVerifierSecp256k1.Contract.Verify(&_TPMVerifierSecp256k1.CallOpts, keyId, messageHash, signature)
}

// Verify is a free data retrieval call binding the contract method 0xde12c640.
//
// Solidity: function verify(bytes32 keyId, bytes32 messageHash, bytes signature) pure returns(bool ok)
func (_TPMVerifierSecp256k1 *TPMVerifierSecp256k1CallerSession) Verify(keyId [32]byte, messageHash [32]byte, signature []byte) (bool, error) {
	return _TPMVerifierSecp256k1.Contract.Verify(&_TPMVerifierSecp256k1.CallOpts, keyId, messageHash, signature)
}
