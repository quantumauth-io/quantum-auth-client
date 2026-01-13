// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package qaerc20

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

// QAERC20MetaData contains all meta data concerning the QAERC20 contract.
var QAERC20MetaData = &bind.MetaData{
	ABI: "[{\"type\":\"constructor\",\"inputs\":[{\"name\":\"name_\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"symbol_\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"decimals_\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"owner_\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"allowance\",\"inputs\":[{\"name\":\"owner\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"spender\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"approve\",\"inputs\":[{\"name\":\"spender\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"value\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"balanceOf\",\"inputs\":[{\"name\":\"account\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"burn\",\"inputs\":[{\"name\":\"amount\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"burnFrom\",\"inputs\":[{\"name\":\"from\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"amount\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"decimals\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"uint8\",\"internalType\":\"uint8\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"mint\",\"inputs\":[{\"name\":\"to\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"amount\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"name\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"owner\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"renounceOwnership\",\"inputs\":[],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"symbol\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"totalSupply\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"transfer\",\"inputs\":[{\"name\":\"to\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"value\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"transferFrom\",\"inputs\":[{\"name\":\"from\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"to\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"value\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"transferOwnership\",\"inputs\":[{\"name\":\"newOwner\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"event\",\"name\":\"Approval\",\"inputs\":[{\"name\":\"owner\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"spender\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"value\",\"type\":\"uint256\",\"indexed\":false,\"internalType\":\"uint256\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"OwnershipTransferred\",\"inputs\":[{\"name\":\"previousOwner\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"newOwner\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"Transfer\",\"inputs\":[{\"name\":\"from\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"to\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"value\",\"type\":\"uint256\",\"indexed\":false,\"internalType\":\"uint256\"}],\"anonymous\":false},{\"type\":\"error\",\"name\":\"ERC20InsufficientAllowance\",\"inputs\":[{\"name\":\"spender\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"allowance\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"needed\",\"type\":\"uint256\",\"internalType\":\"uint256\"}]},{\"type\":\"error\",\"name\":\"ERC20InsufficientBalance\",\"inputs\":[{\"name\":\"sender\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"balance\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"needed\",\"type\":\"uint256\",\"internalType\":\"uint256\"}]},{\"type\":\"error\",\"name\":\"ERC20InvalidApprover\",\"inputs\":[{\"name\":\"approver\",\"type\":\"address\",\"internalType\":\"address\"}]},{\"type\":\"error\",\"name\":\"ERC20InvalidReceiver\",\"inputs\":[{\"name\":\"receiver\",\"type\":\"address\",\"internalType\":\"address\"}]},{\"type\":\"error\",\"name\":\"ERC20InvalidSender\",\"inputs\":[{\"name\":\"sender\",\"type\":\"address\",\"internalType\":\"address\"}]},{\"type\":\"error\",\"name\":\"ERC20InvalidSpender\",\"inputs\":[{\"name\":\"spender\",\"type\":\"address\",\"internalType\":\"address\"}]},{\"type\":\"error\",\"name\":\"OwnableInvalidOwner\",\"inputs\":[{\"name\":\"owner\",\"type\":\"address\",\"internalType\":\"address\"}]},{\"type\":\"error\",\"name\":\"OwnableUnauthorizedAccount\",\"inputs\":[{\"name\":\"account\",\"type\":\"address\",\"internalType\":\"address\"}]}]",
	Bin: "0x60a0604052346103a75761127b80380380610019816103ab565b9283398101906080818303126103a75780516001600160401b0381116103a757826100459183016103d0565b602082015190926001600160401b0382116103a7576100659183016103d0565b9060408101519060ff821682036103a757606001516001600160a01b03811691908290036103a75783516001600160401b0381116102b857600354600181811c9116801561039d575b602082101461029a57601f811161033a575b50602094601f82116001146102d7579481929394955f926102cc575b50508160011b915f199060031b1c1916176003555b82516001600160401b0381116102b857600454600181811c911680156102ae575b602082101461029a57601f8111610237575b506020601f82116001146101d457819293945f926101c9575b50508160011b915f199060031b1c1916176004555b81156101b657600580546001600160a01b03198116841790915560405192906001600160a01b03167f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e05f80a3608052610e59908161042282396080518161079b0152f35b631e4fbdf760e01b5f525f60045260245ffd5b015190505f8061013d565b601f1982169060045f52805f20915f5b81811061021f57509583600195969710610207575b505050811b01600455610152565b01515f1960f88460031b161c191690555f80806101f9565b9192602060018192868b0151815501940192016101e4565b60045f527f8a35acfbc15ff81a39ae7d344fd709f28e8600b4aa8c65c6b64bfe7fe36bd19b601f830160051c81019160208410610290575b601f0160051c01905b8181106102855750610124565b5f8155600101610278565b909150819061026f565b634e487b7160e01b5f52602260045260245ffd5b90607f1690610112565b634e487b7160e01b5f52604160045260245ffd5b015190505f806100dc565b601f1982169560035f52805f20915f5b8881106103225750836001959697981061030a575b505050811b016003556100f1565b01515f1960f88460031b161c191690555f80806102fc565b919260206001819286850151815501940192016102e7565b60035f527fc2575a0e9e593c00f959f8c92f12db2869c3395a3b0502d05e2516446f71f85b601f830160051c81019160208410610393575b601f0160051c01905b81811061038857506100c0565b5f815560010161037b565b9091508190610372565b90607f16906100ae565b5f80fd5b6040519190601f01601f191682016001600160401b038111838210176102b857604052565b81601f820112156103a7578051906001600160401b0382116102b8576103ff601f8301601f19166020016103ab565b92828452602083830101116103a757815f9260208093018386015e830101529056fe6080806040526004361015610012575f80fd5b5f3560e01c90816306fdde031461095557508063095ea7b31461085057806318160ddd1461081557806323b872dd146107bf578063313ce5671461076457806340c10f191461065b57806342966c681461062057806370a08231146105be578063715018a61461052257806379cc6790146104d25780638da5cb5b1461048157806395d89b411461028e578063a9059cbb1461023f578063dd62ed3e146101b35763f2fde38b146100c1575f80fd5b346101af5760207ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126101af5773ffffffffffffffffffffffffffffffffffffffff61010d610ace565b610115610d2c565b1680156101835773ffffffffffffffffffffffffffffffffffffffff600554827fffffffffffffffffffffffff0000000000000000000000000000000000000000821617600555167f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e05f80a3005b7f1e4fbdf7000000000000000000000000000000000000000000000000000000005f525f60045260245ffd5b5f80fd5b346101af5760407ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126101af576101ea610ace565b73ffffffffffffffffffffffffffffffffffffffff610207610af1565b91165f52600160205273ffffffffffffffffffffffffffffffffffffffff60405f2091165f52602052602060405f2054604051908152f35b346101af5760407ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126101af57610283610279610ace565b6024359033610c36565b602060405160018152f35b346101af575f7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126101af576040515f600454908160011c60018316928315610477575b60208210841461044a5781855284939081156103ea5750600114610370575b5003601f017fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe01681019067ffffffffffffffff8211818310176103435761033f82918260405282610a86565b0390f35b7f4e487b71000000000000000000000000000000000000000000000000000000005f52604160045260245ffd5b60045f90815291507f8a35acfbc15ff81a39ae7d344fd709f28e8600b4aa8c65c6b64bfe7fe36bd19b5b8183106103ce57505081016020017fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe06102f3565b602091935080600191548385880101520191019091839261039a565b7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff001660208581019190915291151560051b840190910191507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe090506102f3565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52602260045260245ffd5b90607f16906102d4565b346101af575f7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126101af57602073ffffffffffffffffffffffffffffffffffffffff60055416604051908152f35b346101af5760407ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126101af5761052061050c610ace565b6024359061051b823383610b14565b610d79565b005b346101af575f7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126101af57610558610d2c565b5f73ffffffffffffffffffffffffffffffffffffffff6005547fffffffffffffffffffffffff00000000000000000000000000000000000000008116600555167f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e08280a3005b346101af5760207ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126101af5773ffffffffffffffffffffffffffffffffffffffff61060a610ace565b165f525f602052602060405f2054604051908152f35b346101af5760207ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126101af5761052060043533610d79565b346101af5760407ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126101af57610692610ace565b73ffffffffffffffffffffffffffffffffffffffff602435916106b3610d2c565b16908115610738576002549080820180921161070b5760207fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef915f9360025584845283825260408420818154019055604051908152a3005b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601160045260245ffd5b7fec442f05000000000000000000000000000000000000000000000000000000005f525f60045260245ffd5b346101af575f7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126101af57602060405160ff7f0000000000000000000000000000000000000000000000000000000000000000168152f35b346101af5760607ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126101af576102836107f9610ace565b610801610af1565b60443591610810833383610b14565b610c36565b346101af575f7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126101af576020600254604051908152f35b346101af5760407ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126101af57610887610ace565b6024359033156109295773ffffffffffffffffffffffffffffffffffffffff169081156108fd57335f52600160205260405f20825f526020528060405f20556040519081527f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b92560203392a3602060405160018152f35b7f94280d62000000000000000000000000000000000000000000000000000000005f525f60045260245ffd5b7fe602df05000000000000000000000000000000000000000000000000000000005f525f60045260245ffd5b346101af575f7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc3601126101af575f600354908160011c60018316928315610a7c575b60208210841461044a5781855284939081156103ea5750600114610a02575003601f017fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe01681019067ffffffffffffffff8211818310176103435761033f82918260405282610a86565b60035f90815291507fc2575a0e9e593c00f959f8c92f12db2869c3395a3b0502d05e2516446f71f85b5b818310610a6057505081016020017fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe06102f3565b6020919350806001915483858801015201910190918392610a2c565b90607f1690610998565b7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0601f602060409481855280519182918282880152018686015e5f8582860101520116010190565b6004359073ffffffffffffffffffffffffffffffffffffffff821682036101af57565b6024359073ffffffffffffffffffffffffffffffffffffffff821682036101af57565b73ffffffffffffffffffffffffffffffffffffffff909291921691825f52600160205260405f2073ffffffffffffffffffffffffffffffffffffffff82165f5260205260405f2054927fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8410610b8b575b50505050565b828410610bec5780156109295773ffffffffffffffffffffffffffffffffffffffff8216156108fd575f52600160205273ffffffffffffffffffffffffffffffffffffffff60405f2091165f5260205260405f20910390555f808080610b85565b5073ffffffffffffffffffffffffffffffffffffffff83917ffb8f41b2000000000000000000000000000000000000000000000000000000005f521660045260245260445260645ffd5b73ffffffffffffffffffffffffffffffffffffffff16908115610d005773ffffffffffffffffffffffffffffffffffffffff1691821561073857815f525f60205260405f2054818110610cce57817fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef92602092855f525f84520360405f2055845f525f825260405f20818154019055604051908152a3565b827fe450d38c000000000000000000000000000000000000000000000000000000005f5260045260245260445260645ffd5b7f96c6fd1e000000000000000000000000000000000000000000000000000000005f525f60045260245ffd5b73ffffffffffffffffffffffffffffffffffffffff600554163303610d4d57565b7f118cdaa7000000000000000000000000000000000000000000000000000000005f523360045260245ffd5b90919073ffffffffffffffffffffffffffffffffffffffff168015610d0057805f525f60205260405f2054838110610df0576020845f94957fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef938587528684520360408620558060025403600255604051908152a3565b91507fe450d38c000000000000000000000000000000000000000000000000000000005f5260045260245260445260645ffdfea2646970667358221220990e8825356906e6b951854e4be873ed917cbcd017ba43387bc2e27d8c75e05564736f6c634300081c0033",
}

// QAERC20ABI is the input ABI used to generate the binding from.
// Deprecated: Use QAERC20MetaData.ABI instead.
var QAERC20ABI = QAERC20MetaData.ABI

// QAERC20Bin is the compiled bytecode used for deploying new contracts.
// Deprecated: Use QAERC20MetaData.Bin instead.
var QAERC20Bin = QAERC20MetaData.Bin

// DeployQAERC20 deploys a new Ethereum contract, binding an instance of QAERC20 to it.
func DeployQAERC20(auth *bind.TransactOpts, backend bind.ContractBackend, name_ string, symbol_ string, decimals_ uint8, owner_ common.Address) (common.Address, *types.Transaction, *QAERC20, error) {
	parsed, err := QAERC20MetaData.GetAbi()
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	if parsed == nil {
		return common.Address{}, nil, nil, errors.New("GetABI returned nil")
	}

	address, tx, contract, err := bind.DeployContract(auth, *parsed, common.FromHex(QAERC20Bin), backend, name_, symbol_, decimals_, owner_)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &QAERC20{QAERC20Caller: QAERC20Caller{contract: contract}, QAERC20Transactor: QAERC20Transactor{contract: contract}, QAERC20Filterer: QAERC20Filterer{contract: contract}}, nil
}

// QAERC20 is an auto generated Go binding around an Ethereum contract.
type QAERC20 struct {
	QAERC20Caller     // Read-only binding to the contract
	QAERC20Transactor // Write-only binding to the contract
	QAERC20Filterer   // Log filterer for contract events
}

// QAERC20Caller is an auto generated read-only Go binding around an Ethereum contract.
type QAERC20Caller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// QAERC20Transactor is an auto generated write-only Go binding around an Ethereum contract.
type QAERC20Transactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// QAERC20Filterer is an auto generated log filtering Go binding around an Ethereum contract events.
type QAERC20Filterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// QAERC20Session is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type QAERC20Session struct {
	Contract     *QAERC20          // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// QAERC20CallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type QAERC20CallerSession struct {
	Contract *QAERC20Caller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts  // Call options to use throughout this session
}

// QAERC20TransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type QAERC20TransactorSession struct {
	Contract     *QAERC20Transactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts  // Transaction auth options to use throughout this session
}

// QAERC20Raw is an auto generated low-level Go binding around an Ethereum contract.
type QAERC20Raw struct {
	Contract *QAERC20 // Generic contract binding to access the raw methods on
}

// QAERC20CallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type QAERC20CallerRaw struct {
	Contract *QAERC20Caller // Generic read-only contract binding to access the raw methods on
}

// QAERC20TransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type QAERC20TransactorRaw struct {
	Contract *QAERC20Transactor // Generic write-only contract binding to access the raw methods on
}

// NewQAERC20 creates a new instance of QAERC20, bound to a specific deployed contract.
func NewQAERC20(address common.Address, backend bind.ContractBackend) (*QAERC20, error) {
	contract, err := bindQAERC20(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &QAERC20{QAERC20Caller: QAERC20Caller{contract: contract}, QAERC20Transactor: QAERC20Transactor{contract: contract}, QAERC20Filterer: QAERC20Filterer{contract: contract}}, nil
}

// NewQAERC20Caller creates a new read-only instance of QAERC20, bound to a specific deployed contract.
func NewQAERC20Caller(address common.Address, caller bind.ContractCaller) (*QAERC20Caller, error) {
	contract, err := bindQAERC20(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &QAERC20Caller{contract: contract}, nil
}

// NewQAERC20Transactor creates a new write-only instance of QAERC20, bound to a specific deployed contract.
func NewQAERC20Transactor(address common.Address, transactor bind.ContractTransactor) (*QAERC20Transactor, error) {
	contract, err := bindQAERC20(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &QAERC20Transactor{contract: contract}, nil
}

// NewQAERC20Filterer creates a new log filterer instance of QAERC20, bound to a specific deployed contract.
func NewQAERC20Filterer(address common.Address, filterer bind.ContractFilterer) (*QAERC20Filterer, error) {
	contract, err := bindQAERC20(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &QAERC20Filterer{contract: contract}, nil
}

// bindQAERC20 binds a generic wrapper to an already deployed contract.
func bindQAERC20(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := QAERC20MetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_QAERC20 *QAERC20Raw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _QAERC20.Contract.QAERC20Caller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_QAERC20 *QAERC20Raw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _QAERC20.Contract.QAERC20Transactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_QAERC20 *QAERC20Raw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _QAERC20.Contract.QAERC20Transactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_QAERC20 *QAERC20CallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _QAERC20.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_QAERC20 *QAERC20TransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _QAERC20.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_QAERC20 *QAERC20TransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _QAERC20.Contract.contract.Transact(opts, method, params...)
}

// Allowance is a free data retrieval call binding the contract method 0xdd62ed3e.
//
// Solidity: function allowance(address owner, address spender) view returns(uint256)
func (_QAERC20 *QAERC20Caller) Allowance(opts *bind.CallOpts, owner common.Address, spender common.Address) (*big.Int, error) {
	var out []interface{}
	err := _QAERC20.contract.Call(opts, &out, "allowance", owner, spender)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// Allowance is a free data retrieval call binding the contract method 0xdd62ed3e.
//
// Solidity: function allowance(address owner, address spender) view returns(uint256)
func (_QAERC20 *QAERC20Session) Allowance(owner common.Address, spender common.Address) (*big.Int, error) {
	return _QAERC20.Contract.Allowance(&_QAERC20.CallOpts, owner, spender)
}

// Allowance is a free data retrieval call binding the contract method 0xdd62ed3e.
//
// Solidity: function allowance(address owner, address spender) view returns(uint256)
func (_QAERC20 *QAERC20CallerSession) Allowance(owner common.Address, spender common.Address) (*big.Int, error) {
	return _QAERC20.Contract.Allowance(&_QAERC20.CallOpts, owner, spender)
}

// BalanceOf is a free data retrieval call binding the contract method 0x70a08231.
//
// Solidity: function balanceOf(address account) view returns(uint256)
func (_QAERC20 *QAERC20Caller) BalanceOf(opts *bind.CallOpts, account common.Address) (*big.Int, error) {
	var out []interface{}
	err := _QAERC20.contract.Call(opts, &out, "balanceOf", account)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// BalanceOf is a free data retrieval call binding the contract method 0x70a08231.
//
// Solidity: function balanceOf(address account) view returns(uint256)
func (_QAERC20 *QAERC20Session) BalanceOf(account common.Address) (*big.Int, error) {
	return _QAERC20.Contract.BalanceOf(&_QAERC20.CallOpts, account)
}

// BalanceOf is a free data retrieval call binding the contract method 0x70a08231.
//
// Solidity: function balanceOf(address account) view returns(uint256)
func (_QAERC20 *QAERC20CallerSession) BalanceOf(account common.Address) (*big.Int, error) {
	return _QAERC20.Contract.BalanceOf(&_QAERC20.CallOpts, account)
}

// Decimals is a free data retrieval call binding the contract method 0x313ce567.
//
// Solidity: function decimals() view returns(uint8)
func (_QAERC20 *QAERC20Caller) Decimals(opts *bind.CallOpts) (uint8, error) {
	var out []interface{}
	err := _QAERC20.contract.Call(opts, &out, "decimals")

	if err != nil {
		return *new(uint8), err
	}

	out0 := *abi.ConvertType(out[0], new(uint8)).(*uint8)

	return out0, err

}

// Decimals is a free data retrieval call binding the contract method 0x313ce567.
//
// Solidity: function decimals() view returns(uint8)
func (_QAERC20 *QAERC20Session) Decimals() (uint8, error) {
	return _QAERC20.Contract.Decimals(&_QAERC20.CallOpts)
}

// Decimals is a free data retrieval call binding the contract method 0x313ce567.
//
// Solidity: function decimals() view returns(uint8)
func (_QAERC20 *QAERC20CallerSession) Decimals() (uint8, error) {
	return _QAERC20.Contract.Decimals(&_QAERC20.CallOpts)
}

// Name is a free data retrieval call binding the contract method 0x06fdde03.
//
// Solidity: function name() view returns(string)
func (_QAERC20 *QAERC20Caller) Name(opts *bind.CallOpts) (string, error) {
	var out []interface{}
	err := _QAERC20.contract.Call(opts, &out, "name")

	if err != nil {
		return *new(string), err
	}

	out0 := *abi.ConvertType(out[0], new(string)).(*string)

	return out0, err

}

// Name is a free data retrieval call binding the contract method 0x06fdde03.
//
// Solidity: function name() view returns(string)
func (_QAERC20 *QAERC20Session) Name() (string, error) {
	return _QAERC20.Contract.Name(&_QAERC20.CallOpts)
}

// Name is a free data retrieval call binding the contract method 0x06fdde03.
//
// Solidity: function name() view returns(string)
func (_QAERC20 *QAERC20CallerSession) Name() (string, error) {
	return _QAERC20.Contract.Name(&_QAERC20.CallOpts)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_QAERC20 *QAERC20Caller) Owner(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _QAERC20.contract.Call(opts, &out, "owner")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_QAERC20 *QAERC20Session) Owner() (common.Address, error) {
	return _QAERC20.Contract.Owner(&_QAERC20.CallOpts)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_QAERC20 *QAERC20CallerSession) Owner() (common.Address, error) {
	return _QAERC20.Contract.Owner(&_QAERC20.CallOpts)
}

// Symbol is a free data retrieval call binding the contract method 0x95d89b41.
//
// Solidity: function symbol() view returns(string)
func (_QAERC20 *QAERC20Caller) Symbol(opts *bind.CallOpts) (string, error) {
	var out []interface{}
	err := _QAERC20.contract.Call(opts, &out, "symbol")

	if err != nil {
		return *new(string), err
	}

	out0 := *abi.ConvertType(out[0], new(string)).(*string)

	return out0, err

}

// Symbol is a free data retrieval call binding the contract method 0x95d89b41.
//
// Solidity: function symbol() view returns(string)
func (_QAERC20 *QAERC20Session) Symbol() (string, error) {
	return _QAERC20.Contract.Symbol(&_QAERC20.CallOpts)
}

// Symbol is a free data retrieval call binding the contract method 0x95d89b41.
//
// Solidity: function symbol() view returns(string)
func (_QAERC20 *QAERC20CallerSession) Symbol() (string, error) {
	return _QAERC20.Contract.Symbol(&_QAERC20.CallOpts)
}

// TotalSupply is a free data retrieval call binding the contract method 0x18160ddd.
//
// Solidity: function totalSupply() view returns(uint256)
func (_QAERC20 *QAERC20Caller) TotalSupply(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _QAERC20.contract.Call(opts, &out, "totalSupply")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// TotalSupply is a free data retrieval call binding the contract method 0x18160ddd.
//
// Solidity: function totalSupply() view returns(uint256)
func (_QAERC20 *QAERC20Session) TotalSupply() (*big.Int, error) {
	return _QAERC20.Contract.TotalSupply(&_QAERC20.CallOpts)
}

// TotalSupply is a free data retrieval call binding the contract method 0x18160ddd.
//
// Solidity: function totalSupply() view returns(uint256)
func (_QAERC20 *QAERC20CallerSession) TotalSupply() (*big.Int, error) {
	return _QAERC20.Contract.TotalSupply(&_QAERC20.CallOpts)
}

// Approve is a paid mutator transaction binding the contract method 0x095ea7b3.
//
// Solidity: function approve(address spender, uint256 value) returns(bool)
func (_QAERC20 *QAERC20Transactor) Approve(opts *bind.TransactOpts, spender common.Address, value *big.Int) (*types.Transaction, error) {
	return _QAERC20.contract.Transact(opts, "approve", spender, value)
}

// Approve is a paid mutator transaction binding the contract method 0x095ea7b3.
//
// Solidity: function approve(address spender, uint256 value) returns(bool)
func (_QAERC20 *QAERC20Session) Approve(spender common.Address, value *big.Int) (*types.Transaction, error) {
	return _QAERC20.Contract.Approve(&_QAERC20.TransactOpts, spender, value)
}

// Approve is a paid mutator transaction binding the contract method 0x095ea7b3.
//
// Solidity: function approve(address spender, uint256 value) returns(bool)
func (_QAERC20 *QAERC20TransactorSession) Approve(spender common.Address, value *big.Int) (*types.Transaction, error) {
	return _QAERC20.Contract.Approve(&_QAERC20.TransactOpts, spender, value)
}

// Burn is a paid mutator transaction binding the contract method 0x42966c68.
//
// Solidity: function burn(uint256 amount) returns()
func (_QAERC20 *QAERC20Transactor) Burn(opts *bind.TransactOpts, amount *big.Int) (*types.Transaction, error) {
	return _QAERC20.contract.Transact(opts, "burn", amount)
}

// Burn is a paid mutator transaction binding the contract method 0x42966c68.
//
// Solidity: function burn(uint256 amount) returns()
func (_QAERC20 *QAERC20Session) Burn(amount *big.Int) (*types.Transaction, error) {
	return _QAERC20.Contract.Burn(&_QAERC20.TransactOpts, amount)
}

// Burn is a paid mutator transaction binding the contract method 0x42966c68.
//
// Solidity: function burn(uint256 amount) returns()
func (_QAERC20 *QAERC20TransactorSession) Burn(amount *big.Int) (*types.Transaction, error) {
	return _QAERC20.Contract.Burn(&_QAERC20.TransactOpts, amount)
}

// BurnFrom is a paid mutator transaction binding the contract method 0x79cc6790.
//
// Solidity: function burnFrom(address from, uint256 amount) returns()
func (_QAERC20 *QAERC20Transactor) BurnFrom(opts *bind.TransactOpts, from common.Address, amount *big.Int) (*types.Transaction, error) {
	return _QAERC20.contract.Transact(opts, "burnFrom", from, amount)
}

// BurnFrom is a paid mutator transaction binding the contract method 0x79cc6790.
//
// Solidity: function burnFrom(address from, uint256 amount) returns()
func (_QAERC20 *QAERC20Session) BurnFrom(from common.Address, amount *big.Int) (*types.Transaction, error) {
	return _QAERC20.Contract.BurnFrom(&_QAERC20.TransactOpts, from, amount)
}

// BurnFrom is a paid mutator transaction binding the contract method 0x79cc6790.
//
// Solidity: function burnFrom(address from, uint256 amount) returns()
func (_QAERC20 *QAERC20TransactorSession) BurnFrom(from common.Address, amount *big.Int) (*types.Transaction, error) {
	return _QAERC20.Contract.BurnFrom(&_QAERC20.TransactOpts, from, amount)
}

// Mint is a paid mutator transaction binding the contract method 0x40c10f19.
//
// Solidity: function mint(address to, uint256 amount) returns()
func (_QAERC20 *QAERC20Transactor) Mint(opts *bind.TransactOpts, to common.Address, amount *big.Int) (*types.Transaction, error) {
	return _QAERC20.contract.Transact(opts, "mint", to, amount)
}

// Mint is a paid mutator transaction binding the contract method 0x40c10f19.
//
// Solidity: function mint(address to, uint256 amount) returns()
func (_QAERC20 *QAERC20Session) Mint(to common.Address, amount *big.Int) (*types.Transaction, error) {
	return _QAERC20.Contract.Mint(&_QAERC20.TransactOpts, to, amount)
}

// Mint is a paid mutator transaction binding the contract method 0x40c10f19.
//
// Solidity: function mint(address to, uint256 amount) returns()
func (_QAERC20 *QAERC20TransactorSession) Mint(to common.Address, amount *big.Int) (*types.Transaction, error) {
	return _QAERC20.Contract.Mint(&_QAERC20.TransactOpts, to, amount)
}

// RenounceOwnership is a paid mutator transaction binding the contract method 0x715018a6.
//
// Solidity: function renounceOwnership() returns()
func (_QAERC20 *QAERC20Transactor) RenounceOwnership(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _QAERC20.contract.Transact(opts, "renounceOwnership")
}

// RenounceOwnership is a paid mutator transaction binding the contract method 0x715018a6.
//
// Solidity: function renounceOwnership() returns()
func (_QAERC20 *QAERC20Session) RenounceOwnership() (*types.Transaction, error) {
	return _QAERC20.Contract.RenounceOwnership(&_QAERC20.TransactOpts)
}

// RenounceOwnership is a paid mutator transaction binding the contract method 0x715018a6.
//
// Solidity: function renounceOwnership() returns()
func (_QAERC20 *QAERC20TransactorSession) RenounceOwnership() (*types.Transaction, error) {
	return _QAERC20.Contract.RenounceOwnership(&_QAERC20.TransactOpts)
}

// Transfer is a paid mutator transaction binding the contract method 0xa9059cbb.
//
// Solidity: function transfer(address to, uint256 value) returns(bool)
func (_QAERC20 *QAERC20Transactor) Transfer(opts *bind.TransactOpts, to common.Address, value *big.Int) (*types.Transaction, error) {
	return _QAERC20.contract.Transact(opts, "transfer", to, value)
}

// Transfer is a paid mutator transaction binding the contract method 0xa9059cbb.
//
// Solidity: function transfer(address to, uint256 value) returns(bool)
func (_QAERC20 *QAERC20Session) Transfer(to common.Address, value *big.Int) (*types.Transaction, error) {
	return _QAERC20.Contract.Transfer(&_QAERC20.TransactOpts, to, value)
}

// Transfer is a paid mutator transaction binding the contract method 0xa9059cbb.
//
// Solidity: function transfer(address to, uint256 value) returns(bool)
func (_QAERC20 *QAERC20TransactorSession) Transfer(to common.Address, value *big.Int) (*types.Transaction, error) {
	return _QAERC20.Contract.Transfer(&_QAERC20.TransactOpts, to, value)
}

// TransferFrom is a paid mutator transaction binding the contract method 0x23b872dd.
//
// Solidity: function transferFrom(address from, address to, uint256 value) returns(bool)
func (_QAERC20 *QAERC20Transactor) TransferFrom(opts *bind.TransactOpts, from common.Address, to common.Address, value *big.Int) (*types.Transaction, error) {
	return _QAERC20.contract.Transact(opts, "transferFrom", from, to, value)
}

// TransferFrom is a paid mutator transaction binding the contract method 0x23b872dd.
//
// Solidity: function transferFrom(address from, address to, uint256 value) returns(bool)
func (_QAERC20 *QAERC20Session) TransferFrom(from common.Address, to common.Address, value *big.Int) (*types.Transaction, error) {
	return _QAERC20.Contract.TransferFrom(&_QAERC20.TransactOpts, from, to, value)
}

// TransferFrom is a paid mutator transaction binding the contract method 0x23b872dd.
//
// Solidity: function transferFrom(address from, address to, uint256 value) returns(bool)
func (_QAERC20 *QAERC20TransactorSession) TransferFrom(from common.Address, to common.Address, value *big.Int) (*types.Transaction, error) {
	return _QAERC20.Contract.TransferFrom(&_QAERC20.TransactOpts, from, to, value)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_QAERC20 *QAERC20Transactor) TransferOwnership(opts *bind.TransactOpts, newOwner common.Address) (*types.Transaction, error) {
	return _QAERC20.contract.Transact(opts, "transferOwnership", newOwner)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_QAERC20 *QAERC20Session) TransferOwnership(newOwner common.Address) (*types.Transaction, error) {
	return _QAERC20.Contract.TransferOwnership(&_QAERC20.TransactOpts, newOwner)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_QAERC20 *QAERC20TransactorSession) TransferOwnership(newOwner common.Address) (*types.Transaction, error) {
	return _QAERC20.Contract.TransferOwnership(&_QAERC20.TransactOpts, newOwner)
}

// QAERC20ApprovalIterator is returned from FilterApproval and is used to iterate over the raw logs and unpacked data for Approval events raised by the QAERC20 contract.
type QAERC20ApprovalIterator struct {
	Event *QAERC20Approval // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *QAERC20ApprovalIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(QAERC20Approval)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(QAERC20Approval)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *QAERC20ApprovalIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *QAERC20ApprovalIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// QAERC20Approval represents a Approval event raised by the QAERC20 contract.
type QAERC20Approval struct {
	Owner   common.Address
	Spender common.Address
	Value   *big.Int
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterApproval is a free log retrieval operation binding the contract event 0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925.
//
// Solidity: event Approval(address indexed owner, address indexed spender, uint256 value)
func (_QAERC20 *QAERC20Filterer) FilterApproval(opts *bind.FilterOpts, owner []common.Address, spender []common.Address) (*QAERC20ApprovalIterator, error) {

	var ownerRule []interface{}
	for _, ownerItem := range owner {
		ownerRule = append(ownerRule, ownerItem)
	}
	var spenderRule []interface{}
	for _, spenderItem := range spender {
		spenderRule = append(spenderRule, spenderItem)
	}

	logs, sub, err := _QAERC20.contract.FilterLogs(opts, "Approval", ownerRule, spenderRule)
	if err != nil {
		return nil, err
	}
	return &QAERC20ApprovalIterator{contract: _QAERC20.contract, event: "Approval", logs: logs, sub: sub}, nil
}

// WatchApproval is a free log subscription operation binding the contract event 0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925.
//
// Solidity: event Approval(address indexed owner, address indexed spender, uint256 value)
func (_QAERC20 *QAERC20Filterer) WatchApproval(opts *bind.WatchOpts, sink chan<- *QAERC20Approval, owner []common.Address, spender []common.Address) (event.Subscription, error) {

	var ownerRule []interface{}
	for _, ownerItem := range owner {
		ownerRule = append(ownerRule, ownerItem)
	}
	var spenderRule []interface{}
	for _, spenderItem := range spender {
		spenderRule = append(spenderRule, spenderItem)
	}

	logs, sub, err := _QAERC20.contract.WatchLogs(opts, "Approval", ownerRule, spenderRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(QAERC20Approval)
				if err := _QAERC20.contract.UnpackLog(event, "Approval", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseApproval is a log parse operation binding the contract event 0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925.
//
// Solidity: event Approval(address indexed owner, address indexed spender, uint256 value)
func (_QAERC20 *QAERC20Filterer) ParseApproval(log types.Log) (*QAERC20Approval, error) {
	event := new(QAERC20Approval)
	if err := _QAERC20.contract.UnpackLog(event, "Approval", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// QAERC20OwnershipTransferredIterator is returned from FilterOwnershipTransferred and is used to iterate over the raw logs and unpacked data for OwnershipTransferred events raised by the QAERC20 contract.
type QAERC20OwnershipTransferredIterator struct {
	Event *QAERC20OwnershipTransferred // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *QAERC20OwnershipTransferredIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(QAERC20OwnershipTransferred)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(QAERC20OwnershipTransferred)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *QAERC20OwnershipTransferredIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *QAERC20OwnershipTransferredIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// QAERC20OwnershipTransferred represents a OwnershipTransferred event raised by the QAERC20 contract.
type QAERC20OwnershipTransferred struct {
	PreviousOwner common.Address
	NewOwner      common.Address
	Raw           types.Log // Blockchain specific contextual infos
}

// FilterOwnershipTransferred is a free log retrieval operation binding the contract event 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0.
//
// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
func (_QAERC20 *QAERC20Filterer) FilterOwnershipTransferred(opts *bind.FilterOpts, previousOwner []common.Address, newOwner []common.Address) (*QAERC20OwnershipTransferredIterator, error) {

	var previousOwnerRule []interface{}
	for _, previousOwnerItem := range previousOwner {
		previousOwnerRule = append(previousOwnerRule, previousOwnerItem)
	}
	var newOwnerRule []interface{}
	for _, newOwnerItem := range newOwner {
		newOwnerRule = append(newOwnerRule, newOwnerItem)
	}

	logs, sub, err := _QAERC20.contract.FilterLogs(opts, "OwnershipTransferred", previousOwnerRule, newOwnerRule)
	if err != nil {
		return nil, err
	}
	return &QAERC20OwnershipTransferredIterator{contract: _QAERC20.contract, event: "OwnershipTransferred", logs: logs, sub: sub}, nil
}

// WatchOwnershipTransferred is a free log subscription operation binding the contract event 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0.
//
// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
func (_QAERC20 *QAERC20Filterer) WatchOwnershipTransferred(opts *bind.WatchOpts, sink chan<- *QAERC20OwnershipTransferred, previousOwner []common.Address, newOwner []common.Address) (event.Subscription, error) {

	var previousOwnerRule []interface{}
	for _, previousOwnerItem := range previousOwner {
		previousOwnerRule = append(previousOwnerRule, previousOwnerItem)
	}
	var newOwnerRule []interface{}
	for _, newOwnerItem := range newOwner {
		newOwnerRule = append(newOwnerRule, newOwnerItem)
	}

	logs, sub, err := _QAERC20.contract.WatchLogs(opts, "OwnershipTransferred", previousOwnerRule, newOwnerRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(QAERC20OwnershipTransferred)
				if err := _QAERC20.contract.UnpackLog(event, "OwnershipTransferred", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseOwnershipTransferred is a log parse operation binding the contract event 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0.
//
// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
func (_QAERC20 *QAERC20Filterer) ParseOwnershipTransferred(log types.Log) (*QAERC20OwnershipTransferred, error) {
	event := new(QAERC20OwnershipTransferred)
	if err := _QAERC20.contract.UnpackLog(event, "OwnershipTransferred", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// QAERC20TransferIterator is returned from FilterTransfer and is used to iterate over the raw logs and unpacked data for Transfer events raised by the QAERC20 contract.
type QAERC20TransferIterator struct {
	Event *QAERC20Transfer // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *QAERC20TransferIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(QAERC20Transfer)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(QAERC20Transfer)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *QAERC20TransferIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *QAERC20TransferIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// QAERC20Transfer represents a Transfer event raised by the QAERC20 contract.
type QAERC20Transfer struct {
	From  common.Address
	To    common.Address
	Value *big.Int
	Raw   types.Log // Blockchain specific contextual infos
}

// FilterTransfer is a free log retrieval operation binding the contract event 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef.
//
// Solidity: event Transfer(address indexed from, address indexed to, uint256 value)
func (_QAERC20 *QAERC20Filterer) FilterTransfer(opts *bind.FilterOpts, from []common.Address, to []common.Address) (*QAERC20TransferIterator, error) {

	var fromRule []interface{}
	for _, fromItem := range from {
		fromRule = append(fromRule, fromItem)
	}
	var toRule []interface{}
	for _, toItem := range to {
		toRule = append(toRule, toItem)
	}

	logs, sub, err := _QAERC20.contract.FilterLogs(opts, "Transfer", fromRule, toRule)
	if err != nil {
		return nil, err
	}
	return &QAERC20TransferIterator{contract: _QAERC20.contract, event: "Transfer", logs: logs, sub: sub}, nil
}

// WatchTransfer is a free log subscription operation binding the contract event 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef.
//
// Solidity: event Transfer(address indexed from, address indexed to, uint256 value)
func (_QAERC20 *QAERC20Filterer) WatchTransfer(opts *bind.WatchOpts, sink chan<- *QAERC20Transfer, from []common.Address, to []common.Address) (event.Subscription, error) {

	var fromRule []interface{}
	for _, fromItem := range from {
		fromRule = append(fromRule, fromItem)
	}
	var toRule []interface{}
	for _, toItem := range to {
		toRule = append(toRule, toItem)
	}

	logs, sub, err := _QAERC20.contract.WatchLogs(opts, "Transfer", fromRule, toRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(QAERC20Transfer)
				if err := _QAERC20.contract.UnpackLog(event, "Transfer", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseTransfer is a log parse operation binding the contract event 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef.
//
// Solidity: event Transfer(address indexed from, address indexed to, uint256 value)
func (_QAERC20 *QAERC20Filterer) ParseTransfer(log types.Log) (*QAERC20Transfer, error) {
	event := new(QAERC20Transfer)
	if err := _QAERC20.contract.UnpackLog(event, "Transfer", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}
