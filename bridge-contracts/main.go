package bridge_contracts

import (
	crossbellGateway "github.com/axieinfinity/bridge-core/bridge-contracts/generated_contracts/crossbellGateway"
	mainchainGateway "github.com/axieinfinity/bridge-core/bridge-contracts/generated_contracts/mainchainGateway"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
)

var ABIMaps = map[string]*bind.MetaData{
	"CrossbellGateway": crossbellGateway.CrossbellGatewayMetaData,
	"MainchainGateway": mainchainGateway.MainchainGatewayMetaData,
}
