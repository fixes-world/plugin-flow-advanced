var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// src/actions/transfer.ts
import { z } from "zod";
import { inject as inject2, injectable as injectable2 } from "inversify";
import { elizaLogger as elizaLogger2 } from "@elizaos/core";
import { globalContainer as globalContainer2, property } from "@elizaos-plugins/plugin-di";
import { isCadenceIdentifier, isEVMAddress, isFlowAddress, BaseFlowInjectableAction } from "@elizaos-plugins/plugin-flow";

// src/helpers/formater.ts
var formater_exports = {};
__export(formater_exports, {
  formatAgentWalletInfo: () => formatAgentWalletInfo,
  formatFlowSpent: () => formatFlowSpent,
  formatTransationSent: () => formatTransationSent,
  formatWalletCreated: () => formatWalletCreated,
  formatWalletInfo: () => formatWalletInfo
});
import { formatAgentWalletInfo, formatWalletCreated, formatWalletInfo, formatFlowSpent, formatTransationSent } from "@elizaos-plugins/plugin-flow";

// src/services/acctPool.service.ts
import { injectable, inject } from "inversify";
import { elizaLogger, Service } from "@elizaos/core";
import { globalContainer } from "@elizaos-plugins/plugin-di";
import { FlowWalletService, queries as defaultQueries } from "@elizaos-plugins/plugin-flow";

// src/assets/cadence/scripts/get_flow_price.cdc?raw
var get_flow_price_default = 'import "AddressUtils"\nimport "PublicPriceOracle"\n\naccess(all)\nfun main(): UFix64 {\n    let network = AddressUtils.currentNetwork()\n    // reference: https://docs.increment.fi/protocols/decentralized-price-feed-oracle/deployment-addresses\n    var oracleAddress: Address? = nil\n    if network == "MAINNET" {\n        oracleAddress = Address.fromString("0x".concat("e385412159992e11"))\n    } else if network == "TESTNET" {\n        oracleAddress = Address.fromString("0x".concat("cbdb5a7b89c3c844"))\n    } else {\n        return 1.0\n    }\n    return PublicPriceOracle.getLatestPrice(oracleAddr: oracleAddress!)\n}\n';

// src/assets/cadence/scripts/get_stflow_price.cdc?raw
var get_stflow_price_default = 'import "AddressUtils"\nimport "PublicPriceOracle"\n\naccess(all)\nfun main(): UFix64 {\n    let network = AddressUtils.currentNetwork()\n    // reference: https://docs.increment.fi/protocols/decentralized-price-feed-oracle/deployment-addresses\n    var oracleAddress: Address? = nil\n    if network == "MAINNET" {\n        oracleAddress = Address.fromString("0x".concat("031dabc5ba1d2932"))\n    } else {\n        return 1.0\n    }\n    return PublicPriceOracle.getLatestPrice(oracleAddr: oracleAddress!)\n}\n';

// src/assets/cadence/scripts/get_flow_token_info.cdc?raw
var get_flow_token_info_default = `import "SwapFactory"
import "SwapConfig"
import "SwapInterfaces"
import "FlowToken"
import "FungibleToken"
import "FungibleTokenMetadataViews"

access(all)
fun main(
    address: Address,
    contractName: String
): TokenInfo? {
    if let ftContract = getAccount(address).contracts.borrow<&{FungibleToken}>(name: contractName) {
        let totalSupply = ftContract.resolveContractView(resourceType: nil, viewType: Type<FungibleTokenMetadataViews.TotalSupply>()) as! FungibleTokenMetadataViews.TotalSupply?
        if let tokenKey = getFTKey(address, contractName) {
            if let pairRef = borrowSwapPairRef(tokenKey) {
                let priceInFLOW = getSwapEstimatedAmountIn(tokenKey: tokenKey, pairRef: pairRef, amount: 1.0)
                return TokenInfo(
                    address: address,
                    contractName: contractName,
                    totalSupply: totalSupply?.supply ?? 0.0,
                    priceInFLOW: priceInFLOW
                )
            }
        }
        return TokenInfo(address: address, contractName: contractName, totalSupply: totalSupply?.supply ?? 0.0, priceInFLOW: 0.0)
    }
    return nil
}

access(all)
view fun getFTKey(_ address: Address, _ contractName: String): String? {
    let addrStr = address.toString()
    let addrStrNo0x = addrStr.slice(from: 2, upTo: addrStr.length)
    if let tokenVaultType = CompositeType("A.".concat(addrStrNo0x).concat(".").concat(contractName).concat(".Vault")) {
        return SwapConfig.SliceTokenTypeIdentifierFromVaultType(vaultTypeIdentifier: tokenVaultType.identifier)
    } else {
        return nil
    }
}

/// Borrow the swap pair reference
///
access(all)
view fun borrowSwapPairRef(_ token0Key: String): &{SwapInterfaces.PairPublic}? {
    let token1Key = SwapConfig.SliceTokenTypeIdentifierFromVaultType(vaultTypeIdentifier: Type<@FlowToken.Vault>().identifier)
    if let pairAddr = SwapFactory.getPairAddress(token0Key: token0Key, token1Key: token1Key) {
        // ensure the pair's contract exists
        let acct = getAccount(pairAddr)
        let allNames = acct.contracts.names
        if !allNames.contains("SwapPair") {
            return nil
        }

        // Now we can borrow the reference
        return acct
            .capabilities.get<&{SwapInterfaces.PairPublic}>(SwapConfig.PairPublicPath)
            .borrow()
    }
    return nil
}

/// Get the swap pair reserved info for the liquidity pool
/// 0 - Token0 reserve
/// 1 - Token1 reserve
/// 2 - LP token supply
///
access(all)
view fun getSwapPairReservedInfo(
    tokenKey: String,
    pairRef: &{SwapInterfaces.PairPublic},
): [UFix64; 3]? {
    let pairInfo = pairRef.getPairInfo()

    var reserve0 = 0.0
    var reserve1 = 0.0
    if tokenKey == (pairInfo[0] as! String) {
        reserve0 = (pairInfo[2] as! UFix64)
        reserve1 = (pairInfo[3] as! UFix64)
    } else {
        reserve0 = (pairInfo[3] as! UFix64)
        reserve1 = (pairInfo[2] as! UFix64)
    }
    let lpTokenSupply = pairInfo[5] as! UFix64
    return [reserve0, reserve1, lpTokenSupply]
}

/// Get the estimated swap amount by amount in
///
access(all)
view fun getSwapEstimatedAmountIn(
    tokenKey: String,
    pairRef: &{SwapInterfaces.PairPublic},
    amount: UFix64,
): UFix64 {
    let pairInfo = getSwapPairReservedInfo(tokenKey: tokenKey, pairRef: pairRef)
    if pairInfo == nil {
        return 0.0
    }
    let reserveToken = pairInfo![0]
    let reserveFlow = pairInfo![1]

    if reserveToken == 0.0 || reserveFlow == 0.0 {
        return 0.0
    }

    return SwapConfig.getAmountIn(amountOut: amount, reserveIn: reserveFlow, reserveOut: reserveToken)
}

access(all)
struct TokenInfo {
    access(all)
    let address: Address
    access(all)
    let contractName: String
    access(all)
    let totalSupply: UFix64
    access(all)
    let priceInFLOW: UFix64

    init(
        address: Address,
        contractName: String,
        totalSupply: UFix64,
        priceInFLOW: UFix64
    ) {
        self.address = address
        self.contractName = contractName
        self.totalSupply = totalSupply
        self.priceInFLOW = priceInFLOW
    }
}
`;

// src/assets/cadence/scripts/get_erc20_token_info.cdc?raw
var get_erc20_token_info_default = 'import "EVM"\nimport "FlowEVMBridgeUtils"\nimport "FlowEVMBridgeConfig"\n\naccess(all)\nfun main(\n    erc20Address: String,\n): TokenInfo? {\n    let ftAddr = EVM.addressFromString(erc20Address)\n    if FlowEVMBridgeUtils.isERC20(evmContractAddress: ftAddr) {\n        let name  = FlowEVMBridgeUtils.getName(evmContractAddress: ftAddr)\n        let symbol = FlowEVMBridgeUtils.getSymbol(evmContractAddress: ftAddr)\n        let decimals = FlowEVMBridgeUtils.getTokenDecimals(evmContractAddress: ftAddr)\n        let totalSupply = FlowEVMBridgeUtils.totalSupply(evmContractAddress: ftAddr)\n\n        // From https://kittypunch.gitbook.io/kittypunch-docs/litterbox/punchswap\n        let punchSwapFactoryAddress = EVM.addressFromString("29372c22459a4e373851798bFd6808e71EA34A71".toLower())\n        // let punchSwapRouterAddress = EVM.addressFromString("f45AFe28fd5519d5f8C1d4787a4D5f724C0eFa4d".toLower())\n        // From https://evm.flowscan.io/token/0xd3bF53DAC106A0290B0483EcBC89d40FcC961f3e\n        let wflowAddress = EVM.addressFromString("d3bF53DAC106A0290B0483EcBC89d40FcC961f3e".toLower())\n\n        let bridgeCOA = borrowCOA()\n\n        // result variables\n        var pairAddress: String? = nil\n        var reservedTokenInPair: UInt128 = 0\n        var reservedFlowInPair: UInt128 = 0\n\n        // Get the pair address\n        let pairAddressRes = bridgeCOA.call(\n            to: punchSwapFactoryAddress,\n            data: EVM.encodeABIWithSignature("getPair(address,address)", [wflowAddress, ftAddr]),\n            gasLimit: FlowEVMBridgeConfig.gasLimit,\n            value: EVM.Balance(attoflow: 0)\n        )\n        if pairAddressRes.status == EVM.Status.successful {\n            let decodedCallResult = EVM.decodeABI(types: [Type<EVM.EVMAddress>()], data: pairAddressRes.data)\n            if decodedCallResult.length == 1 {\n                let pairAddr = decodedCallResult[0] as! EVM.EVMAddress\n                pairAddress = "0x".concat(pairAddr.toString())\n\n                // Get the reserve of the pair\n                let reservesRes = bridgeCOA.call(\n                    to: pairAddr,\n                    data: EVM.encodeABIWithSignature("getReserves()", []),\n                    gasLimit: FlowEVMBridgeConfig.gasLimit,\n                    value: EVM.Balance(attoflow: 0)\n                )\n\n                // Get the token0 of the pair\n                let token0Res = bridgeCOA.call(\n                    to: pairAddr,\n                    data: EVM.encodeABIWithSignature("token0()", []),\n                    gasLimit: FlowEVMBridgeConfig.gasLimit,\n                    value: EVM.Balance(attoflow: 0)\n                )\n\n                if reservesRes.status == EVM.Status.successful && token0Res.status == EVM.Status.successful {\n                    let decodedReservesResult = EVM.decodeABI(types: [Type<UInt128>(), Type<UInt128>(), Type<UInt32>()], data: reservesRes.data)\n                    let decodedToken0Result = EVM.decodeABI(types: [Type<EVM.EVMAddress>()], data: token0Res.data)\n\n                    let token0Addr = decodedToken0Result[0] as! EVM.EVMAddress\n                    let isToken0FT = token0Addr.toString() == ftAddr.toString()\n                    reservedTokenInPair = isToken0FT ? decodedReservesResult[0] as! UInt128 : decodedReservesResult[1] as! UInt128\n                    reservedFlowInPair = isToken0FT ? decodedReservesResult[1] as! UInt128 : decodedReservesResult[0] as! UInt128\n                }\n            }\n        }\n\n        return TokenInfo(\n            address: erc20Address,\n            name: name,\n            symbol: symbol,\n            decimals: decimals,\n            totalSupply: totalSupply,\n            pairAddress: pairAddress,\n            reservedTokenInPair: reservedTokenInPair,\n            reservedFlowInPair: reservedFlowInPair\n        )\n    }\n    return nil\n}\n\n/// Enables other bridge contracts to orchestrate bridge operations from contract-owned COA\n///\naccess(all)\nview fun borrowCOA(): auth(EVM.Call) &EVM.CadenceOwnedAccount {\n    let vmBridgeAddr = Address.fromString("0x1e4aa0b87d10b141")!\n    return getAuthAccount<auth(BorrowValue) &Account>(vmBridgeAddr)\n        .storage.borrow<auth(EVM.Call) &EVM.CadenceOwnedAccount>(\n            from: FlowEVMBridgeConfig.coaStoragePath\n        ) ?? panic("Could not borrow COA reference")\n}\n\n\naccess(all)\nstruct TokenInfo {\n    access(all)\n    let address: String\n    access(all)\n    let name: String\n    access(all)\n    let symbol: String\n    access(all)\n    let decimals: UInt8\n    access(all)\n    let totalSupply: UInt256\n    access(all)\n    let pairAddress: String?\n    access(all)\n    let reservedTokenInPair: UInt128\n    access(all)\n    let reservedFlowInPair: UInt128\n\n    init(\n        address: String,\n        name: String,\n        symbol: String,\n        decimals: UInt8,\n        totalSupply: UInt256,\n        pairAddress: String?,\n        reservedTokenInPair: UInt128,\n        reservedFlowInPair: UInt128\n    ) {\n        self.address = address\n        self.name = name\n        self.symbol = symbol\n        self.decimals = decimals\n        self.totalSupply = totalSupply\n        self.pairAddress = pairAddress\n        self.reservedTokenInPair = reservedTokenInPair\n        self.reservedFlowInPair = reservedFlowInPair\n    }\n}\n';

// src/assets/cadence/scripts/account-pool/is_address_child_of_main.cdc?raw
var is_address_child_of_main_default = 'import "AccountsPool"\nimport "EVM"\n\n/// Check if the address belongs to the main account\n///\naccess(all) fun main(\n    mainAddr: Address,\n    address: Address,\n): Bool {\n    let acct = getAuthAccount<auth(Storage) &Account>(mainAddr)\n    if let pool = acct.storage\n        .borrow<auth(AccountsPool.Child) &AccountsPool.Pool>(from: AccountsPool.StoragePath) {\n        return AccountsPool.isAddressOwnedBy(mainAddr, checkAddress: address)\n    }\n    return false\n}\n';

// src/assets/cadence/scripts/account-pool/get_acct_info_from.cdc?raw
var get_acct_info_from_default = 'import "FungibleToken"\nimport "EVM"\nimport "AccountsPool"\n\n/// Returns the hex encoded address of the COA in the given Flow address\n///\naccess(all) fun main(\n    mainAddr: Address,\n    userId: String?,\n): AccountInfo? {\n    let acct = getAuthAccount<auth(Storage) &Account>(mainAddr)\n    var flowAddress: Address? = nil\n    if userId == nil {\n        flowAddress = mainAddr\n    } else if let pool = acct.storage\n        .borrow<auth(AccountsPool.Child) &AccountsPool.Pool>(from: AccountsPool.StoragePath) {\n        flowAddress = pool.getAddress(type: "eliza", userId!) ;\n    }\n\n    if flowAddress == nil {\n        return nil\n    }\n\n    var flowBalance: UFix64 = 0.0\n    if let flowVaultRef = getAccount(flowAddress!)\n        .capabilities.get<&{FungibleToken.Balance}>(/public/flowTokenBalance)\n        .borrow() {\n        flowBalance = flowVaultRef.balance\n    }\n\n    var coaAddress: String? = nil\n    var coaBalance: UFix64? = nil\n\n    if let address: EVM.EVMAddress = getAuthAccount<auth(BorrowValue) &Account>(flowAddress!)\n        .storage.borrow<&EVM.CadenceOwnedAccount>(from: /storage/evm)?.address() {\n        let bytes: [UInt8] = []\n        for byte in address.bytes {\n            bytes.append(byte)\n        }\n        coaAddress = String.encodeHex(bytes)\n        coaBalance = address.balance().inFLOW()\n    }\n    return AccountInfo(\n        flowAddress!,\n        flowBalance,\n        coaAddress,\n        coaBalance\n    )\n}\n\naccess(all) struct AccountInfo {\n    access(all) let address: Address\n    access(all) let balance: UFix64\n    access(all) let coaAddress: String?\n    access(all) let coaBalance: UFix64?\n\n    init(\n        _ address: Address,\n        _ balance: UFix64,\n        _ coaAddress: String?,\n        _ coaBalance: UFix64?\n    ) {\n        self.address = address\n        self.balance = balance\n        self.coaAddress = coaAddress\n        self.coaBalance = coaBalance\n    }\n}\n';

// src/assets/cadence/scripts/account-pool/get_acct_status.cdc?raw
var get_acct_status_default = 'import "FungibleToken"\nimport "EVM"\nimport "AccountsPool"\n\n/// Returns the hex encoded address of the COA in the given Flow address\n///\naccess(all) fun main(\n    mainAddr: Address,\n): AccountStatus? {\n    if let pool = AccountsPool.borrowAccountsPool(mainAddr) {\n        var flowBalance: UFix64 = 0.0\n        if let flowVaultRef = getAccount(mainAddr)\n            .capabilities.get<&{FungibleToken.Balance}>(/public/flowTokenBalance)\n            .borrow() {\n            flowBalance = flowVaultRef.balance\n        }\n\n        let childrenAmount = pool.getChildrenAmount(type: "eliza")\n        return AccountStatus(\n            mainAddr,\n            flowBalance,\n            childrenAmount\n        )\n    }\n    return nil\n}\n\naccess(all) struct AccountStatus {\n    access(all) let address: Address\n    access(all) let balance: UFix64\n    access(all) let childrenAmount: UInt64\n\n    init(\n        _ address: Address,\n        _ balance: UFix64,\n        _ childrenAmount: UInt64\n    ) {\n        self.address = address\n        self.balance = balance\n        self.childrenAmount = childrenAmount\n    }\n}\n';

// src/assets/cadence/scripts/token-list/is-token-registered.cdc?raw
var is_token_registered_default = 'import "TokenList"\n\naccess(all)\nfun main(\n    ftAddress: Address,\n    ftContractName: String,\n): Bool {\n    return TokenList.isFungibleTokenRegistered(ftAddress, ftContractName)\n}\n';

// src/assets/cadence/scripts/token-list/is-evm-asset-registered.cdc?raw
var is_evm_asset_registered_default = 'import "EVMTokenList"\n\naccess(all)\nfun main(\n    evmContractAddress: String,\n): Bool {\n    let addrNo0x = evmContractAddress.slice(from: 0, upTo: 2) == "0x"\n            ? evmContractAddress.slice(from: 2, upTo: evmContractAddress.length)\n            : evmContractAddress\n    return EVMTokenList.isEVMAddressRegistered(addrNo0x)\n}\n';

// src/assets/scripts.defs.ts
var scripts = {
  getFlowPrice: get_flow_price_default,
  getStFlowPrice: get_stflow_price_default,
  getTokenInfoCadence: get_flow_token_info_default,
  getTokenInfoEVM: get_erc20_token_info_default,
  getAccountInfoFrom: get_acct_info_from_default,
  getAccountStatus: get_acct_status_default,
  isAddressChildOf: is_address_child_of_main_default,
  isTokenRegistered: is_token_registered_default,
  isEVMAssetRegistered: is_evm_asset_registered_default
};

// src/assets/cadence/transactions/init_agent_account.cdc?raw
var init_agent_account_default = 'import "EVM"\nimport "HybridCustody"\nimport "AccountsPool"\n\n/// Transaction to initialize the agent account\n/// The following resources are required:\n/// - EVM\n/// - HybridCustody.Manager\n/// - AccountsPool\ntransaction() {\n\n    prepare(acct: auth(Storage, Capabilities, Keys) &Account) {\n        // --- Start --- EVM initialization ---\n        let evmStoragePath = StoragePath(identifier: "evm")!\n        let evmPublicPath = PublicPath(identifier: "evm")!\n        if acct.storage.borrow<&AnyResource>(from: evmStoragePath) == nil {\n            let coa <- EVM.createCadenceOwnedAccount()\n            // Save the COA to the new account\n            acct.storage.save<@EVM.CadenceOwnedAccount>(<-coa, to: evmStoragePath)\n        }\n\n        if acct.capabilities.get<&EVM.CadenceOwnedAccount>(evmPublicPath).borrow() == nil {\n            let _ = acct.capabilities.unpublish(evmPublicPath)\n            let addressableCap = acct.capabilities.storage.issue<&EVM.CadenceOwnedAccount>(evmStoragePath)\n            acct.capabilities.publish(addressableCap, at: evmPublicPath)\n        }\n        // --- End --- EVM initialization ---\n\n        // --- Start --- HybridCustody.Manager initialization ---\n        // create account manager with hybrid custody manager capability\n        if acct.storage.borrow<&HybridCustody.Manager>(from: HybridCustody.ManagerStoragePath) == nil {\n            let m <- HybridCustody.createManager(filter: nil)\n            acct.storage.save(<- m, to: HybridCustody.ManagerStoragePath)\n        }\n\n        if acct.capabilities.get<&HybridCustody.Manager>(HybridCustody.ManagerPublicPath).borrow() == nil {\n            let _ = acct.capabilities.unpublish(HybridCustody.ManagerPublicPath)\n            acct.capabilities.publish(\n                acct.capabilities.storage.issue<&HybridCustody.Manager>(HybridCustody.ManagerStoragePath),\n                at: HybridCustody.ManagerPublicPath\n            )\n        }\n        // --- End --- HybridCustody.Manager initialization ---\n\n        // --- Start --- AccountsPool initialization ---\n        // create account pool with accounts pool capability\n        if acct.storage.borrow<&AccountsPool.Pool>(from: AccountsPool.StoragePath) == nil {\n            let acctCap = acct.capabilities.storage\n                .issue<auth(HybridCustody.Manage) &HybridCustody.Manager>(HybridCustody.ManagerStoragePath)\n\n            let pool <- AccountsPool.createAccountsPool(acctCap)\n            acct.storage.save(<- pool, to: AccountsPool.StoragePath)\n        }\n\n        if acct.capabilities.get<&AccountsPool.Pool>(AccountsPool.PublicPath).borrow() == nil {\n            let _ = acct.capabilities.unpublish(AccountsPool.PublicPath)\n            acct.capabilities.publish(\n                acct.capabilities.storage.issue<&AccountsPool.Pool>(AccountsPool.StoragePath),\n                at: AccountsPool.PublicPath\n            )\n        }\n        // --- End --- AccountsPool initialization ---\n\n        // --- Start --- Ensure Key is enough ---\n        let firstKey = acct.keys.get(keyIndex: 0) ?? panic("No Key 0")\n        let currentAmount = acct.keys.count\n        let amtToAdd: UInt64 = currentAmount < 50 ? 50 - currentAmount : 0\n\n        var i: UInt64 = 0\n        while i < amtToAdd {\n            acct.keys.add(publicKey: firstKey.publicKey, hashAlgorithm: firstKey.hashAlgorithm, weight: 1000.0)\n            i = i + 1\n        }\n        // --- End --- Ensure Key is enough ---\n    }\n}\n';

// src/assets/cadence/transactions/account-pool/create_child.cdc?raw
var create_child_default = `#allowAccountLinking
import "FungibleToken"
import "FlowToken"
import "AccountsPool"

/// Creates a child account for the given user by the main account
///
transaction(
    userId: String,
    initialFundingAmt: UFix64?
) {
    let category: String
    let pool: auth(AccountsPool.Admin) &AccountsPool.Pool
    let newAcctCap: Capability<auth(Storage, Contracts, Keys, Inbox, Capabilities) &Account>

    prepare(signer: auth(Storage, Capabilities) &Account) {
        self.category = "eliza"
        self.pool = signer.storage
            .borrow<auth(AccountsPool.Admin) &AccountsPool.Pool>(from: AccountsPool.StoragePath)
            ?? panic("Could not borrow the pool reference")

        // create a new Account, no keys needed
        let newAccount = Account(payer: signer)
        let fundingAmt = initialFundingAmt ?? 0.01 // Default deposit is 0.01 FLOW to the newly created account

        // Get a reference to the signer's stored vault
        let vaultRef = signer.storage
            .borrow<auth(FungibleToken.Withdraw) &FlowToken.Vault>(from: /storage/flowTokenVault)
            ?? panic("Could not borrow reference to the owner's Vault!")
        // Withdraw the funding amount from the owner's vault
        let flowToReserve <- vaultRef.withdraw(amount: fundingAmt)

        // Borrow the new account's Flow Token Receiver reference
        let newAcctFlowTokenReceiverRef = newAccount.capabilities
            .get<&{FungibleToken.Receiver}>(/public/flowTokenReceiver)
            .borrow()
            ?? panic("Could not borrow receiver reference to the newly created account")
        // Deposit the withdrawn FLOW into the new account's vault
        newAcctFlowTokenReceiverRef.deposit(from: <- flowToReserve)

        /* --- Link the AuthAccount Capability --- */
        //
        self.newAcctCap = newAccount.capabilities.account.issue<auth(Storage, Contracts, Keys, Inbox, Capabilities) &Account>()
    }

    pre {
        self.pool.getAddress(type: self.category, userId) == nil: "Account already exists for the given user"
    }

    execute {
        // Setup the new child account
        self.pool.setupNewChildByKey(type: self.category, key: userId, self.newAcctCap)
    }

    post {
        self.pool.getAddress(type: self.category, userId) != nil: "Account was not created"
    }
}
`;

// src/assets/cadence/transactions/account-pool/evm/transfer_erc20_from.cdc?raw
var transfer_erc20_from_default = `import "EVM"
import "FlowEVMBridgeUtils"

import "AccountsPool"

/// Executes a token transfer to the defined recipient address against the specified ERC20 contract.
///
transaction(
    evmContractAddressHex: String,
    recipientAddressHex: String,
    amount: UInt256,
    from: String?,
) {

    let evmContractAddress: EVM.EVMAddress
    let recipientAddress: EVM.EVMAddress
    let coa: auth(EVM.Call) &EVM.CadenceOwnedAccount
    let preBalance: UInt256
    var postBalance: UInt256

    prepare(signer: auth(Storage) &Account) {
        // ------------- Start - Load the correct Account from signer's Account Pool -------------
        let acct = (from == nil
            ? signer
            : (signer.storage.borrow<auth(AccountsPool.Child) &AccountsPool.Pool>(from: AccountsPool.StoragePath)
                ?? panic("Failed to load Accounts Pool for ".concat(signer.address.toString()))
            ).borrowChildAccount(type: "eliza", from))
                ?? panic("Could not borrow Account reference for ".concat(from ?? "signer"))
        // ------------- End - Load the correct Account from signer's Account Pool -------------

        self.evmContractAddress = EVM.addressFromString(evmContractAddressHex)
        self.recipientAddress = EVM.addressFromString(recipientAddressHex)

        self.coa = acct.storage.borrow<auth(EVM.Call) &EVM.CadenceOwnedAccount>(from: /storage/evm)
            ?? panic("Could not borrow CadenceOwnedAccount reference")

        self.preBalance = FlowEVMBridgeUtils.balanceOf(owner: self.coa.address(), evmContractAddress: self.evmContractAddress)
        self.postBalance = 0
    }

    execute {
        let calldata = EVM.encodeABIWithSignature("transfer(address,uint256)", [self.recipientAddress, amount])
        let callResult = self.coa.call(
            to: self.evmContractAddress,
            data: calldata,
            gasLimit: 15_000_000,
            value: EVM.Balance(attoflow: 0)
        )
        assert(callResult.status == EVM.Status.successful, message: "Call to ERC20 contract failed")
        self.postBalance = FlowEVMBridgeUtils.balanceOf(owner: self.coa.address(), evmContractAddress: self.evmContractAddress)
    }

    post {
        self.postBalance == self.preBalance - amount: "Transfer failed"
    }
}
`;

// src/assets/cadence/transactions/account-pool/flow-token/dynamic_vm_transfer_from.cdc?raw
var dynamic_vm_transfer_from_default = `import "FungibleToken"
import "FlowToken"

import "EVM"

import "AccountsPool"

// Transfers $FLOW from the user's account to the recipient's address, determining the target VM based on the format
// of the recipient's hex address. Note that the sender's funds are sourced by default from the target VM, pulling any
// difference from the alternate VM if available. e.g. Transfers to Flow addresses will first attempt to withdraw from
// the user's Flow vault, pulling any remaining funds from the user's EVM account if available. Transfers to EVM
// addresses will first attempt to withdraw from the user's EVM account, pulling any remaining funds from the user's
// Flow vault if available. If the user's balance across both VMs is insufficient, the transaction will revert.
///
/// @param addressString: The recipient's address in hex format - this should be either an EVM address or a Flow address
/// @param amount: The amount of $FLOW to transfer as a UFix64 value
/// @param from: The optional account key to use for the transfer, if the signer is an AccountsPool account
///
transaction(
    addressString: String,
    amount: UFix64,
    from: String?,
) {
    let sentVault: @FlowToken.Vault
    let evmRecipient: EVM.EVMAddress?
    var receiver: &{FungibleToken.Receiver}?

    prepare(signer: auth(Storage) &Account) {
        // ------------- Start - Load the correct Account from signer's Account Pool -------------
        let acct = (from == nil
            ? signer
            : (signer.storage.borrow<auth(AccountsPool.Child) &AccountsPool.Pool>(from: AccountsPool.StoragePath)
                ?? panic("Failed to load Accounts Pool for ".concat(signer.address.toString()))
            ).borrowChildAccount(type: "eliza", from))
                ?? panic("Could not borrow Account reference for ".concat(from ?? "signer"))
        // ------------- End - Load the correct Account from signer's Account Pool -------------

        // Reference account's COA if one exists
        let coa = acct.storage.borrow<auth(EVM.Withdraw) &EVM.CadenceOwnedAccount>(from: /storage/evm)

        // Reference account's FlowToken Vault
        let sourceVault = acct.storage.borrow<auth(FungibleToken.Withdraw) &FlowToken.Vault>(from: /storage/flowTokenVault)
            ?? panic("Could not borrow account's FlowToken.Vault")
        let cadenceBalance = sourceVault.balance

        // Define optional recipients for both VMs
        self.receiver = nil
        let cadenceRecipient = Address.fromString(addressString)
        self.evmRecipient = cadenceRecipient == nil ? EVM.addressFromString(addressString) : nil
        // Validate exactly one target address is assigned
        if cadenceRecipient != nil && self.evmRecipient != nil {
            panic("Malformed recipient address - assignable as both Cadence and EVM addresses")
        } else if cadenceRecipient == nil && self.evmRecipient == nil {
            panic("Malformed recipient address - not assignable as either Cadence or EVM address")
        }

        // Create empty FLOW vault to capture funds
        self.sentVault <- FlowToken.createEmptyVault(vaultType: Type<@FlowToken.Vault>())
        /// If the target VM is Flow, does the Vault have sufficient balance to cover?
        if cadenceRecipient != nil {
            // Assign the Receiver of the $FLOW transfer
            self.receiver = getAccount(cadenceRecipient!).capabilities.borrow<&{FungibleToken.Receiver}>(
                    /public/flowTokenReceiver
                ) ?? panic("Could not borrow reference to recipient's FungibleToken.Receiver")

            // Withdraw from the account's Cadence Vault and deposit to sentVault
            var withdrawAmount = amount < cadenceBalance ? amount : cadenceBalance
            self.sentVault.deposit(from: <-sourceVault.withdraw(amount: withdrawAmount))

            // If the cadence balance didn't cover the amount, check the account's EVM balance
            if amount > self.sentVault.balance {
                let difference = amount - cadenceBalance
                // Revert if the account doesn't have an EVM account or EVM balance is insufficient
                if coa == nil || difference < coa!.balance().inFLOW() {
                    panic("Insufficient balance across Flow and EVM accounts")
                }

                // Withdraw from the account's EVM account and deposit to sentVault
                let withdrawFromEVM = EVM.Balance(attoflow: 0)
                withdrawFromEVM.setFLOW(flow: difference)
                self.sentVault.deposit(from: <-coa!.withdraw(balance: withdrawFromEVM))
            }
        } else if self.evmRecipient != nil {
            // Check account's balance can cover the amount
            if coa != nil {
                // Determine the amount to withdraw from the account's EVM account
                let balance = coa!.balance()
                let withdrawAmount = amount < balance.inFLOW() ? amount : balance.inFLOW()
                balance.setFLOW(flow: withdrawAmount)

                // Withdraw funds from EVM to the sentVault
                self.sentVault.deposit(from: <-coa!.withdraw(balance: balance))
            }
            if amount > self.sentVault.balance {
                // Insufficient amount withdrawn from EVM, check account's Flow balance
                let difference = amount - self.sentVault.balance
                if difference > cadenceBalance {
                    panic("Insufficient balance across Flow and EVM accounts")
                }
                // Withdraw from the account's Cadence Vault and deposit to sentVault
                self.sentVault.deposit(from: <-sourceVault.withdraw(amount: difference))
            }
        }
    }

    pre {
        self.sentVault.balance == amount: "Attempting to send an incorrect amount of $FLOW"
    }

    execute {
        // Complete Cadence transfer if the FungibleToken Receiver is assigned
        if self.receiver != nil {
            self.receiver!.deposit(from: <-self.sentVault)
        } else {
            // Otherwise, complete EVM transfer
            self.evmRecipient!.deposit(from: <-self.sentVault)
        }
    }
}
`;

// src/assets/cadence/transactions/account-pool/ft/generic_transfer_with_address_from.cdc?raw
var generic_transfer_with_address_from_default = `import "FungibleToken"
import "FungibleTokenMetadataViews"

import "AccountsPool"

#interaction (
  version: "1.0.0",
	title: "Generic FT Transfer with Contract Address and Name",
	description: "Transfer any Fungible Token by providing the contract address and name",
	language: "en-US",
)

/// Can pass in any contract address and name to transfer a token from that contract
/// This lets you choose the token you want to send
///
/// Any contract can be chosen here, so wallets should check argument values
/// to make sure the intended token contract name and address is passed in
/// Contracts that are used must implement the FTVaultData Metadata View
///
/// Note: This transaction only will work for Fungible Tokens that
///       have their token's resource name set as "Vault".
///       Tokens with other names will need to use a different transaction
///       that additionally specifies the identifier
///
/// @param amount: The amount of tokens to transfer
/// @param to: The address to transfer the tokens to
/// @param contractAddress: The address of the contract that defines the tokens being transferred
/// @param contractName: The name of the contract that defines the tokens being transferred. Ex: "FlowToken"
/// @param from: The optional account key to use for the transfer, if the signer is an AccountsPool account
///
transaction(
    amount: UFix64,
    to: Address,
    contractAddress: Address,
    contractName: String,
    from: String?,
) {

    // The Vault resource that holds the tokens that are being transferred
    let tempVault: @{FungibleToken.Vault}

    // FTVaultData struct to get paths from
    let vaultData: FungibleTokenMetadataViews.FTVaultData

    prepare(signer: auth(Storage) &Account) {
        // ------------- Start - Load the correct Account from signer's Account Pool -------------
        let acct = (from == nil
            ? signer
            : (signer.storage.borrow<auth(AccountsPool.Child) &AccountsPool.Pool>(from: AccountsPool.StoragePath)
                ?? panic("Failed to load Accounts Pool for ".concat(signer.address.toString()))
            ).borrowChildAccount(type: "eliza", from))
                ?? panic("Could not borrow Account reference for ".concat(from ?? "signer"))
        // ------------- End - Load the correct Account from signer's Account Pool -------------

        // Borrow a reference to the vault stored on the passed account at the passed publicPath
        let resolverRef = getAccount(contractAddress)
            .contracts.borrow<&{FungibleToken}>(name: contractName)
                ?? panic("Could not borrow FungibleToken reference to the contract. Make sure the provided contract name ("
                          .concat(contractName).concat(") and address (").concat(contractAddress.toString()).concat(") are correct!"))

        // Use that reference to retrieve the FTView
        self.vaultData = resolverRef.resolveContractView(resourceType: nil, viewType: Type<FungibleTokenMetadataViews.FTVaultData>()) as! FungibleTokenMetadataViews.FTVaultData?
            ?? panic("Could not resolve FTVaultData view. The ".concat(contractName)
                .concat(" contract needs to implement the FTVaultData Metadata view in order to execute this transaction."))

        // Get a reference to the signer's stored vault
        let vaultRef = acct.storage.borrow<auth(FungibleToken.Withdraw) &{FungibleToken.Provider}>(from: self.vaultData.storagePath)
			?? panic("The signer does not store a FungibleToken.Provider object at the path "
                .concat(self.vaultData.storagePath.toString()).concat("For the ").concat(contractName)
                .concat(" contract at address ").concat(contractAddress.toString())
                .concat(". The signer must initialize their account with this object first!"))

        self.tempVault <- vaultRef.withdraw(amount: amount)

        // Get the string representation of the address without the 0x
        var addressString = contractAddress.toString()
        if addressString.length == 18 {
            addressString = addressString.slice(from: 2, upTo: 18)
        }
        let typeString: String = "A.".concat(addressString).concat(".").concat(contractName).concat(".Vault")
        let type = CompositeType(typeString)
        assert(
            type != nil,
            message: "Could not create a type out of the contract name and address!"
        )

        assert(
            self.tempVault.getType() == type!,
            message: "The Vault that was withdrawn to transfer is not the type that was requested!"
        )
    }

    execute {
        let recipient = getAccount(to)
        let receiverRef = recipient.capabilities.borrow<&{FungibleToken.Receiver}>(self.vaultData.receiverPath)
            ?? panic("Could not borrow a Receiver reference to the FungibleToken Vault in account "
                .concat(to.toString()).concat(" at path ").concat(self.vaultData.receiverPath.toString())
                .concat(". Make sure you are sending to an address that has ")
                .concat("a FungibleToken Vault set up properly at the specified path."))

        // Transfer tokens from the signer's stored vault to the receiver capability
        receiverRef.deposit(from: <-self.tempVault)
    }
}
`;

// src/assets/cadence/transactions/account-pool/token-list/register_evm_asset_from.cdc?raw
var register_evm_asset_from_default = `import "FungibleToken"
import "FlowToken"

import "ScopedFTProviders"
import "EVM"
import "FlowEVMBridgeConfig"

import "TokenList"
import "NFTList"
import "EVMTokenList"

import "AccountsPool"

transaction(
    contractAddressHex: String,
    from: String?,
) {
    let scopedProvider: @ScopedFTProviders.ScopedFTProvider

    prepare(signer: auth(Storage, Capabilities) &Account) {
        // ------------- Start - Load the correct Account from signer's Account Pool -------------
        let acct = (from == nil
            ? signer
            : (signer.storage.borrow<auth(AccountsPool.Child) &AccountsPool.Pool>(from: AccountsPool.StoragePath)
                ?? panic("Failed to load Accounts Pool for ".concat(signer.address.toString()))
            ).borrowChildAccount(type: "eliza", from))
                ?? panic("Could not borrow Account reference for ".concat(from ?? "signer"))
        // ------------- End - Load the correct Account from signer's Account Pool -------------

        /* --- Configure a ScopedFTProvider - Start -- */

        // Issue and store bridge-dedicated Provider Capability in storage if necessary
        if acct.storage.type(at: FlowEVMBridgeConfig.providerCapabilityStoragePath) == nil {
            let providerCap = acct.capabilities
                .storage.issue<auth(FungibleToken.Withdraw) &{FungibleToken.Provider}>(/storage/flowTokenVault)
            acct.storage.save(providerCap, to: FlowEVMBridgeConfig.providerCapabilityStoragePath)
        }
        // Copy the stored Provider capability and create a ScopedFTProvider
        let providerCapCopy = acct.storage
            .copy<Capability<auth(FungibleToken.Withdraw) &{FungibleToken.Provider}>>(
                from: FlowEVMBridgeConfig.providerCapabilityStoragePath
            ) ?? panic("Invalid Provider Capability found in storage.")
        let providerFilter = ScopedFTProviders.AllowanceFilter(FlowEVMBridgeConfig.onboardFee)
        self.scopedProvider <- ScopedFTProviders.createScopedFTProvider(
            provider: providerCapCopy,
            filters: [ providerFilter ],
            expiration: getCurrentBlock().timestamp + 1.0
        )
        /* --- Configure a ScopedFTProvider - End -- */
    }

    execute {
        // Onboard the EVM contract
        EVMTokenList.ensureEVMAssetRegistered(
            contractAddressHex,
            feeProvider: &self.scopedProvider as auth(FungibleToken.Withdraw) &{FungibleToken.Provider}
        )
        destroy self.scopedProvider
    }
}
`;

// src/assets/cadence/transactions/account-pool/token-list/register_standard_asset_from.cdc?raw
var register_standard_asset_from_default = `import "FungibleToken"
import "FlowToken"

import "ScopedFTProviders"
import "FlowEVMBridgeConfig"

import "TokenList"
import "NFTList"
import "EVMTokenList"

import "AccountsPool"

transaction(
    address: Address,
    contractName: String,
    from: String?,
) {
    let scopedProvider: @ScopedFTProviders.ScopedFTProvider

    prepare(signer: auth(Storage, Capabilities) &Account) {
        // ------------- Start - Load the correct Account from signer's Account Pool -------------
        let acct = (from == nil
            ? signer
            : (signer.storage.borrow<auth(AccountsPool.Child) &AccountsPool.Pool>(from: AccountsPool.StoragePath)
                ?? panic("Failed to load Accounts Pool for ".concat(signer.address.toString()))
            ).borrowChildAccount(type: "eliza", from))
                ?? panic("Could not borrow Account reference for ".concat(from ?? "signer"))
        // ------------- End - Load the correct Account from signer's Account Pool -------------

        /* --- Configure a ScopedFTProvider - Start -- */

        // Issue and store bridge-dedicated Provider Capability in storage if necessary
        if acct.storage.type(at: FlowEVMBridgeConfig.providerCapabilityStoragePath) == nil {
            let providerCap = acct.capabilities
                .storage.issue<auth(FungibleToken.Withdraw) &{FungibleToken.Provider}>(/storage/flowTokenVault)
            acct.storage.save(providerCap, to: FlowEVMBridgeConfig.providerCapabilityStoragePath)
        }
        // Copy the stored Provider capability and create a ScopedFTProvider
        let providerCapCopy = acct.storage
            .copy<Capability<auth(FungibleToken.Withdraw) &{FungibleToken.Provider}>>(
                from: FlowEVMBridgeConfig.providerCapabilityStoragePath
            ) ?? panic("Invalid Provider Capability found in storage.")
        let providerFilter = ScopedFTProviders.AllowanceFilter(FlowEVMBridgeConfig.onboardFee)
        self.scopedProvider <- ScopedFTProviders.createScopedFTProvider(
            provider: providerCapCopy,
            filters: [ providerFilter ],
            expiration: getCurrentBlock().timestamp + 1.0
        )
        /* --- Configure a ScopedFTProvider - End -- */
    }

    execute {
        EVMTokenList.ensureCadenceAssetRegistered(
            address,
            contractName,
            feeProvider:  &self.scopedProvider as auth(FungibleToken.Withdraw) &{FungibleToken.Provider}
        )
        destroy self.scopedProvider
    }
}
`;

// src/assets/cadence/transactions/token-list/register_standard_asset_no_bridge.cdc?raw
var register_standard_asset_no_bridge_default = 'import "TokenList"\nimport "NFTList"\n\ntransaction(\n    address: Address,\n    contractName: String,\n) {\n    prepare(signer: &Account) {\n        if TokenList.isValidToRegister(address, contractName) {\n            TokenList.ensureFungibleTokenRegistered(address, contractName)\n        } else if NFTList.isValidToRegister(address, contractName) {\n            NFTList.ensureNFTCollectionRegistered(address, contractName)\n        }\n    }\n}\n';

// src/assets/transactions.defs.ts
var transactions = {
  initAgentAccount: init_agent_account_default,
  acctPoolCreateChildAccount: create_child_default,
  acctPoolEVMTransferERC20: transfer_erc20_from_default,
  acctPoolFlowTokenDynamicTransfer: dynamic_vm_transfer_from_default,
  acctPoolFTGenericTransfer: generic_transfer_with_address_from_default,
  tlRegisterEVMAsset: register_evm_asset_from_default,
  tlRegisterCadenceAsset: register_standard_asset_from_default,
  tlRegisterCadenceAssetNoBridge: register_standard_asset_no_bridge_default
};

// src/services/acctPool.service.ts
function _ts_decorate(decorators, target, key, desc) {
  var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
  if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
  else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
  return c > 3 && r && Object.defineProperty(target, key, r), r;
}
__name(_ts_decorate, "_ts_decorate");
function _ts_metadata(k, v) {
  if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
}
__name(_ts_metadata, "_ts_metadata");
function _ts_param(paramIndex, decorator) {
  return function(target, key) {
    decorator(target, key, paramIndex);
  };
}
__name(_ts_param, "_ts_param");
var AccountsPoolService = class extends Service {
  static {
    __name(this, "AccountsPoolService");
  }
  walletService;
  constructor(walletService) {
    super(), this.walletService = walletService;
  }
  static get serviceType() {
    return "accounts-pool";
  }
  async initialize(_runtime) {
    const status = await this.getMainAccountStatus();
    if (!status) {
      await new Promise((resolve, reject) => {
        this.walletService.sendTransaction(transactions.initAgentAccount, (_arg, _t) => [], {
          onFinalized: /* @__PURE__ */ __name(async (txid, _status, errorMsg) => {
            if (errorMsg) {
              elizaLogger.error(`Failed to initialize main account: ${errorMsg}`);
              reject(new Error(errorMsg));
            } else {
              elizaLogger.info("Main account initialized by txid:", txid);
              resolve();
            }
          }, "onFinalized")
        }).catch(reject);
      });
    }
  }
  // ----- Customized methods -----
  /**
   * Get the main address of the wallet
   */
  get mainAddress() {
    return this.walletService.address;
  }
  // ----- Flow blockchain READ scripts -----
  /**
   * Get the main account status
   */
  async getMainAccountStatus() {
    const walletAddress = this.walletService.address;
    try {
      const obj = await this.walletService.executeScript(scripts.getAccountStatus, (arg, t) => [
        arg(walletAddress, t.Address)
      ], void 0);
      if (obj) {
        return {
          address: obj.address,
          balance: Number.parseFloat(obj.balance),
          childrenAmount: Number.parseInt(obj.childrenAmount)
        };
      }
    } catch (error) {
      elizaLogger.error(`Failed to query account status from ${walletAddress}`, error);
      throw error;
    }
    return void 0;
  }
  /**
   * Check if the address is a child of the agent
   * @param address
   */
  async checkAddressIsChildOfAgent(address) {
    const walletAddress = this.walletService.address;
    try {
      return await this.walletService.executeScript(scripts.isAddressChildOf, (arg, t) => [
        arg(walletAddress, t.Address),
        arg(address, t.Address)
      ], false);
    } catch (error) {
      elizaLogger.error(`Failed to check if address ${address} is child of agent`, error);
    }
    return false;
  }
  /**
   * Query account info
   * @param userId
   * @returns
   */
  async queryAccountInfo(userId = void 0) {
    const walletAddress = this.walletService.address;
    try {
      const obj = await this.walletService.executeScript(scripts.getAccountInfoFrom, (arg, t) => [
        arg(walletAddress, t.Address),
        arg(userId ?? null, t.Optional(t.String))
      ], void 0);
      if (obj) {
        return {
          address: obj.address,
          balance: Number.parseFloat(obj.balance),
          coaAddress: obj.coaAddress,
          coaBalance: obj.coaBalance ? Number.parseFloat(obj.coaBalance) : 0
        };
      }
    } catch (error) {
      elizaLogger.error(`Failed to query account info for ${userId ?? "root"} from ${walletAddress}`, error);
      throw error;
    }
    return void 0;
  }
  // ----- Flow blockchain WRITE transactions -----
  /**
   * Create a new account
   * @param userId
   * @returns
   */
  async createNewAccount(userId, callbacks, initalFunding) {
    return await this.walletService.sendTransaction(transactions.acctPoolCreateChildAccount, (arg, t) => [
      arg(userId, t.String),
      arg(initalFunding ? initalFunding.toFixed(8) : null, t.Optional(t.UFix64))
    ], callbacks);
  }
  /**
   * Transfer FlowToken to another account from the user's account
   * @param fromUserId
   */
  async transferFlowToken(fromUserId, recipient, amount, callbacks) {
    return await this.walletService.sendTransaction(transactions.acctPoolFlowTokenDynamicTransfer, (arg, t) => [
      arg(recipient, t.String),
      arg(amount.toFixed(8), t.UFix64),
      arg(fromUserId, t.Optional(t.String))
    ], callbacks);
  }
  /**
   * Transfer Cadence Generic FT to another account from the user's account
   * @param fromUserId
   * @param recipient
   * @param amount
   * @param tokenFTAddr
   * @param tokenContractName
   * @param callbacks
   */
  async transferGenericFT(fromUserId, recipient, amount, tokenFTAddr, tokenContractName, callbacks) {
    return await this.walletService.sendTransaction(transactions.acctPoolFTGenericTransfer, (arg, t) => [
      arg(amount.toFixed(8), t.UFix64),
      arg(recipient, t.Address),
      arg(tokenFTAddr, t.Address),
      arg(tokenContractName, t.String),
      arg(fromUserId, t.Optional(t.String))
    ], callbacks);
  }
  /**
   * Transfer ERC20 token to another account from the user's account
   * @param fromUserId
   * @param recipient
   * @param amount
   * @param callback
   */
  async transferERC20(fromUserId, recipient, amount, erc20Contract, callbacks) {
    const decimals = await defaultQueries.queryEvmERC20Decimals(this.walletService.wallet, erc20Contract);
    const adjustedAmount = BigInt(amount * 10 ** decimals);
    return await this.walletService.sendTransaction(transactions.acctPoolEVMTransferERC20, (arg, t) => [
      arg(erc20Contract, t.String),
      arg(recipient, t.String),
      arg(adjustedAmount.toString(), t.UInt256),
      arg(fromUserId, t.Optional(t.String))
    ], callbacks);
  }
};
AccountsPoolService = _ts_decorate([
  injectable(),
  _ts_param(0, inject(FlowWalletService)),
  _ts_metadata("design:type", Function),
  _ts_metadata("design:paramtypes", [
    typeof FlowWalletService === "undefined" ? Object : FlowWalletService
  ])
], AccountsPoolService);
globalContainer.bind(AccountsPoolService).toSelf().inSingletonScope();

// src/actions/transfer.ts
function _ts_decorate2(decorators, target, key, desc) {
  var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
  if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
  else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
  return c > 3 && r && Object.defineProperty(target, key, r), r;
}
__name(_ts_decorate2, "_ts_decorate");
function _ts_metadata2(k, v) {
  if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
}
__name(_ts_metadata2, "_ts_metadata");
function _ts_param2(paramIndex, decorator) {
  return function(target, key) {
    decorator(target, key, paramIndex);
  };
}
__name(_ts_param2, "_ts_param");
var TransferContent = class {
  static {
    __name(this, "TransferContent");
  }
  token;
  amount;
  to;
};
_ts_decorate2([
  property({
    description: "Cadence Resource Identifier or ERC20 contract address (if not native token). this field should be null if the token is native token: $FLOW or FLOW",
    examples: [
      "For Cadence resource identifier, the field should be 'A.1654653399040a61.ContractName'",
      "For ERC20 contract address, the field should be '0xe6ffc15a5bde7dd33c127670ba2b9fcb82db971a'"
    ],
    schema: z.string().nullable()
  }),
  _ts_metadata2("design:type", Object)
], TransferContent.prototype, "token", void 0);
_ts_decorate2([
  property({
    description: "Amount to transfer, it should be a number or a string",
    examples: [
      "'1000'",
      "1000"
    ],
    schema: z.union([
      z.string(),
      z.number()
    ])
  }),
  _ts_metadata2("design:type", String)
], TransferContent.prototype, "amount", void 0);
_ts_decorate2([
  property({
    description: "Recipient identifier, can a wallet address like EVM address or Cadence address, or a userId which is UUID formated.",
    examples: [
      "For Cadence address: '0x1654653399040a61'",
      "For EVM address: '0x742d35Cc6634C0532925a3b844Bc454e4438f44e'",
      "For userId: 'e1b3b9c2-7e3f-4b1b-9f7d-2a0c7e2d6e9c', If the recipient mentioned in message is 'me' or 'myself', it should be the current user's id"
    ],
    schema: z.string()
  }),
  _ts_metadata2("design:type", String)
], TransferContent.prototype, "to", void 0);
var transferOption = {
  name: "SEND_COIN",
  similes: [
    "SEND_TOKEN",
    "SEND_TOKEN_ON_FLOW",
    "TRANSFER_TOKEN_ON_FLOW",
    "TRANSFER_TOKENS_ON_FLOW",
    "TRANSFER_FLOW",
    "SEND_FLOW",
    "PAY_BY_FLOW"
  ],
  description: "Call this action to transfer any fungible token/coin from the user's Flow wallet to another address",
  examples: [
    [
      {
        user: "{{user1}}",
        content: {
          text: "Send 1 FLOW to 0xa2de93114bae3e73",
          action: "SEND_COIN"
        }
      }
    ],
    [
      {
        user: "{{user1}}",
        content: {
          text: "Send 1 FLOW - A.1654653399040a61.FlowToken to 0xa2de93114bae3e73",
          action: "SEND_COIN"
        }
      }
    ],
    [
      {
        user: "{{user1}}",
        content: {
          text: "Send 1000 FROTH - 0xb73bf8e6a4477a952e0338e6cc00cc0ce5ad04ba to 0x000000000000000000000002e44fbfbd00395de5",
          action: "SEND_COIN"
        }
      }
    ],
    [
      {
        user: "{{agentName}}",
        content: {
          text: "I need to send 1 FLOW to user: {{user1}}",
          action: "SEND_COIN"
        }
      }
    ]
  ],
  contentClass: TransferContent,
  suppressInitialMessage: true
};
function isUUID(str) {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  return uuidRegex.test(str);
}
__name(isUUID, "isUUID");
var TransferAction = class extends BaseFlowInjectableAction {
  static {
    __name(this, "TransferAction");
  }
  acctPoolService;
  constructor(acctPoolService) {
    super(transferOption), this.acctPoolService = acctPoolService;
  }
  /**
   * Validate the transfer action
   * @param runtime the runtime instance
   * @param message the message content
   * @param state the state object
   */
  async validate(runtime, message, state) {
    if (await super.validate(runtime, message, state)) {
      return true;
    }
    return false;
  }
  /**
   * Execute the transfer action
   *
   * @param content the content from processMessages
   * @param callback the callback function to pass the result to Eliza runtime
   * @returns the transaction response
   */
  async execute(content, _runtime, message, _state, callback) {
    if (!content) {
      elizaLogger2.warn("No content generated");
      return;
    }
    elizaLogger2.log(`Starting ${this.name} handler...`);
    const walletAddress = this.walletSerivce.address;
    const userId = message.userId;
    const isSelf = userId === message.agentId;
    const logPrefix = `Account[${walletAddress}/${isSelf ? "root" : userId}]`;
    const amount = typeof content.amount === "number" ? content.amount : Number.parseFloat(content.amount);
    try {
      let recipient = content.to;
      if (isUUID(content.to)) {
        if (content.to === userId) {
          throw new Error("Recipient is the same as the sender");
        }
        const acctInfo = await this.acctPoolService.queryAccountInfo(content.to);
        if (acctInfo) {
          recipient = acctInfo.address;
          elizaLogger2.info(`${logPrefix}
 Recipient is a user id - ${content.to}, its wallet address: ${recipient}`);
        } else {
          throw new Error(`Recipient not found with id: ${content.to}`);
        }
      }
      let txId;
      let keyIndex;
      if (!content.token) {
        const fromAccountInfo = await this.acctPoolService.queryAccountInfo(userId);
        const totalBalance = fromAccountInfo.balance + (fromAccountInfo.coaBalance ?? 0);
        if (totalBalance < amount) {
          throw new Error("Insufficient balance to transfer");
        }
        elizaLogger2.log(`${logPrefix}
 Sending ${amount} FLOW to ${recipient}...`);
        const resp = await this.acctPoolService.transferFlowToken(userId, recipient, amount);
        txId = resp.txId;
        keyIndex = resp.index;
      } else if (isCadenceIdentifier(content.token)) {
        if (!isFlowAddress(recipient)) {
          throw new Error("Recipient address is not a valid Flow address");
        }
        const [_, tokenAddr, tokenContractName] = content.token.split(".");
        elizaLogger2.log(`${logPrefix}
 Sending ${amount} A.${tokenAddr}.${tokenContractName} to ${recipient}...`);
        const resp = await this.acctPoolService.transferGenericFT(userId, recipient, amount, `0x${tokenAddr}`, tokenContractName);
        txId = resp.txId;
        keyIndex = resp.index;
      } else if (isEVMAddress(content.token)) {
        if (!isEVMAddress(recipient)) {
          throw new Error("Recipient address is not a valid EVM address");
        }
        elizaLogger2.log(`${logPrefix}
 Sending ${amount} ${content.token}(EVM) to ${recipient}...`);
        const resp = await this.acctPoolService.transferERC20(userId, recipient, amount, content.token);
        txId = resp.txId;
        keyIndex = resp.index;
      }
      elizaLogger2.log(`${logPrefix}
 Sent transaction: ${txId} by KeyIndex[${keyIndex}]`);
      if (callback) {
        const tokenName = content.token || "FLOW";
        const extraMsg = `${logPrefix}
 Successfully transferred ${content.amount} ${tokenName} to ${content.to}`;
        callback?.({
          text: formater_exports.formatTransationSent(txId, this.walletSerivce.wallet.network, extraMsg),
          content: {
            success: true,
            txid: txId,
            token: content.token,
            to: content.to,
            amount: content.amount
          }
        });
      }
    } catch (e) {
      elizaLogger2.error("Error in sending transaction:", e.message);
      callback?.({
        text: `${logPrefix}
 Unable to process transfer request. Error: 
 ${e.message}`,
        content: {
          error: e.message
        }
      });
    }
    elizaLogger2.log(`Finished ${this.name} handler.`);
  }
};
TransferAction = _ts_decorate2([
  injectable2(),
  _ts_param2(0, inject2(AccountsPoolService)),
  _ts_metadata2("design:type", Function),
  _ts_metadata2("design:paramtypes", [
    typeof AccountsPoolService === "undefined" ? Object : AccountsPoolService
  ])
], TransferAction);
globalContainer2.bind(TransferAction).toSelf();

// src/actions/get-flow-price.ts
import { z as z2 } from "zod";
import { injectable as injectable3 } from "inversify";
import { elizaLogger as elizaLogger3 } from "@elizaos/core";
import { globalContainer as globalContainer3, property as property2 } from "@elizaos-plugins/plugin-di";
import { BaseFlowInjectableAction as BaseFlowInjectableAction2 } from "@elizaos-plugins/plugin-flow";
function _ts_decorate3(decorators, target, key, desc) {
  var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
  if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
  else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
  return c > 3 && r && Object.defineProperty(target, key, r), r;
}
__name(_ts_decorate3, "_ts_decorate");
function _ts_metadata3(k, v) {
  if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
}
__name(_ts_metadata3, "_ts_metadata");
var GetPriceContent = class {
  static {
    __name(this, "GetPriceContent");
  }
  token;
};
_ts_decorate3([
  property2({
    description: "This field should be FLOW or stFLOW",
    examples: [
      "If asking for FLOW token, the field should be FLOW",
      "Otherwise, the field should be stFLOW"
    ],
    schema: z2.string()
  }),
  _ts_metadata3("design:type", String)
], GetPriceContent.prototype, "token", void 0);
var actionOpts = {
  name: "GET_FLOW_PRICE",
  similes: [
    "GET_STFLOW_PRICE",
    "GET_FLOW_TOKEN_PRICE",
    "GET_STFLOW_TOKEN_PRICE"
  ],
  description: "Call this action to obtain the current price in USD of FLOW token or stFLOW token",
  examples: [
    [
      {
        user: "{{user1}}",
        content: {
          text: "Get current FLOW token price.",
          action: "GET_FLOW_PRICE"
        }
      }
    ],
    [
      {
        user: "{{user1}}",
        content: {
          text: "Get current stFLOW token price in USD.",
          action: "GET_STFLOW_PRICE"
        }
      }
    ]
  ],
  contentClass: GetPriceContent,
  suppressInitialMessage: true
};
var GetPriceAction = class extends BaseFlowInjectableAction2 {
  static {
    __name(this, "GetPriceAction");
  }
  constructor() {
    super(actionOpts);
  }
  /**
   * Validate if the action can be executed
   */
  async validate(_runtime, message, _state) {
    const keywords = [
      "price",
      "flow",
      "stflow",
      "\u4EF7\u683C",
      "\u5E01\u4EF7"
    ];
    return keywords.some((keyword) => message.content.text.toLowerCase().includes(keyword.toLowerCase()));
  }
  /**
   * Execute the transfer action
   *
   * @param content the content from processMessages
   * @param callback the callback function to pass the result to Eliza runtime
   * @returns the transaction response
   */
  async execute(content, _runtime, _message, _state, callback) {
    if (!content) {
      elizaLogger3.warn("No content generated");
      return;
    }
    elizaLogger3.log(`Starting ${this.name} handler...`);
    const resp = {
      ok: false
    };
    const targetToken = content.token?.toLowerCase();
    const validTokens = [
      "flow",
      "stflow"
    ];
    if (!validTokens.includes(targetToken)) {
      resp.error = `Invalid token type: ${targetToken}`;
    } else {
      let data;
      try {
        data = await this.walletSerivce.executeScript(targetToken === "flow" ? scripts.getFlowPrice : scripts.getStFlowPrice, (_arg, _t) => [], "");
      } catch (err) {
        resp.error = err.message;
      }
      if (data) {
        resp.ok = true;
        resp.data = Number.parseFloat(data);
      } else {
        resp.error = resp.error ?? "Failed to get price data";
      }
    }
    if (resp.ok) {
      callback?.({
        text: format(resp.data, targetToken),
        content: {
          success: true,
          token: content.token,
          price: resp.data
        },
        source: "FlowBlockchain"
      });
    } else {
      elizaLogger3.error("Error:", resp.error);
      callback?.({
        text: `Unable to get price for ${content.token}.`,
        content: {
          error: resp.error ?? "Unknown error"
        },
        source: "FlowBlockchain"
      });
    }
    elizaLogger3.log(`Finished ${this.name} handler.`);
    return resp;
  }
};
GetPriceAction = _ts_decorate3([
  injectable3(),
  _ts_metadata3("design:type", Function),
  _ts_metadata3("design:paramtypes", [])
], GetPriceAction);
var format = /* @__PURE__ */ __name((price, token) => {
  return `The current price of ${token} token is $${price.toFixed(8)}`;
}, "format");
globalContainer3.bind(GetPriceAction).toSelf();

// src/actions/get-token-info.ts
import { z as z3 } from "zod";
import { inject as inject3, injectable as injectable4 } from "inversify";
import { elizaLogger as elizaLogger4 } from "@elizaos/core";
import { globalContainer as globalContainer4, property as property3 } from "@elizaos-plugins/plugin-di";
import { BaseFlowInjectableAction as BaseFlowInjectableAction3, CacheProvider } from "@elizaos-plugins/plugin-flow";
function _ts_decorate4(decorators, target, key, desc) {
  var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
  if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
  else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
  return c > 3 && r && Object.defineProperty(target, key, r), r;
}
__name(_ts_decorate4, "_ts_decorate");
function _ts_metadata4(k, v) {
  if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
}
__name(_ts_metadata4, "_ts_metadata");
function _ts_param3(paramIndex, decorator) {
  return function(target, key) {
    decorator(target, key, paramIndex);
  };
}
__name(_ts_param3, "_ts_param");
var GetTokenInfoContent = class {
  static {
    __name(this, "GetTokenInfoContent");
  }
  symbol;
  token;
  vm;
};
_ts_decorate4([
  property3({
    description: "This field should be the token symbol which usually starts with $ or uppercase letters.",
    examples: [
      "if a token is named LOPPY or $LOPPY, the field should be LOPPY",
      "if no token symbol is provided, the field should be null"
    ],
    schema: z3.string().nullable()
  }),
  _ts_metadata4("design:type", String)
], GetTokenInfoContent.prototype, "symbol", void 0);
_ts_decorate4([
  property3({
    description: "Cadence Resource Identifier or ERC20 contract address (if not native token). this field should be null if the token is native token which symbol is FLOW.",
    examples: [
      "For Cadence resource identifier, the field should be 'A.1654653399040a61.ContractName'",
      "For ERC20 contract address, the field should be '0xe6ffc15a5bde7dd33c127670ba2b9fcb82db971a'"
    ],
    schema: z3.string().nullable()
  }),
  _ts_metadata4("design:type", Object)
], GetTokenInfoContent.prototype, "token", void 0);
_ts_decorate4([
  property3({
    description: "The blockchain VM type. This field should be either 'flow' or 'evm' according to the token type.",
    examples: [
      "If token field is Cadence resource identifier or null value, the vm field should be 'flow'",
      "If token field is ERC20 contract address, the vm field should be 'evm'",
      "If only symbol field is provided, the vm field should be 'flow'",
      "if symbol field is FLOW or token field is null, the vm field should be 'flow'"
    ],
    schema: z3.string().refine((vm) => [
      "flow",
      "evm"
    ].includes(vm))
  }),
  _ts_metadata4("design:type", String)
], GetTokenInfoContent.prototype, "vm", void 0);
var actionOpts2 = {
  name: "GET_TOKEN_INFO",
  similes: [
    "GET_TOKEN_DETAILS",
    "GET_TOKEN_METADATA"
  ],
  description: "Call this action to obtain the current information of any fungible token on the Flow blockchain.",
  examples: [
    [
      {
        user: "{{user1}}",
        content: {
          text: "Get details for the $LOPPY token",
          action: "GET_TOKEN_INFO"
        }
      }
    ],
    [
      {
        user: "{{user1}}",
        content: {
          text: "Get information of $LOPPY token: A.53f389d96fb4ce5e.SloppyStakes",
          action: "GET_TOKEN_INFO"
        }
      }
    ],
    [
      {
        user: "{{user1}}",
        content: {
          text: "Tell me current marketcap of token: 0x995258Cea49C25595CD94407FaD9E99B81406A84",
          action: "GET_TOKEN_INFO"
        }
      }
    ]
  ],
  contentClass: GetTokenInfoContent,
  suppressInitialMessage: true
};
var GetTokenInfoAction = class extends BaseFlowInjectableAction3 {
  static {
    __name(this, "GetTokenInfoAction");
  }
  cache;
  constructor(cache) {
    super(actionOpts2), this.cache = cache;
  }
  /**
   * Validate if the action can be executed
   */
  async validate(_runtime, message, _state) {
    const keywords = [
      "details",
      "token",
      "info",
      "information",
      "mcap",
      "marketcap",
      "\u8BE6\u60C5",
      "\u5E02\u503C"
    ];
    return keywords.some((keyword) => message.content.text.toLowerCase().includes(keyword.toLowerCase()));
  }
  /**
   * Execute the transfer action
   *
   * @param content the content from processMessages
   * @param callback the callback function to pass the result to Eliza runtime
   * @returns the transaction response
   */
  async execute(content, _runtime, _message, _state, callback) {
    if (!content) {
      elizaLogger4.warn("No content generated");
      return;
    }
    elizaLogger4.log(`Starting ${this.name} handler...`);
    const network = this.walletSerivce.connector.network;
    const cacheKey = `flow-tokenlist-${network}`;
    const tokenListStr = await this.cache.getCachedData(cacheKey);
    let tokenList = [];
    if (!tokenListStr) {
      tokenList = await fetchTokenList(network);
      if (tokenList?.length > 0) {
        await this.cache.setCachedData(cacheKey, JSON.stringify(tokenList), 60 * 60 * 24);
      }
    } else {
      tokenList = JSON.parse(tokenListStr);
    }
    const resp = {
      ok: false
    };
    let tokenInfo;
    const targetToken = content.symbol?.toLowerCase();
    if ([
      "flow"
    ].includes(targetToken)) {
      resp.error = "Cannot get token info for native FLOW token.";
    } else {
      const tokenDetails = tokenList.find((t) => content.token ? t.evmAddress === content.token || `A.${t.flowAddress}.${t.contractName}` === content.token : t.symbol === content.symbol);
      if (tokenDetails) {
        tokenInfo = {
          symbol: tokenDetails.symbol,
          name: tokenDetails.name,
          description: tokenDetails.description,
          decimals: tokenDetails.decimals,
          addressEVM: tokenDetails.evmAddress,
          identifierCadence: `A.${tokenDetails.flowAddress.slice(2)}.${tokenDetails.contractName}`,
          logoURI: tokenDetails.logoURI,
          totalSupply: 0,
          priceInFLOW: 0,
          mcapValueInFLOW: 0
        };
      } else {
        tokenInfo = {
          symbol: content.symbol,
          name: "Unknown",
          description: "",
          decimals: 0,
          addressEVM: void 0,
          identifierCadence: void 0,
          logoURI: void 0,
          totalSupply: 0,
          priceInFLOW: 0,
          mcapValueInFLOW: 0
        };
      }
      if (content.vm === "flow") {
        tokenInfo.decimals = 8;
        if (!tokenDetails) {
          resp.error = `Token info not found for $${content.symbol}`;
        } else {
          elizaLogger4.debug(`Loading token info for $${content.symbol}:`, tokenDetails);
          try {
            const info = await this.walletSerivce.executeScript(scripts.getTokenInfoCadence, (arg, t) => [
              arg(tokenDetails.flowAddress, t.Address),
              arg(tokenDetails.contractName, t.String)
            ], void 0);
            elizaLogger4.debug(`Loaded token info for ${content.symbol}:`, info);
            if (info && info.address === tokenDetails.flowAddress && info.contractName === tokenDetails.contractName) {
              tokenInfo.totalSupply = Number.parseFloat(info.totalSupply);
              tokenInfo.priceInFLOW = Number.parseFloat(info.priceInFLOW);
              tokenInfo.mcapValueInFLOW = tokenInfo.totalSupply * tokenInfo.priceInFLOW;
              resp.ok = true;
              resp.data = tokenInfo;
            } else {
              resp.error = `Failed to get token info for $${content.symbol}`;
            }
          } catch (err) {
            resp.error = `Failed to get token info for $${content.symbol}: ${err.message}`;
          }
        }
      } else if (/^0x[0-9a-fA-F]{40}$/.test(content.token ?? "")) {
        try {
          const info = await this.walletSerivce.executeScript(scripts.getTokenInfoEVM, (arg, t) => [
            arg(content.token, t.String)
          ], void 0);
          if (info && info.address?.toLowerCase() === content.token.toLowerCase()) {
            tokenInfo.name = info.name;
            tokenInfo.symbol = info.symbol;
            tokenInfo.decimals = Number.parseInt(info.decimals);
            tokenInfo.totalSupply = Number.parseInt(info.totalSupply) / 10 ** tokenInfo.decimals;
            const reservedTokenInPair = Number.parseInt(info.reservedTokenInPair);
            const reservedFlowInPair = Number.parseInt(info.reservedFlowInPair);
            tokenInfo.priceInFLOW = reservedFlowInPair / reservedTokenInPair;
            tokenInfo.mcapValueInFLOW = tokenInfo.totalSupply * tokenInfo.priceInFLOW;
            resp.ok = true;
            resp.data = tokenInfo;
          }
        } catch (err) {
          resp.error = `Failed to get token info for $${content.symbol}: ${err.message}`;
        }
      } else {
        resp.error = `Invalid token address or identifier: ${content.token}`;
      }
    }
    if (resp.ok && resp.data) {
      callback?.({
        text: format2(resp.data),
        content: {
          success: true,
          tokenInfo
        },
        source: "FlowBlockchain"
      });
    } else {
      const errMsg = resp.error ?? resp.errorMessage ?? "Unknown error";
      elizaLogger4.error("Error:", errMsg);
      callback?.({
        text: `Failed to get token info of $${content.symbol ?? "UKN"} - ${content.token}(${content.vm}): ${resp.error}`,
        content: {
          error: errMsg
        },
        source: "FlowBlockchain"
      });
    }
    elizaLogger4.log(`Finished ${this.name} handler.`);
    return resp;
  }
};
GetTokenInfoAction = _ts_decorate4([
  injectable4(),
  _ts_param3(0, inject3(CacheProvider)),
  _ts_metadata4("design:type", Function),
  _ts_metadata4("design:paramtypes", [
    typeof CacheProvider === "undefined" ? Object : CacheProvider
  ])
], GetTokenInfoAction);
var TOKEN_LIST_REQUEST_URLS = {
  mainnet: "https://raw.githubusercontent.com/fixes-world/token-list-jsons/refs/heads/main/jsons/mainnet/flow/reviewers/0xa2de93114bae3e73.json",
  testnet: "https://raw.githubusercontent.com/fixes-world/token-list-jsons/refs/heads/main/jsons/testnet/flow/default.json"
};
var fetchTokenList = /* @__PURE__ */ __name(async (network) => {
  const jsonUrl = TOKEN_LIST_REQUEST_URLS[network];
  if (!jsonUrl) {
    return [];
  }
  const response = await fetch(jsonUrl);
  try {
    const rawdata = await response.json();
    return rawdata?.tokens ?? [];
  } catch (error) {
    elizaLogger4.error("Error fetching token list:", error.message);
  }
  return [];
}, "fetchTokenList");
var format2 = /* @__PURE__ */ __name((token) => `### Token Details

${token.logoURI?.startsWith("http") ? `![${token.name}](${token.logoURI})` : ""}
Symbol: $${token.symbol}
Name: ${token.name}
Decimals: ${token.decimals}
Total Supply: ${token.totalSupply}

EVM contract address: ${token.addressEVM ?? "unknown"}
Cadence identifier: ${token.identifierCadence ?? "unknown"}

Price in FLOW: ${token.priceInFLOW ?? "unknown"}
Market Cap in FLOW: ${token.mcapValueInFLOW ?? "unknown"}
`, "format");
globalContainer4.bind(GetTokenInfoAction).toSelf();

// src/actions/ensure-user-account-exists.ts
import { inject as inject4, injectable as injectable5 } from "inversify";
import { elizaLogger as elizaLogger5 } from "@elizaos/core";
import { globalContainer as globalContainer5 } from "@elizaos-plugins/plugin-di";
import { FlowWalletService as FlowWalletService2 } from "@elizaos-plugins/plugin-flow";
function _ts_decorate5(decorators, target, key, desc) {
  var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
  if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
  else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
  return c > 3 && r && Object.defineProperty(target, key, r), r;
}
__name(_ts_decorate5, "_ts_decorate");
function _ts_metadata5(k, v) {
  if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
}
__name(_ts_metadata5, "_ts_metadata");
function _ts_param4(paramIndex, decorator) {
  return function(target, key) {
    decorator(target, key, paramIndex);
  };
}
__name(_ts_param4, "_ts_param");
var EnsureUserAccountExistsAction = class {
  static {
    __name(this, "EnsureUserAccountExistsAction");
  }
  walletSerivce;
  acctPoolService;
  name;
  similes;
  description;
  examples;
  suppressInitialMessage;
  constructor(walletSerivce, acctPoolService) {
    this.walletSerivce = walletSerivce;
    this.acctPoolService = acctPoolService;
    this.name = "FETCH_ACCOUNT_INFO";
    this.similes = [
      "ENSURE_USER_ACCOUNT",
      "ENSURE_USER_ACCOUNT_EXISTS",
      "ENSURE_CHILD_ACCOUNT",
      "ENSURE_CHILD_ACCOUNT_EXISTS",
      "GET_USER_ACCOUNT_INFO",
      "GET_AGENT_ACCOUNT_INFO"
    ];
    this.description = "Call this action to ensure user or agent's wallet account existing on Flow blockchain, and obtain the current wallet account information of it.";
    this.examples = [
      [
        {
          user: "{{user1}}",
          content: {
            text: "Create a new wallet for me.",
            action: "ENSURE_USER_ACCOUNT"
          }
        }
      ],
      [
        {
          user: "{{user1}}",
          content: {
            text: "Check if I have a wallet, if not, create one.",
            action: "ENSURE_USER_ACCOUNT"
          }
        }
      ],
      [
        {
          user: "{{user1}}",
          content: {
            text: "Tell me about my Flow account, if no walelt, please create one.",
            action: "GET_USER_ACCOUNT_INFO"
          }
        }
      ],
      [
        {
          user: "{{user1}}",
          content: {
            text: "What's your wallet status?"
          }
        },
        {
          user: "{{user2}}",
          content: {
            text: "Let me check my wallet status.",
            action: "GET_AGENT_ACCOUNT_INFO"
          }
        }
      ],
      [
        {
          user: "{{user1}}",
          content: {
            text: "What's your balance?"
          }
        },
        {
          user: "{{user2}}",
          content: {
            text: "Let me check my wallet status.",
            action: "GET_AGENT_ACCOUNT_INFO"
          }
        }
      ]
    ];
    this.suppressInitialMessage = true;
  }
  /**
   * Validate if the action can be executed
   */
  async validate(_runtime, message) {
    if (!this.walletSerivce.isInitialized) {
      return false;
    }
    const content = typeof message.content === "string" ? message.content : message.content?.text;
    if (!content) return false;
    const keywords = [
      "create",
      "wallet",
      "account",
      "info",
      "balance",
      "status",
      "\u521B\u5EFA",
      "\u8D26\u53F7",
      "\u94B1\u5305",
      "\u4F59\u989D",
      "\u8D26\u6237"
    ];
    return keywords.some((keyword) => content.toLowerCase().includes(keyword.toLowerCase()));
  }
  /**
   * Execute the transfer action
   *
   * @param content the content from processMessages
   * @param callback the callback function to pass the result to Eliza runtime
   * @returns the transaction response
   */
  async handler(runtime, message, _state, _options, callback) {
    elizaLogger5.log(`Starting ${this.name} handler...`);
    const content = typeof message.content === "string" ? message.content : message.content?.text;
    const keywords = [
      "you",
      "your",
      "agent",
      "agent's",
      "\u4F60",
      "\u4F60\u7684",
      "\u4EE3\u7406"
    ];
    const isQueryAgent = keywords.some((keyword) => content.toLowerCase().includes(keyword));
    const userId = message.userId;
    const isSelf = message.userId === runtime.agentId || isQueryAgent;
    const mainAddr = this.walletSerivce.address;
    const accountName = `Account[${mainAddr}/${isSelf ? "root" : userId}]`;
    let acctInfo;
    try {
      elizaLogger5.debug("Querying account info for", accountName);
      acctInfo = await this.acctPoolService.queryAccountInfo(isSelf ? null : userId);
    } catch (e) {
      elizaLogger5.error("Error:", e);
      callback?.({
        text: `Unable to fetch info for ${accountName}.`,
        content: {
          error: e.message
        },
        source: "FlowBlockchain"
      });
      return;
    }
    if (acctInfo) {
      callback?.({
        text: isSelf ? formater_exports.formatAgentWalletInfo(runtime.character, acctInfo) : formater_exports.formatWalletInfo(userId, accountName, acctInfo),
        content: {
          success: true,
          exists: true,
          info: acctInfo
        },
        source: "FlowBlockchain"
      });
      return;
    }
    try {
      const resp = await new Promise((resolve, reject) => {
        let txResp;
        this.acctPoolService.createNewAccount(userId, {
          onFinalized: /* @__PURE__ */ __name(async (txId, status, errorMsg) => {
            if (errorMsg) {
              reject(new Error(`Error in the creation transaction: ${errorMsg}`));
              return;
            }
            const addressCreateEvt = status.events.find((e) => e.type === "flow.AccountCreated");
            if (addressCreateEvt) {
              const address = addressCreateEvt.data.address;
              elizaLogger5.log(`Account created for ${userId} at ${address}`);
              resolve({
                txId: txResp?.txId ?? txId,
                keyIndex: txResp?.index,
                address
              });
            } else {
              reject(new Error("No account created event found."));
            }
          }, "onFinalized")
        }).then((tx) => {
          txResp = tx;
        }).catch((e) => reject(e));
      });
      callback?.({
        text: formater_exports.formatWalletCreated(message.userId, accountName, resp.address),
        content: resp,
        source: "FlowBlockchain"
      });
    } catch (e) {
      callback?.({
        text: `Failed to create account for ${accountName}, maybe the account already exists.`,
        content: {
          error: e.message
        },
        source: "FlowBlockchain"
      });
    }
    elizaLogger5.log(`Completed ${this.name} handler.`);
  }
};
EnsureUserAccountExistsAction = _ts_decorate5([
  injectable5(),
  _ts_param4(0, inject4(FlowWalletService2)),
  _ts_param4(1, inject4(AccountsPoolService)),
  _ts_metadata5("design:type", Function),
  _ts_metadata5("design:paramtypes", [
    typeof FlowWalletService2 === "undefined" ? Object : FlowWalletService2,
    typeof AccountsPoolService === "undefined" ? Object : AccountsPoolService
  ])
], EnsureUserAccountExistsAction);
globalContainer5.bind(EnsureUserAccountExistsAction).toSelf();

// src/actions/ensure-token-registered.ts
import { injectable as injectable6 } from "inversify";
import { z as z4 } from "zod";
import { elizaLogger as elizaLogger6 } from "@elizaos/core";
import { property as property4, globalContainer as globalContainer6 } from "@elizaos-plugins/plugin-di";
import { isCadenceIdentifier as isCadenceIdentifier2, isEVMAddress as isEVMAddress2, BaseFlowInjectableAction as BaseFlowInjectableAction4 } from "@elizaos-plugins/plugin-flow";
function _ts_decorate6(decorators, target, key, desc) {
  var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
  if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
  else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
  return c > 3 && r && Object.defineProperty(target, key, r), r;
}
__name(_ts_decorate6, "_ts_decorate");
function _ts_metadata6(k, v) {
  if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
}
__name(_ts_metadata6, "_ts_metadata");
var Content = class {
  static {
    __name(this, "Content");
  }
  token;
  vm;
  bridging;
};
_ts_decorate6([
  property4({
    description: "Cadence Resource Identifier or ERC20 contract address (if not native token).",
    examples: [
      "For Cadence resource identifier, the field should be 'A.1654653399040a61.ContractName'",
      "For ERC20 contract address, the field should be '0xe6ffc15a5bde7dd33c127670ba2b9fcb82db971a'"
    ],
    schema: z4.string()
  }),
  _ts_metadata6("design:type", String)
], Content.prototype, "token", void 0);
_ts_decorate6([
  property4({
    description: "The blockchain VM type. This field should be either 'flow' or 'evm' according to the token type.",
    examples: [
      "If token field is Cadence resource identifier, the vm field should be 'flow'",
      "If token field is ERC20 contract address, the vm field should be 'evm'"
    ],
    schema: z4.string().refine((vm) => [
      "flow",
      "evm"
    ].includes(vm))
  }),
  _ts_metadata6("design:type", String)
], Content.prototype, "vm", void 0);
_ts_decorate6([
  property4({
    description: "The bridging requirement. If user mentioned the token doesn't need to be bridged, set this field to false. Default is true.",
    examples: [],
    schema: z4.boolean().default(true)
  }),
  _ts_metadata6("design:type", Boolean)
], Content.prototype, "bridging", void 0);
var option = {
  name: "ENSURE_TOKEN_REGISTERED",
  similes: [
    "ENSURE_NFT_REGISTERED",
    "REGISTER_TOKEN",
    "REGISTER_NFT",
    "REGISTER_FT"
  ],
  description: "Call this action to ensure any fungible token/coin or non-fungible token(NFT) be registered in the TokenList on Flow blockchain.",
  examples: [
    [
      {
        user: "{{user1}}",
        content: {
          text: "Register token A.1654653399040a61.FlowToken, no need to bridge",
          action: "ENSURE_TOKEN_REGISTERED"
        }
      }
    ],
    [
      {
        user: "{{user1}}",
        content: {
          text: "Register token 0xb73bf8e6a4477a952e0338e6cc00cc0ce5ad04ba to Tokenlist",
          action: "ENSURE_TOKEN_REGISTERED"
        }
      }
    ]
  ],
  contentClass: Content,
  suppressInitialMessage: true
};
var EnsureTokenRegisteredAction = class extends BaseFlowInjectableAction4 {
  static {
    __name(this, "EnsureTokenRegisteredAction");
  }
  constructor() {
    super(option);
  }
  /**
   * Validate if the action can be executed
   */
  async validate(_runtime, message) {
    if (!this.walletSerivce.isInitialized) {
      return false;
    }
    const content = typeof message.content === "string" ? message.content : message.content?.text;
    if (!content) return false;
    const keywords = [
      "token",
      "register",
      "tokenlist",
      "token-list",
      "nftlist",
      "nft-list"
    ];
    return keywords.some((keyword) => content.toLowerCase().includes(keyword.toLowerCase()));
  }
  /**
   * Execute the action
   *
   * @param content the content from processMessages
   * @param callback the callback function to pass the result to Eliza runtime
   * @returns the transaction response
   */
  async execute(content, runtime, message, _state, callback) {
    if (!content) {
      elizaLogger6.warn("No content generated");
      return;
    }
    elizaLogger6.log(`Starting ${this.name} handler...`);
    const userId = message.userId;
    const isSelf = message.userId === runtime.agentId;
    const mainAddr = this.walletSerivce.address;
    const accountName = `Account[${mainAddr}/${isSelf ? "root" : userId}]`;
    let isRegistered = false;
    let errorMsg = void 0;
    let address;
    let contractName;
    if (isCadenceIdentifier2(content.token) && content.vm === "flow") {
      const [_, tokenAddr, tokenContractName] = content.token.split(".");
      address = `0x${tokenAddr}`;
      contractName = tokenContractName;
      elizaLogger6.debug(`${accountName}
 Check A.${tokenAddr}.${tokenContractName} in TokenList...`);
      try {
        isRegistered = await this.walletSerivce.executeScript(scripts.isTokenRegistered, (arg, t) => [
          arg(address, t.Address),
          arg(contractName, t.String)
        ], false);
      } catch (e) {
        elizaLogger6.error("Error in checking token registration:", e);
        errorMsg = e.message;
      }
    } else if (isEVMAddress2(content.token) && content.vm === "evm") {
      elizaLogger6.debug(`${accountName}
 Check ${content.token} in EVMTokenList...`);
      address = content.token;
      try {
        isRegistered = await this.walletSerivce.executeScript(scripts.isEVMAssetRegistered, (arg, t) => [
          arg(content.token.toLowerCase(), t.String)
        ], false);
      } catch (e) {
        elizaLogger6.error("Error in checking token registration:", e);
        errorMsg = e.message;
      }
    } else {
      errorMsg = `Invalid token format or wrong VM type: ${content.token} (${content.vm})`;
    }
    if (errorMsg) {
      callback?.({
        text: `Unable to fetch info for ${content.token}.`,
        content: {
          error: errorMsg
        },
        source: "FlowBlockchain"
      });
      return;
    }
    if (isRegistered) {
      callback?.({
        text: `Token ${content.token} is already registered in TokenList.`,
        content: {
          exists: true
        },
        source: "FlowBlockchain"
      });
      return;
    }
    try {
      const resp = await new Promise((resolve, reject) => {
        const transactionCallbacks = {
          onFinalized: /* @__PURE__ */ __name(async (txId, status, errorMsg2) => {
            if (errorMsg2) {
              reject(new Error(`Error in the creation transaction: ${errorMsg2}`));
              return;
            }
            const validEventNames = [
              "EVMTokenList.EVMBridgedAssetRegistered",
              "TokenList.FungibleTokenRegistered",
              "NFTList.NFTCollectionRegistered"
            ];
            let fromAddress = "";
            let flowSpent = 0;
            let gasFeeSpent = 0;
            let hasValidEvent = false;
            let evmBridged = false;
            for (const evt of status.events) {
              if (!hasValidEvent) {
                const [_1, _2, contractName2, eventName] = evt.type.split(".");
                hasValidEvent = validEventNames.includes(`${contractName2}.${eventName}`);
              }
              if (evt.type.endsWith("FlowToken.TokensWithdrawn") && evt.data.from !== this.walletSerivce.address) {
                fromAddress = evt.data.from;
                flowSpent += Number.parseFloat(evt.data.amount);
              }
              if (evt.type.endsWith("FlowFees.FeesDeducted")) {
                gasFeeSpent += Number.parseFloat(evt.data.amount);
              }
              if (evt.type.endsWith("FlowEVMBridge.BridgeDefiningContractDeployed")) {
                evmBridged = true;
              }
            }
            if (hasValidEvent) {
              elizaLogger6.log(`Token registered successfully: ${content.token}`);
              resolve({
                success: true,
                txid: txId,
                evmBridged,
                from: fromAddress,
                flowSpent,
                gasFeeSpent
              });
            } else {
              elizaLogger6.log(`Failed to register token: ${content.token}, no valid event found.`);
              resolve({
                success: false,
                txid: txId,
                evmBridged,
                from: fromAddress,
                flowSpent,
                gasFeeSpent
              });
            }
          }, "onFinalized")
        };
        let transaction;
        if (content.vm === "flow") {
          if (content.bridging) {
            transaction = this.walletSerivce.sendTransaction(transactions.tlRegisterCadenceAsset, (arg, t) => [
              arg(address, t.Address),
              arg(contractName, t.String),
              arg(userId, t.String)
            ], transactionCallbacks);
          } else {
            transaction = this.walletSerivce.sendTransaction(transactions.tlRegisterCadenceAssetNoBridge, (arg, t) => [
              arg(address, t.Address),
              arg(contractName, t.String)
            ], transactionCallbacks);
          }
        } else {
          transaction = this.walletSerivce.sendTransaction(transactions.tlRegisterEVMAsset, (arg, t) => [
            arg(content.token, t.String),
            arg(userId, t.String)
          ], transactionCallbacks);
        }
        transaction.catch((e) => reject(e));
      });
      const flowSpentInfo = formater_exports.formatFlowSpent(resp.from, resp.flowSpent, this.walletSerivce.address, resp.gasFeeSpent);
      const prefix = `Operator: ${accountName}
${flowSpentInfo}
`;
      const finalMsg = resp.success ? `${prefix}
  Token ${content.token} registered successfully.` : resp.evmBridged ? `${prefix}
  Token has just bridged from EVM side, you need send another transaction to register it in TokenList.` : `${prefix}
  Failed to register token, no valid event found.`;
      callback?.({
        text: formater_exports.formatTransationSent(resp.txid, this.walletSerivce.connector.network, finalMsg),
        content: resp,
        source: "FlowBlockchain"
      });
    } catch (e) {
      callback?.({
        text: `Operator: ${accountName}
 Failed to register token, Error: ${e.message}`,
        content: {
          error: e.message
        },
        source: "FlowBlockchain"
      });
    }
    elizaLogger6.log(`Finished ${this.name} handler.`);
  }
};
EnsureTokenRegisteredAction = _ts_decorate6([
  injectable6(),
  _ts_metadata6("design:type", Function),
  _ts_metadata6("design:paramtypes", [])
], EnsureTokenRegisteredAction);
globalContainer6.bind(EnsureTokenRegisteredAction).toSelf();

// src/plugin.ts
import { FlowWalletService as FlowWalletService3 } from "@elizaos-plugins/plugin-flow";

// src/providers/account.provider.ts
import { injectable as injectable7, inject as inject5 } from "inversify";
import { elizaLogger as elizaLogger7 } from "@elizaos/core";
import { globalContainer as globalContainer7 } from "@elizaos-plugins/plugin-di";
function _ts_decorate7(decorators, target, key, desc) {
  var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
  if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
  else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
  return c > 3 && r && Object.defineProperty(target, key, r), r;
}
__name(_ts_decorate7, "_ts_decorate");
function _ts_metadata7(k, v) {
  if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
}
__name(_ts_metadata7, "_ts_metadata");
function _ts_param5(paramIndex, decorator) {
  return function(target, key) {
    decorator(target, key, paramIndex);
  };
}
__name(_ts_param5, "_ts_param");
var AccountProvider = class {
  static {
    __name(this, "AccountProvider");
  }
  acctPoolService;
  constructor(acctPoolService) {
    this.acctPoolService = acctPoolService;
  }
  /**
   * Eliza provider `get` method
   * @returns The message to be injected into the context
   */
  async get(_runtime, message, state) {
    const userId = message.userId;
    if (state) {
      const PROVIDER_SESSION_FLAG = `account-provider-session:${userId}`;
      if (state[PROVIDER_SESSION_FLAG]) {
        return null;
      }
      state[PROVIDER_SESSION_FLAG] = true;
    }
    try {
      const isSelf = message.userId === message.agentId;
      const acctInfo = await this.acctPoolService.queryAccountInfo(isSelf ? void 0 : userId);
      const accountName = `Account[${this.acctPoolService.mainAddress}/${isSelf ? "root" : userId}]`;
      return formater_exports.formatWalletInfo(userId, accountName, acctInfo);
    } catch (error) {
      elizaLogger7.error("Error in Account provider:", error.message);
    }
    return null;
  }
};
AccountProvider = _ts_decorate7([
  injectable7(),
  _ts_param5(0, inject5(AccountsPoolService)),
  _ts_metadata7("design:type", Function),
  _ts_metadata7("design:paramtypes", [
    typeof AccountsPoolService === "undefined" ? Object : AccountsPoolService
  ])
], AccountProvider);
globalContainer7.bind(AccountProvider).toSelf().inRequestScope();

// src/plugin.ts
var basicFlowPlugin = {
  name: "flow-basic",
  description: "Flow Plugin for Eliza with accounts management features.",
  actions: [
    TransferAction,
    GetPriceAction,
    GetTokenInfoAction,
    EnsureUserAccountExistsAction,
    EnsureTokenRegisteredAction
  ],
  providers: [
    AccountProvider
  ],
  evaluators: [],
  services: [
    FlowWalletService3,
    AccountsPoolService
  ]
};

// src/index.ts
var index_default = basicFlowPlugin;
export {
  Content,
  EnsureTokenRegisteredAction,
  EnsureUserAccountExistsAction,
  GetPriceAction,
  GetPriceContent,
  GetTokenInfoAction,
  GetTokenInfoContent,
  TransferAction,
  TransferContent,
  basicFlowPlugin,
  index_default as default,
  scripts
};
//# sourceMappingURL=index.js.map