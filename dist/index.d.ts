import { Service, ServiceType, IAgentRuntime, Memory, State, HandlerCallback, Action, ActionExample } from '@elizaos/core';
import { FlowWalletService, FlowAccountBalanceInfo, TransactionCallbacks, TransactionSentResponse, BaseFlowInjectableAction, ScriptQueryResponse, CacheProvider } from '@elizaos-plugins/plugin-flow';
import { PluginOptions } from '@elizaos-plugins/plugin-di';

declare module "@elizaos/core" {
    enum ServiceType {
        ACCOUNTS_POOL = "accounts-pool"
    }
}
/**
 * Wallet provider
 */
declare class AccountsPoolService extends Service {
    private readonly walletService;
    constructor(walletService: FlowWalletService);
    static get serviceType(): ServiceType;
    initialize(_runtime: IAgentRuntime): Promise<void>;
    /**
     * Get the main address of the wallet
     */
    get mainAddress(): string;
    /**
     * Get the main account status
     */
    getMainAccountStatus(): Promise<{
        address: any;
        balance: number;
        childrenAmount: number;
    }>;
    /**
     * Check if the address is a child of the agent
     * @param address
     */
    checkAddressIsChildOfAgent(address: string): Promise<boolean>;
    /**
     * Query account info
     * @param userId
     * @returns
     */
    queryAccountInfo(userId?: string): Promise<FlowAccountBalanceInfo | undefined>;
    /**
     * Create a new account
     * @param userId
     * @returns
     */
    createNewAccount(userId: string, callbacks?: TransactionCallbacks, initalFunding?: number): Promise<TransactionSentResponse>;
    /**
     * Transfer FlowToken to another account from the user's account
     * @param fromUserId
     */
    transferFlowToken(fromUserId: string, recipient: string, amount: number, callbacks?: TransactionCallbacks): Promise<TransactionSentResponse>;
    /**
     * Transfer Cadence Generic FT to another account from the user's account
     * @param fromUserId
     * @param recipient
     * @param amount
     * @param tokenFTAddr
     * @param tokenContractName
     * @param callbacks
     */
    transferGenericFT(fromUserId: string, recipient: string, amount: number, tokenFTAddr: string, tokenContractName: string, callbacks?: TransactionCallbacks): Promise<TransactionSentResponse>;
    /**
     * Transfer ERC20 token to another account from the user's account
     * @param fromUserId
     * @param recipient
     * @param amount
     * @param callback
     */
    transferERC20(fromUserId: string, recipient: string, amount: number, erc20Contract: string, callbacks?: TransactionCallbacks): Promise<TransactionSentResponse>;
}

/**
 * The generated content for the transfer action
 */
declare class TransferContent {
    token: string | null;
    amount: string;
    to: string;
}
/**
 * Transfer action
 *
 * @category Actions
 * @description Transfer funds from one account to another
 */
declare class TransferAction extends BaseFlowInjectableAction<TransferContent> {
    private readonly acctPoolService;
    constructor(acctPoolService: AccountsPoolService);
    /**
     * Validate the transfer action
     * @param runtime the runtime instance
     * @param message the message content
     * @param state the state object
     */
    validate(runtime: IAgentRuntime, message: Memory, state?: State): Promise<boolean>;
    /**
     * Execute the transfer action
     *
     * @param content the content from processMessages
     * @param callback the callback function to pass the result to Eliza runtime
     * @returns the transaction response
     */
    execute(content: TransferContent | null, _runtime: IAgentRuntime, message: Memory, _state?: State, callback?: HandlerCallback): Promise<void>;
}

/**
 * The generated content for the transfer action
 */
declare class GetPriceContent {
    token: string;
}
/**
 * Get price action
 *
 * @category Actions
 * @description Get the current price of FLOW token or stFLOW token
 */
declare class GetPriceAction extends BaseFlowInjectableAction<GetPriceContent> {
    constructor();
    /**
     * Validate if the action can be executed
     */
    validate(_runtime: IAgentRuntime, message: Memory, _state?: State): Promise<boolean>;
    /**
     * Execute the transfer action
     *
     * @param content the content from processMessages
     * @param callback the callback function to pass the result to Eliza runtime
     * @returns the transaction response
     */
    execute(content: GetPriceContent | null, _runtime: IAgentRuntime, _message: Memory, _state?: State, callback?: HandlerCallback): Promise<ScriptQueryResponse | null>;
}

/**
 * The generated content for the transfer action
 */
declare class GetTokenInfoContent {
    symbol: string;
    token: string | null;
    vm: "flow" | "evm";
}
/**
 * Get price action
 *
 * @category Actions
 * @description Get the current price of FLOW token or stFLOW token
 */
declare class GetTokenInfoAction extends BaseFlowInjectableAction<GetTokenInfoContent> {
    private readonly cache;
    constructor(cache: CacheProvider);
    /**
     * Validate if the action can be executed
     */
    validate(_runtime: IAgentRuntime, message: Memory, _state?: State): Promise<boolean>;
    /**
     * Execute the transfer action
     *
     * @param content the content from processMessages
     * @param callback the callback function to pass the result to Eliza runtime
     * @returns the transaction response
     */
    execute(content: GetTokenInfoContent | null, _runtime: IAgentRuntime, _message: Memory, _state?: State, callback?: HandlerCallback): Promise<ScriptQueryResponse | null>;
}

/**
 * Ensure user account exists
 *
 * @category Actions
 * @description Ensure user account exists on Flow blockchain
 */
declare class EnsureUserAccountExistsAction implements Action {
    private readonly walletSerivce;
    private readonly acctPoolService;
    readonly name: string;
    readonly similes: string[];
    readonly description: string;
    readonly examples: ActionExample[][];
    readonly suppressInitialMessage: boolean;
    constructor(walletSerivce: FlowWalletService, acctPoolService: AccountsPoolService);
    /**
     * Validate if the action can be executed
     */
    validate(_runtime: IAgentRuntime, message: Memory): Promise<boolean>;
    /**
     * Execute the transfer action
     *
     * @param content the content from processMessages
     * @param callback the callback function to pass the result to Eliza runtime
     * @returns the transaction response
     */
    handler(runtime: IAgentRuntime, message: Memory, _state?: State, _options?: Record<string, unknown>, callback?: HandlerCallback): Promise<void>;
}

/**
 * The generated content for the transfer action
 */
declare class Content {
    token: string;
    vm: "flow" | "evm";
    bridging: boolean;
}
/**
 * Ensure token registered in TokenList
 *
 * @category Actions
 * @description Ensure token registered in TokenList on Flow blockchain
 */
declare class EnsureTokenRegisteredAction extends BaseFlowInjectableAction<Content> {
    constructor();
    /**
     * Validate if the action can be executed
     */
    validate(_runtime: IAgentRuntime, message: Memory): Promise<boolean>;
    /**
     * Execute the action
     *
     * @param content the content from processMessages
     * @param callback the callback function to pass the result to Eliza runtime
     * @returns the transaction response
     */
    execute(content: Content | null, runtime: IAgentRuntime, message: Memory, _state?: State, callback?: HandlerCallback): Promise<void>;
}

/**
 * Advanced Flow Plugin configuration
 * Required for the plugin to be loaded, will be exported as default
 */
declare const advancedFlowPlugin: PluginOptions;

declare const scripts: {
    getFlowPrice: any;
    getStFlowPrice: any;
    getTokenInfoCadence: any;
    getTokenInfoEVM: any;
    getAccountInfoFrom: any;
    getAccountStatus: any;
    isAddressChildOf: any;
    isTokenRegistered: any;
    isEVMAssetRegistered: any;
};

export { Content, EnsureTokenRegisteredAction, EnsureUserAccountExistsAction, GetPriceAction, GetPriceContent, GetTokenInfoAction, GetTokenInfoContent, TransferAction, TransferContent, advancedFlowPlugin, advancedFlowPlugin as default, scripts };
