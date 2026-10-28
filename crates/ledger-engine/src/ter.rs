//! Transaction result codes and their messages: `engine_result_code` and
//! `engine_result_message` in subscription messages. The `transResults` table
//! from `src/libxrpl/protocol/TER.cpp` in xrpld 3.4.1; codes checked against
//! `server_definitions` from a node of the same version.

/// (name, code, message), sorted by name.
const RESULTS: &[(&str, i32, &str)] = &[
    (
        "tecAMM_ACCOUNT",
        168,
        "This operation is not allowed on an AMM Account.",
    ),
    ("tecAMM_BALANCE", 163, "AMM has invalid balance."),
    ("tecAMM_EMPTY", 166, "AMM is in empty state."),
    ("tecAMM_FAILED", 164, "AMM transaction failed."),
    ("tecAMM_INVALID_TOKENS", 165, "AMM invalid LP tokens."),
    ("tecAMM_NOT_EMPTY", 167, "AMM is not in empty state."),
    ("tecARRAY_EMPTY", 190, "Array is empty."),
    ("tecARRAY_TOO_LARGE", 191, "Array is too large."),
    ("tecBAD_CREDENTIALS", 193, "Bad credentials."),
    ("tecBAD_PROOF", 199, "Proof cannot be verified"),
    (
        "tecCANT_ACCEPT_OWN_NFTOKEN_OFFER",
        158,
        "An NFToken offer cannot be claimed by its owner.",
    ),
    ("tecCLAIM", 100, "Fee claimed. Sequence used. No action."),
    (
        "tecCRYPTOCONDITION_ERROR",
        146,
        "Malformed, invalid, or mismatched conditional or fulfillment.",
    ),
    ("tecDIR_FULL", 121, "Can not add entry to full directory."),
    ("tecDST_TAG_NEEDED", 143, "A destination tag is required."),
    ("tecDUPLICATE", 149, "Ledger object already exists."),
    (
        "tecEMPTY_DID",
        187,
        "The DID object did not have a URI or DIDDocument field.",
    ),
    ("tecEXPIRED", 148, "Expiration time is passed."),
    (
        "tecFAILED_PROCESSING",
        105,
        "Failed to correctly process transaction.",
    ),
    ("tecFROZEN", 137, "Asset is frozen."),
    (
        "tecHAS_OBLIGATIONS",
        151,
        "The account cannot be deleted since it has obligations.",
    ),
    (
        "tecINCOMPLETE",
        169,
        "Some work was completed, but more submissions required to finish.",
    ),
    (
        "tecINSUFFICIENT_FUNDS",
        159,
        "Not enough funds available to complete requested transaction.",
    ),
    (
        "tecINSUFFICIENT_PAYMENT",
        161,
        "The payment is not sufficient.",
    ),
    (
        "tecINSUFFICIENT_RESERVE",
        141,
        "Insufficient reserve to complete requested operation.",
    ),
    ("tecINSUFF_FEE", 136, "Insufficient balance to pay fee."),
    (
        "tecINSUF_RESERVE_LINE",
        122,
        "Insufficient reserve to add trust line.",
    ),
    (
        "tecINSUF_RESERVE_OFFER",
        123,
        "Insufficient reserve to create offer.",
    ),
    (
        "tecINTERNAL",
        144,
        "An internal error has occurred during processing.",
    ),
    (
        "tecINVALID_UPDATE_TIME",
        188,
        "The Oracle object has invalid LastUpdateTime field.",
    ),
    (
        "tecINVARIANT_FAILED",
        147,
        "One or more invariants for the transaction were not satisfied.",
    ),
    (
        "tecKILLED",
        150,
        "No funds transferred and no offer created.",
    ),
    ("tecLIMIT_EXCEEDED", 195, "Limit exceeded."),
    ("tecLOCKED", 192, "Fund is locked."),
    (
        "tecMAX_SEQUENCE_REACHED",
        154,
        "The maximum sequence number was reached.",
    ),
    (
        "tecNEED_MASTER_KEY",
        142,
        "The operation requires the use of the Master Key.",
    ),
    (
        "tecNFTOKEN_BUY_SELL_MISMATCH",
        156,
        "The 'Buy' and 'Sell' NFToken offers are mismatched.",
    ),
    (
        "tecNFTOKEN_OFFER_TYPE_MISMATCH",
        157,
        "The type of NFToken offer is incorrect.",
    ),
    (
        "tecNO_ALTERNATIVE_KEY",
        130,
        "The operation would remove the ability to sign transactions with the account.",
    ),
    ("tecNO_AUTH", 134, "Not authorized to hold asset."),
    (
        "tecNO_DST",
        124,
        "Destination does not exist. Send XRP to create it.",
    ),
    (
        "tecNO_DST_INSUF_XRP",
        125,
        "Destination does not exist. Too little XRP sent to create it.",
    ),
    ("tecNO_ENTRY", 140, "No matching entry found."),
    ("tecNO_ISSUER", 133, "Issuer account does not exist."),
    ("tecNO_LINE", 135, "No such line."),
    (
        "tecNO_LINE_INSUF_RESERVE",
        126,
        "No such line. Too little reserve to create it.",
    ),
    (
        "tecNO_LINE_REDUNDANT",
        127,
        "Can't set non-existent line to default.",
    ),
    (
        "tecNO_PERMISSION",
        139,
        "No permission to perform requested operation.",
    ),
    ("tecNO_REGULAR_KEY", 131, "Regular key is not set."),
    (
        "tecNO_SPONSOR_PERMISSION",
        200,
        "Sponsor has not authorized this transaction.",
    ),
    (
        "tecNO_SUITABLE_NFTOKEN_PAGE",
        155,
        "A suitable NFToken page could not be located.",
    ),
    ("tecNO_TARGET", 138, "Target account does not exist."),
    (
        "tecOBJECT_NOT_FOUND",
        160,
        "A requested object could not be located.",
    ),
    ("tecOVERSIZE", 145, "Object exceeded serialization limits."),
    ("tecOWNERS", 132, "Non-zero owner count."),
    ("tecPATH_DRY", 128, "Path could not send partial amount."),
    ("tecPATH_PARTIAL", 101, "Path could not send full amount."),
    (
        "tecPRECISION_LOSS",
        197,
        "The amounts used by the transaction cannot interact.",
    ),
    (
        "tecPSEUDO_ACCOUNT",
        196,
        "This operation is not allowed against a pseudo-account.",
    ),
    (
        "tecTOKEN_PAIR_NOT_FOUND",
        189,
        "Token pair is not found in Oracle object.",
    ),
    (
        "tecTOO_SOON",
        152,
        "It is too early to attempt the requested operation. Please wait.",
    ),
    (
        "tecUNFUNDED",
        129,
        "Not enough XRP to satisfy the reserve requirement.",
    ),
    ("tecUNFUNDED_ADD", 102, "DEPRECATED."),
    ("tecUNFUNDED_AMM", 162, "Insufficient balance to fund AMM."),
    (
        "tecUNFUNDED_OFFER",
        103,
        "Insufficient balance to fund created offer.",
    ),
    (
        "tecUNFUNDED_PAYMENT",
        104,
        "Insufficient XRP balance to send.",
    ),
    ("tecWRONG_ASSET", 194, "Wrong asset given."),
    (
        "tecXCHAIN_ACCOUNT_CREATE_PAST",
        181,
        "The account create count has already passed.",
    ),
    (
        "tecXCHAIN_ACCOUNT_CREATE_TOO_MANY",
        182,
        "There are too many pending account create transactions to submit a new one.",
    ),
    ("tecXCHAIN_BAD_CLAIM_ID", 172, "Bad xchain claim id."),
    (
        "tecXCHAIN_BAD_PUBLIC_KEY_ACCOUNT_PAIR",
        185,
        "Bad public key account pair in an xchain transaction.",
    ),
    (
        "tecXCHAIN_BAD_TRANSFER_ISSUE",
        170,
        "Bad xchain transfer issue.",
    ),
    (
        "tecXCHAIN_CLAIM_NO_QUORUM",
        173,
        "Quorum was not reached on the xchain claim.",
    ),
    (
        "tecXCHAIN_CREATE_ACCOUNT_DISABLED",
        186,
        "This bridge does not support account creation.",
    ),
    (
        "tecXCHAIN_CREATE_ACCOUNT_NONXRP_ISSUE",
        175,
        "Only XRP may be used for xchain create account.",
    ),
    (
        "tecXCHAIN_INSUFF_CREATE_AMOUNT",
        180,
        "Insufficient amount to create an account.",
    ),
    ("tecXCHAIN_NO_CLAIM_ID", 171, "No such xchain claim id."),
    (
        "tecXCHAIN_NO_SIGNERS_LIST",
        178,
        "The account did not have a signers list.",
    ),
    (
        "tecXCHAIN_PAYMENT_FAILED",
        183,
        "Failed to transfer funds in a xchain transaction.",
    ),
    (
        "tecXCHAIN_PROOF_UNKNOWN_KEY",
        174,
        "Unknown key for the xchain proof.",
    ),
    (
        "tecXCHAIN_REWARD_MISMATCH",
        177,
        "The reward amount must match the reward specified in the xchain bridge.",
    ),
    (
        "tecXCHAIN_SELF_COMMIT",
        184,
        "Account cannot commit funds to itself.",
    ),
    (
        "tecXCHAIN_SENDING_ACCOUNT_MISMATCH",
        179,
        "The sending account did not match the expected sending account.",
    ),
    (
        "tecXCHAIN_WRONG_CHAIN",
        176,
        "XChain Transaction was submitted to the wrong chain.",
    ),
    (
        "tefALREADY",
        -198,
        "The exact transaction was already in this ledger.",
    ),
    ("tefBAD_ADD_AUTH", -197, "Not authorized to add account."),
    (
        "tefBAD_AUTH",
        -196,
        "Transaction's public key is not authorized.",
    ),
    (
        "tefBAD_AUTH_MASTER",
        -183,
        "Auth for unclaimed account needs correct master key.",
    ),
    ("tefBAD_LEDGER", -195, "Ledger in unexpected state."),
    ("tefBAD_PATH_COUNT", -176, "Malformed: Too many paths."),
    (
        "tefBAD_QUORUM",
        -185,
        "Signatures provided do not meet the quorum.",
    ),
    (
        "tefBAD_SIGNATURE",
        -186,
        "A signature is provided for a non-signer.",
    ),
    ("tefCREATED", -194, "Can't add an already created account."),
    ("tefEXCEPTION", -193, "Unexpected program state."),
    ("tefFAILURE", -199, "Failed to apply."),
    ("tefINTERNAL", -192, "Internal error."),
    (
        "tefINVALID_LEDGER_FIX_TYPE",
        -178,
        "The LedgerFixType field has an invalid value.",
    ),
    (
        "tefINVARIANT_FAILED",
        -182,
        "Fee claim violated invariants for the transaction.",
    ),
    ("tefMASTER_DISABLED", -188, "Master key is disabled."),
    ("tefMAX_LEDGER", -187, "Ledger sequence too high."),
    (
        "tefNFTOKEN_IS_NOT_TRANSFERABLE",
        -179,
        "The specified NFToken is not transferable.",
    ),
    (
        "tefNOT_MULTI_SIGNING",
        -184,
        "Account has no appropriate list of multi-signers.",
    ),
    ("tefNO_AUTH_REQUIRED", -191, "Auth is not required."),
    (
        "tefNO_DST_PARTIAL",
        -177,
        "Partial payment to create account not allowed.",
    ),
    ("tefNO_TICKET", -180, "Ticket is not in ledger."),
    (
        "tefPAST_SEQ",
        -190,
        "This sequence number has already passed.",
    ),
    ("tefTOO_BIG", -181, "Transaction affects too many items."),
    (
        "tefWRONG_PRIOR",
        -189,
        "This previous transaction does not match.",
    ),
    ("telBAD_DOMAIN", -398, "Domain too long."),
    ("telBAD_PATH_COUNT", -397, "Malformed: Too many paths."),
    ("telBAD_PUBLIC_KEY", -396, "Public key is not valid."),
    ("telCAN_NOT_QUEUE", -392, "Can not queue at this time."),
    (
        "telCAN_NOT_QUEUE_BALANCE",
        -391,
        "Can not queue at this time: insufficient balance to pay all queued fees.",
    ),
    (
        "telCAN_NOT_QUEUE_BLOCKED",
        -389,
        "Can not queue at this time: blocking transaction in queue.",
    ),
    (
        "telCAN_NOT_QUEUE_BLOCKS",
        -390,
        "Can not queue at this time: would block later queued transaction(s).",
    ),
    (
        "telCAN_NOT_QUEUE_FEE",
        -388,
        "Can not queue at this time: fee insufficient to replace queued transaction.",
    ),
    (
        "telCAN_NOT_QUEUE_FULL",
        -387,
        "Can not queue at this time: queue is full.",
    ),
    ("telENV_RPC_FAILED", -383, "Unit test RPC failure."),
    (
        "telFAILED_PROCESSING",
        -395,
        "Failed to correctly process transaction.",
    ),
    ("telINSUF_FEE_P", -394, "Fee insufficient."),
    ("telLOCAL_ERROR", -399, "Local failure."),
    (
        "telNETWORK_ID_MAKES_TX_NON_CANONICAL",
        -384,
        "Transactions submitted to this node/network must NOT include a NetworkID field.",
    ),
    (
        "telNO_DST_PARTIAL",
        -393,
        "Partial payment to create account not allowed.",
    ),
    (
        "telREQUIRES_NETWORK_ID",
        -385,
        "Transactions submitted to this node/network must include a correct NetworkID field.",
    ),
    (
        "telWRONG_NETWORK",
        -386,
        "Transaction specifies a Network ID that differs from that of the local node.",
    ),
    ("temARRAY_EMPTY", -253, "Malformed: Array is empty."),
    ("temARRAY_TOO_LARGE", -252, "Malformed: Array is too large."),
    ("temBAD_AMM_TOKENS", -261, "Malformed: Invalid LPTokens."),
    ("temBAD_AMOUNT", -298, "Malformed: Bad amount."),
    ("temBAD_CIPHERTEXT", -248, "Malformed: Invalid ciphertext."),
    ("temBAD_CURRENCY", -297, "Malformed: Bad currency."),
    ("temBAD_EXPIRATION", -296, "Malformed: Bad expiration."),
    ("temBAD_FEE", -295, "Invalid fee, negative or not XRP."),
    ("temBAD_ISSUER", -294, "Malformed: Bad issuer."),
    ("temBAD_LIMIT", -293, "Limits must be non-negative."),
    ("temBAD_MPT", -249, "Malformed: Bad MPT."),
    (
        "temBAD_NFTOKEN_TRANSFER_FEE",
        -262,
        "Malformed: The NFToken transfer fee must be between 1 and 5000, inclusive.",
    ),
    ("temBAD_OFFER", -292, "Malformed: Bad offer."),
    ("temBAD_PATH", -291, "Malformed: Bad path."),
    ("temBAD_PATH_LOOP", -290, "Malformed: Loop in path."),
    ("temBAD_QUORUM", -271, "Malformed: Quorum is unreachable."),
    (
        "temBAD_REGKEY",
        -289,
        "Malformed: Regular key cannot be same as master key.",
    ),
    (
        "temBAD_SEND_XRP_LIMIT",
        -288,
        "Malformed: Limit quality is not allowed for XRP to XRP.",
    ),
    (
        "temBAD_SEND_XRP_MAX",
        -287,
        "Malformed: Send max is not allowed for XRP to XRP.",
    ),
    (
        "temBAD_SEND_XRP_NO_DIRECT",
        -286,
        "Malformed: No Ripple direct is not allowed for XRP to XRP.",
    ),
    (
        "temBAD_SEND_XRP_PARTIAL",
        -285,
        "Malformed: Partial payment is not allowed for XRP to XRP.",
    ),
    (
        "temBAD_SEND_XRP_PATHS",
        -284,
        "Malformed: Paths are not allowed for XRP to XRP.",
    ),
    (
        "temBAD_SEQUENCE",
        -283,
        "Malformed: Sequence is not in the past.",
    ),
    ("temBAD_SIGNATURE", -282, "Malformed: Bad signature."),
    (
        "temBAD_SIGNER",
        -272,
        "Malformed: No signer may duplicate account or other signers.",
    ),
    ("temBAD_SRC_ACCOUNT", -281, "Malformed: Bad source account."),
    (
        "temBAD_TICK_SIZE",
        -269,
        "Malformed: Tick size out of range.",
    ),
    (
        "temBAD_TRANSFER_FEE",
        -251,
        "Malformed: Transfer fee is outside valid range.",
    ),
    (
        "temBAD_TRANSFER_RATE",
        -280,
        "Malformed: Transfer rate must be >= 1.0 and <= 2.0",
    ),
    (
        "temBAD_WEIGHT",
        -270,
        "Malformed: Weight must be a positive value.",
    ),
    (
        "temCANNOT_PREAUTH_SELF",
        -267,
        "Malformed: An account may not preauthorize itself.",
    ),
    (
        "temDISABLED",
        -273,
        "The transaction requires logic that is currently disabled.",
    ),
    ("temDST_IS_SRC", -279, "Destination may not be source."),
    ("temDST_NEEDED", -278, "Destination not specified."),
    ("temEMPTY_DID", -254, "Malformed: No DID data provided."),
    ("temINVALID", -277, "The transaction is ill-formed."),
    (
        "temINVALID_ACCOUNT_ID",
        -268,
        "Malformed: A field contains an invalid account ID.",
    ),
    (
        "temINVALID_COUNT",
        -266,
        "Malformed: Count field outside valid range.",
    ),
    (
        "temINVALID_FLAG",
        -276,
        "The transaction has an invalid flag.",
    ),
    (
        "temINVALID_INNER_BATCH",
        -250,
        "Malformed: Invalid inner batch transaction.",
    ),
    ("temMALFORMED", -299, "Malformed transaction."),
    ("temREDUNDANT", -275, "The transaction is redundant."),
    ("temRIPPLE_EMPTY", -274, "PathSet with no paths."),
    (
        "temSEQ_AND_TICKET",
        -263,
        "Transaction contains a TicketSequence and a non-zero Sequence.",
    ),
    (
        "temUNCERTAIN",
        -265,
        "In process of determining result. Never returned.",
    ),
    (
        "temUNKNOWN",
        -264,
        "The transaction requires logic that is not implemented yet.",
    ),
    (
        "temXCHAIN_BAD_PROOF",
        -259,
        "Malformed: Bad cross-chain claim proof.",
    ),
    (
        "temXCHAIN_BRIDGE_BAD_ISSUES",
        -258,
        "Malformed: Bad bridge issues.",
    ),
    (
        "temXCHAIN_BRIDGE_BAD_MIN_ACCOUNT_CREATE_AMOUNT",
        -256,
        "Malformed: Bad min account create amount.",
    ),
    (
        "temXCHAIN_BRIDGE_BAD_REWARD_AMOUNT",
        -255,
        "Malformed: Bad reward amount.",
    ),
    (
        "temXCHAIN_BRIDGE_NONDOOR_OWNER",
        -257,
        "Malformed: Bridge owner must be one of the door accounts.",
    ),
    (
        "temXCHAIN_EQUAL_DOOR_ACCOUNTS",
        -260,
        "Malformed: Bridge must have unique door accounts.",
    ),
    (
        "terADDRESS_COLLISION",
        -86,
        "Failed to allocate an unique account address.",
    ),
    ("terFUNDS_SPENT", -98, "DEPRECATED."),
    ("terINSUF_FEE_B", -97, "Account balance can't pay fee."),
    ("terLAST", -91, "DEPRECATED."),
    ("terLOCKED", -84, "Fund is locked."),
    ("terNO_ACCOUNT", -96, "The source account does not exist."),
    ("terNO_AMM", -87, "AMM doesn't exist for the asset pair."),
    ("terNO_AUTH", -95, "Not authorized to hold IOUs."),
    (
        "terNO_DELEGATE_PERMISSION",
        -85,
        "Delegated account lacks permission to perform this transaction.",
    ),
    ("terNO_LINE", -94, "No such line."),
    (
        "terNO_PERMISSION",
        -83,
        "No permission to perform requested operation.",
    ),
    ("terNO_RIPPLE", -90, "Path does not permit rippling."),
    ("terOWNERS", -93, "Non-zero owner count."),
    ("terPRE_SEQ", -92, "Missing/inapplicable prior transaction."),
    ("terPRE_TICKET", -88, "Ticket is not yet in ledger."),
    ("terQUEUED", -89, "Held until escalated fee drops."),
    ("terRETRY", -99, "Retry transaction."),
    (
        "tesSUCCESS",
        0,
        "The transaction was applied. Only final in a validated ledger.",
    ),
];

/// Result code and message by name, e.g. `tesSUCCESS`.
pub fn result(name: &str) -> Option<(i32, &'static str)> {
    RESULTS
        .binary_search_by(|r| r.0.cmp(name))
        .ok()
        .map(|i| (RESULTS[i].1, RESULTS[i].2))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_results() {
        assert!(RESULTS.windows(2).all(|w| w[0].0 < w[1].0));
        assert_eq!(
            result("tesSUCCESS"),
            Some((
                0,
                "The transaction was applied. Only final in a validated ledger."
            ))
        );
        assert_eq!(
            result("tecPATH_DRY"),
            Some((128, "Path could not send partial amount."))
        );
        assert_eq!(result("tecNOPE"), None);
    }
}
