// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./MinimalForwarder.sol";

/**
 * @title RMDTForwarder
 * @notice Trusted forwarder for RMDT ecosystem (token + vesting contracts)
 * @dev Inherits from MinimalForwarder (EIP-2771 compatible)
 *      - Verifies signed meta-transactions
 *      - Executes them on behalf of the user
 *      - Designed for OpenZeppelin v5.x environment
 */
contract RMDTForwarder is MinimalForwarder {
    /**
     * @notice Initializes the forwarder domain separator
     * @dev Calls MinimalForwarder constructor with name/version
     */
    constructor() MinimalForwarder() {}
}
