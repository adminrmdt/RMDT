// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";

/**
 * @title RMDTTimelock
 * @notice Thin wrapper around OpenZeppelin TimelockController for the RMDT system.
 *         Use this contract as the owner of admin-privileged contracts to enforce
 *         a delay for sensitive operations while keeping user-facing functions instant.
 *
 * Constructor params:
 *  - minDelay: required delay in seconds before an operation can be executed
 *  - proposers: addresses allowed to schedule operations (e.g., your multisig)
 *  - executors: addresses allowed to execute ready operations (can be an array
 *               containing your multisig, or use address(0) to allow anyone)
 *  - admin: initial admin to manage roles; set to your multisig for production
 */
contract RMDTTimelock is TimelockController {
    constructor(
        uint256 minDelay,
        address[] memory proposers,
        address[] memory executors,
        address admin
    ) TimelockController(minDelay, proposers, executors, admin) {}
}