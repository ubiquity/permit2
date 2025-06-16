// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import {Test} from "forge-std/Test.sol";
import {Permit2} from "../src/Permit2.sol";
import {TokenProvider} from "./utils/TokenProvider.sol";
import {PermitSignature} from "./utils/PermitSignature.sol";
import {ISignatureTransfer} from "../src/interfaces/ISignatureTransfer.sol";
import {SignatureExpired} from "../src/PermitErrors.sol";

contract SignatureTransferBatchTest is Test, TokenProvider, PermitSignature {
    Permit2 public permit2;
    uint256 public fromPrivateKey;
    address public from;
    bytes32 public DOMAIN_SEPARATOR;
    address public to0 = address(0x1);
    address public to1 = address(0x2);
    uint256 public defaultAmount = 1e18;

    function setUp() public {
        fromPrivateKey = 0x12345678;
        from = vm.addr(fromPrivateKey);
        permit2 = new Permit2();
        DOMAIN_SEPARATOR = permit2.DOMAIN_SEPARATOR();

        initializeERC20Tokens();
        setERC20TestTokens(from);
        setERC20TestTokenApprovals(vm, from, address(permit2));
    }

    function testBatchPermitTransferFromHappyPath() public {
        // Build permits array
        ISignatureTransfer.PermitTransferFrom[] memory permits =
            new ISignatureTransfer.PermitTransferFrom[](2);
        permits[0] = defaultERC20PermitTransfer(address(token0), 0);
        permits[1] = defaultERC20PermitTransfer(address(token1), 1);

        // Build details array
        ISignatureTransfer.SignatureTransferDetails[] memory details =
            new ISignatureTransfer.SignatureTransferDetails[](2);
        details[0] = ISignatureTransfer.SignatureTransferDetails({to: to0, requestedAmount: defaultAmount});
        details[1] = ISignatureTransfer.SignatureTransferDetails({to: to1, requestedAmount: defaultAmount});

        // Owners
        address[] memory owners = new address[](2);
        owners[0] = from;
        owners[1] = from;

        // Signatures
        bytes[] memory sigs = new bytes[](2);
        sigs[0] = getPermitTransferSignature(permits[0], fromPrivateKey, DOMAIN_SEPARATOR);
        sigs[1] = getPermitTransferSignature(permits[1], fromPrivateKey, DOMAIN_SEPARATOR);

        // Record starting balances
        uint256 start0 = token0.balanceOf(from);
        uint256 start1 = token1.balanceOf(from);
        uint256 startTo0 = token0.balanceOf(to0);
        uint256 startTo1 = token1.balanceOf(to1);

        // Execute batch transfer
        permit2.batchPermitTransferFrom(permits, details, owners, sigs);

        // Verify balances updated
        assertEq(token0.balanceOf(from), start0 - defaultAmount);
        assertEq(token1.balanceOf(from), start1 - defaultAmount);
        assertEq(token0.balanceOf(to0), startTo0 + defaultAmount);
        assertEq(token1.balanceOf(to1), startTo1 + defaultAmount);
    }

    function testBatchPermitTransferFromLengthMismatch() public {
        uint256 nonce = 0;

        // Mismatched lengths
        ISignatureTransfer.PermitTransferFrom[] memory permits = new ISignatureTransfer.PermitTransferFrom[](1);
        permits[0] = defaultERC20PermitTransfer(address(token0), nonce);

        ISignatureTransfer.SignatureTransferDetails[] memory details = new ISignatureTransfer.SignatureTransferDetails[](2);

        address[] memory owners = new address[](1);
        owners[0] = from;

        bytes[] memory sigs = new bytes[](1);
        sigs[0] = getPermitTransferSignature(permits[0], fromPrivateKey, DOMAIN_SEPARATOR);

        vm.expectRevert(ISignatureTransfer.LengthMismatch.selector);
        permit2.batchPermitTransferFrom(permits, details, owners, sigs);
    }

    function testBatchPermitTransferFromInvalidAmount() public {
        uint256 nonce = 0;
        // Single permit with default limit
        ISignatureTransfer.PermitTransferFrom memory permit =
            defaultERC20PermitTransfer(address(token0), nonce);

        ISignatureTransfer.PermitTransferFrom[] memory permits = new ISignatureTransfer.PermitTransferFrom[](1);
        permits[0] = permit;

        // Request more than permitted
        ISignatureTransfer.SignatureTransferDetails[] memory details =
            new ISignatureTransfer.SignatureTransferDetails[](1);
        details[0] = ISignatureTransfer.SignatureTransferDetails({to: to0, requestedAmount: defaultAmount + 1});

        address[] memory owners = new address[](1);
        owners[0] = from;

        bytes[] memory sigs = new bytes[](1);
        sigs[0] = getPermitTransferSignature(permit, fromPrivateKey, DOMAIN_SEPARATOR);

        vm.expectRevert(abi.encodeWithSelector(ISignatureTransfer.InvalidAmount.selector, defaultAmount));
        permit2.batchPermitTransferFrom(permits, details, owners, sigs);
    }

    function testBatchPermitTransferFromSignatureExpired() public {
        uint256 nonce = 0;
        // Permit with past deadline
        ISignatureTransfer.PermitTransferFrom memory permit =
            defaultERC20PermitTransfer(address(token0), nonce);
        permit.deadline = uint48(block.timestamp) - 1;

        ISignatureTransfer.PermitTransferFrom[] memory permits = new ISignatureTransfer.PermitTransferFrom[](1);
        permits[0] = permit;

        ISignatureTransfer.SignatureTransferDetails[] memory details =
            new ISignatureTransfer.SignatureTransferDetails[](1);
        details[0] = ISignatureTransfer.SignatureTransferDetails({to: to0, requestedAmount: defaultAmount});

        address[] memory owners = new address[](1);
        owners[0] = from;

        bytes[] memory sigs = new bytes[](1);
        sigs[0] = getPermitTransferSignature(permit, fromPrivateKey, DOMAIN_SEPARATOR);

        // Move past deadline
        vm.warp(block.timestamp + 1);
        vm.expectRevert(abi.encodeWithSelector(SignatureExpired.selector, permit.deadline));
        permit2.batchPermitTransferFrom(permits, details, owners, sigs);
    }
}
