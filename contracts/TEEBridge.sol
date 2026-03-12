// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {IVerifier} from "./IVerifier.sol";

/// @title TEEBridge
/// @notice Multi-verifier TEE membership registry. Platform-agnostic — verifiers implement IVerifier.
contract TEEBridge {
    address public owner;
    mapping(address => bool) public allowedVerifiers;
    mapping(bytes32 => bool) public allowedCode;

    struct Member {
        bytes32 codeId;
        address verifier;
        bytes pubkey;
        bytes userData;
        uint256 registeredAt;
    }
    mapping(bytes32 => Member) internal _members;

    struct OnboardMsg {
        bytes32 fromMember;
        bytes encryptedPayload;
    }
    mapping(bytes32 => OnboardMsg[]) internal _onboarding;

    event MemberRegistered(bytes32 indexed memberId, bytes32 indexed codeId, address indexed verifier, bytes pubkey, bytes userData);
    event OnboardingPosted(bytes32 indexed toMember, bytes32 indexed fromMember);
    event AllowedCodeAdded(bytes32 indexed codeId);
    event AllowedCodeRemoved(bytes32 indexed codeId);
    event VerifierAdded(address indexed verifier);
    event VerifierRemoved(address indexed verifier);

    error NotOwner();
    error VerifierNotAllowed();
    error CodeNotAllowed();
    error AlreadyRegistered();
    error MemberNotFound();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    // --- Admin ---

    function addVerifier(address verifier) external onlyOwner {
        allowedVerifiers[verifier] = true;
        emit VerifierAdded(verifier);
    }

    function removeVerifier(address verifier) external onlyOwner {
        allowedVerifiers[verifier] = false;
        emit VerifierRemoved(verifier);
    }

    function addAllowedCode(bytes32 codeId) external onlyOwner {
        allowedCode[codeId] = true;
        emit AllowedCodeAdded(codeId);
    }

    function removeAllowedCode(bytes32 codeId) external onlyOwner {
        allowedCode[codeId] = false;
        emit AllowedCodeRemoved(codeId);
    }

    // --- Registration ---

    function register(address verifier, bytes calldata proof) external returns (bytes32) {
        if (!allowedVerifiers[verifier]) revert VerifierNotAllowed();
        (bytes32 codeId, bytes memory pubkey, bytes memory userData) = IVerifier(verifier).verifyAndCache(proof);
        if (!allowedCode[codeId]) revert CodeNotAllowed();

        bytes32 memberId = keccak256(pubkey);
        if (_members[memberId].registeredAt != 0) revert AlreadyRegistered();
        _members[memberId] = Member({codeId: codeId, verifier: verifier, pubkey: pubkey, userData: userData, registeredAt: block.timestamp});
        emit MemberRegistered(memberId, codeId, verifier, pubkey, userData);
        return memberId;
    }

    // --- Onboarding ---

    function onboard(bytes32 fromMemberId, bytes32 toMemberId, bytes calldata encryptedPayload) external {
        if (_members[fromMemberId].registeredAt == 0) revert MemberNotFound();
        if (_members[toMemberId].registeredAt == 0) revert MemberNotFound();
        _onboarding[toMemberId].push(OnboardMsg({fromMember: fromMemberId, encryptedPayload: encryptedPayload}));
        emit OnboardingPosted(toMemberId, fromMemberId);
    }

    // --- Views ---

    function getMember(bytes32 memberId) external view returns (bytes32 codeId, address verifier, bytes memory pubkey, bytes memory userData, uint256 registeredAt) {
        Member storage m = _members[memberId];
        return (m.codeId, m.verifier, m.pubkey, m.userData, m.registeredAt);
    }

    function isMember(bytes32 memberId) external view returns (bool) {
        return _members[memberId].registeredAt != 0;
    }

    function getOnboarding(bytes32 memberId) external view returns (OnboardMsg[] memory) {
        return _onboarding[memberId];
    }
}
