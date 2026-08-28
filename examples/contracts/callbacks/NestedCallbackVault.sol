pragma solidity ^0.8.0;

interface IERC721Receiver {
    function onERC721Received(
        address operator,
        address from,
        uint256 tokenId,
        bytes calldata data
    ) external returns (bytes4);
}

/// @notice Deposit flow that fires two distinct standard callbacks from the
/// same function — an ERC-777 sender hook followed by an ERC-721
/// receiver-hook mint for the deposit receipt — both correctly guarded by
/// a reentrancy lock and full Checks-Effects-Interactions ordering. Used
/// as a false-positive control for nested, multi-standard callbacks.
contract NestedCallbackVault {
    mapping(address => uint256) public shares;
    mapping(uint256 => address) public receiptOwner;
    uint256 public totalShares;
    bool private _locked;

    modifier nonReentrant() {
        require(!_locked, "reentrant");
        _locked = true;
        _;
        _locked = false;
    }

    function depositAndMintReceipt(uint256 amount, uint256 receiptId) external nonReentrant {
        shares[msg.sender] += amount;
        totalShares += amount;
        receiptOwner[receiptId] = msg.sender;

        _callTokensToSend(msg.sender, address(this), amount);
        _checkOnERC721Received(msg.sender, address(0), msg.sender, receiptId);
    }

    function _callTokensToSend(address from, address to, uint256 amount) internal {
        // Dispatches to IERC777Sender(implementer).tokensToSend(...).
    }

    function _checkOnERC721Received(
        address operator,
        address from,
        address to,
        uint256 tokenId
    ) internal {
        IERC721Receiver(to).onERC721Received(operator, from, tokenId, "");
    }
}
