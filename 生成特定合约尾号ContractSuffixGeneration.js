import {ethers} from 'ethers';

// 假设这是你希望得到的合约地址尾号
const desiredSuffix = '6666';

function numberToHex32(number) {
    // 将数字转换为十六进制字符串
    let hex = number.toString(16);
    // 计算需要填充的0的数量
    const padding = 64 - hex.length;
    // 填充0并添加'0x'前缀
    return '0x' + '0'.repeat(padding) + hex;
}

function findSaltForDesiredSuffix() {
    let salt = 0; // 从0开始尝试
    let found = false;
    while (!found) {
        // 生成预期的合约地址
        const contractCode = ''; // 替换为你的合约字节码
        const addressDeployer = ''; // 替换为你部署的deploy合约地址
        const contractCodeHash = ethers.keccak256(contractCode);
        const potentialContractAddress = ethers.getCreate2Address(
            addressDeployer,
            ethers.keccak256(numberToHex32(salt)),
            contractCodeHash
        );

        const potentialContractAddressSuffix = potentialContractAddress.substring(potentialContractAddress.length - desiredSuffix.length);
        if (potentialContractAddressSuffix.toLowerCase() === desiredSuffix.toLowerCase()) {
            found = true;
            console.log(`Found matching salt: ${salt}`);
            console.log(`hashSalt,${ethers.keccak256(numberToHex32(salt))}`);
            console.log(`Contract address would be: ${potentialContractAddress}`);
        } else {
            salt++;
        }

        if (salt % 10000 === 0) {
            console.log(`Checked ${salt} salts so far...`);
        }
        // 在实际情况中，你可能需要在这里设置一些退出条件以避免无限循环
    }
}

findSaltForDesiredSuffix();


/*
library Create2 {
    error Create2InsufficientBalance(uint256 balance, uint256 needed);

    error Create2EmptyBytecode();

    error Create2FailedDeployment();

    function deploy(uint256 amount, bytes32 salt, bytes memory bytecode) internal returns (address addr) {
        if (address(this).balance < amount) {
            revert Create2InsufficientBalance(address(this).balance, amount);
        }
        if (bytecode.length == 0) {
            revert Create2EmptyBytecode();
        }
        /// @solidity memory-safe-assembly
        assembly {
            addr := create2(amount, add(bytecode, 0x20), mload(bytecode), salt) //amount为传入合约的eth值
        }
        if (addr == address(0)) {
            revert Create2FailedDeployment();
        }
    }

    function computeAddress(bytes32 salt, bytes32 bytecodeHash) internal view returns (address) {
        return computeAddress(salt, bytecodeHash, address(this));
    }

    function computeAddress(bytes32 salt, bytes32 bytecodeHash, address deployer) internal pure returns (address addr) {
        /// @solidity memory-safe-assembly
        assembly {
            let ptr := mload(0x40) // Get free memory pointer
            mstore(add(ptr, 0x40), bytecodeHash)
            mstore(add(ptr, 0x20), salt)
            mstore(ptr, deployer) // Right-aligned with 12 preceding garbage bytes
            let start := add(ptr, 0x0b) // The hashed data starts at the final garbage byte which we will set to 0xff
            mstore8(start, 0xff)
            addr := keccak256(start, 85)
        }
    }
}
contract Deploy{
    using Create2 for *;

    function getHashSalt(uint256 i) public pure returns(bytes memory,bytes32){
        return (abi.encode(i),keccak256(abi.encode(i)));
    }

    function calculateAddr(bytes32 salt,bytes memory bytecode) public view returns(address){
        address predictedAddress;
            predictedAddress = address(uint160(uint(keccak256(abi.encodePacked(
                bytes1(0xff),
                address(this),
                salt,
                keccak256(bytecode)
            )))));
        return predictedAddress;
    }

    function getCode() public pure returns(bytes memory){
        return type(test).creationCode;
    }

    function deployContract(bytes32 salt,bytes memory bytecode) public{
        Create2.deploy(0,salt,bytecode);
    }
}
*/
