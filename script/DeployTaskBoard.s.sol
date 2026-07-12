// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {Script, console2} from "forge-std/Script.sol";
import {TaskBoard} from "../contracts/TaskBoard.sol";

contract DeployTaskBoard is Script {
    function run() external {
        vm.startBroadcast(vm.envUint("PRIVATE_KEY"));
        TaskBoard board = new TaskBoard();
        vm.stopBroadcast();
        console2.log("TaskBoard:", address(board));
    }
}
