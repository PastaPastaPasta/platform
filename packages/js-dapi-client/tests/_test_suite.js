require('./index.js');
require('./Accounts/User/create.js')
require('./Accounts/User/login.js')
require('./Explorer/API/getStatus.js')
require('./Explorer/API/getBlock.js')
require('./Explorer/API/getBlockBits.js')
require('./Explorer/API/getBlockChainwork.js')
require('./Explorer/API/getBlockConfirmations.js')
//FIXME If a block is mined during the fetching process, this data, when verified will be shifted and won't equal.
require('./Explorer/API/getBlockHeaders.js')
require('./Explorer/API/getBlockMerkleRoot.js')
require('./Explorer/API/getBlockSize.js')
require('./Explorer/API/getBlockTime.js')
require('./Explorer/API/getBlockTransactions.js')
require('./Explorer/API/getBlockVersion.js')
require('./Explorer/API/getHashFromHeight.js')
require('./Explorer/API/getHeightFromHash.js')
require('./Explorer/API/getLastBlock.js')
require('./Explorer/API/getLastBlockHash.js')
require('./Explorer/API/getLastBlockHeight.js')
require('./Explorer/API/getLastDifficulty.js')
