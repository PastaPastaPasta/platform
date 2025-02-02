const { BloomFilter } = require('@dashevo/dashcore-lib');
const crypto = require('crypto');

const {
  server: {
    error: {
      InvalidArgumentGrpcError,
      NotFoundGrpcError,
    },
    stream: {
      AcknowledgingWritable,
    },
  },
} = require('@dashevo/grpc-common');

const {
  v0: {
    TransactionsWithProofsResponse,
    RawTransactions,
    InstantSendLockMessages,
  },
} = require('@dashevo/dapi-grpc');

const ProcessMediator = require('../../../transactionsFilter/ProcessMediator');
const wait = require('../../../utils/wait');
const logger = require('../../../logger');

/**
 * Prepare the response and send transactions response
 *
 * @param {AcknowledgingWritable} call
 * @param {Transaction[]} transactions
 * @returns {Promise<void>}
 */
async function sendTransactionsResponse(call, transactions) {
  const rawTransactions = new RawTransactions();
  rawTransactions.setTransactionsList(
    transactions.map((tx) => tx.toBuffer()),
  );

  const response = new TransactionsWithProofsResponse();
  response.setRawTransactions(rawTransactions);

  await call.write(response);
}

/**
 * Prepare the response and send merkle block response
 *
 * @param {AcknowledgingWritable} call
 * @param {MerkleBlock} merkleBlock
 * @returns {Promise<void>}
 */
async function sendMerkleBlockResponse(call, merkleBlock) {
  const response = new TransactionsWithProofsResponse();
  response.setRawMerkleBlock(merkleBlock.toBuffer());

  await call.write(response);
}

/**
 * Prepare the response and send transactions response
 *
 * @param {AcknowledgingWritable} call
 * @param {InstantLock} instantLock
 * @returns {Promise<void>}
 */
async function sendInstantLockResponse(call, instantLock) {
  const instantSendLockMessages = new InstantSendLockMessages();
  instantSendLockMessages.setMessagesList([instantLock.toBuffer()]);

  const response = new TransactionsWithProofsResponse();
  response.setInstantSendLockMessages(instantSendLockMessages);

  await call.write(response);
}

/**
 *
 * @param {getHistoricalTransactionsIterator} getHistoricalTransactionsIterator
 * @param {subscribeToNewTransactions} subscribeToNewTransactions
 * @param {BloomFilterEmitterCollection} bloomFilterEmitterCollection
 * @param {testFunction} testTransactionAgainstFilter
 * @param {CoreRpcClient} coreAPI
 * @param {getMemPoolTransactions} getMemPoolTransactions
 * @return {subscribeToTransactionsWithProofsHandler}
 */
function subscribeToTransactionsWithProofsHandlerFactory(
  getHistoricalTransactionsIterator,
  subscribeToNewTransactions,
  bloomFilterEmitterCollection,
  testTransactionAgainstFilter,
  coreAPI,
  getMemPoolTransactions,
) {
  /**
   * @typedef subscribeToTransactionsWithProofsHandler
   * @param {grpc.ServerWriteableStream<TransactionsWithProofsRequest>} call
   */
  async function subscribeToTransactionsWithProofsHandler(call) {
    const { request } = call;

    const bloomFilterMessage = request.getBloomFilter();

    if (!bloomFilterMessage) {
      throw new InvalidArgumentGrpcError('Bloom filter is not set');
    }

    const bloomFilter = {
      vData: bloomFilterMessage.getVData_asU8(),
      nHashFuncs: bloomFilterMessage.getNHashFuncs(),
      nTweak: bloomFilterMessage.getNTweak(),
      nFlags: bloomFilterMessage.getNFlags(),
    };

    const fromBlockHash = Buffer.from(request.getFromBlockHash_asU8()).toString('hex');
    const fromBlockHeight = request.getFromBlockHeight();

    if (!fromBlockHash && fromBlockHeight === 0) {
      throw new InvalidArgumentGrpcError('Minimum value for `fromBlockHeight` is 1');
    }

    const from = fromBlockHash || fromBlockHeight;
    const count = request.getCount();

    // Create a new bloom filter emitter when client connects
    let filter;

    try {
      filter = new BloomFilter(bloomFilter);
    } catch (e) {
      throw new InvalidArgumentGrpcError(`Invalid bloom filter: ${e.message}`);
    }

    const isNewTransactionsRequested = count === 0;

    const requestId = crypto.createHash('sha256')
      .update(filter.toBuffer())
      .digest('hex');

    const requestLogger = logger.child({
      requestId,
    });

    let countMessage = ` for ${count} blocks`;
    if (isNewTransactionsRequested) {
      countMessage = ' and upcoming new transactions';
    }

    requestLogger.debug({
      from,
      count,
    }, `open transactions stream from block ${from}${countMessage}`);

    const acknowledgingCall = new AcknowledgingWritable(call);

    const mediator = new ProcessMediator();

    mediator.on(
      ProcessMediator.EVENTS.TRANSACTION,
      async (tx) => {
        requestLogger.debug(`sent transaction ${tx.hash}`);

        await sendTransactionsResponse(acknowledgingCall, [tx]);
      },
    );

    mediator.on(
      ProcessMediator.EVENTS.MERKLE_BLOCK,
      async (merkleBlock) => {
        requestLogger.debug(`sent merkle block ${merkleBlock.header.hash}`);

        await sendMerkleBlockResponse(acknowledgingCall, merkleBlock);
      },
    );

    mediator.on(
      ProcessMediator.EVENTS.INSTANT_LOCK,
      async (instantLock) => {
        requestLogger.debug({
          instantLock,
        }, `sent instant lock for ${instantLock.txid}`);

        await sendInstantLockResponse(acknowledgingCall, instantLock);
      },
    );

    if (isNewTransactionsRequested) {
      subscribeToNewTransactions(
        mediator,
        filter,
        testTransactionAgainstFilter,
        bloomFilterEmitterCollection,
      );
    }

    // Send historical transactions
    let fromBlock;

    try {
      fromBlock = await coreAPI.getBlockStats(from, ['height']);
    } catch (e) {
      if (e.code === -5 || e.code === -8) {
        // -5 -> invalid block height or block is not on best chain
        // -8 -> block hash not found
        throw new NotFoundGrpcError(`Block ${from} not found`);
      }
      throw e;
    }

    const bestBlockHeight = await coreAPI.getBestBlockHeight();

    let historicalCount = count;

    // if block 'count' is 0 (new transactions are requested)
    // or 'count' is bigger than chain tip we need to read all blocks
    // from specified block hash including the most recent one
    //
    // Theoretically, if count is bigger than chain tips,
    // we should throw an error 'count is too big',
    // however at the time of writing this logic, height chain sync isn't yet implemented,
    // so the client library doesn't know the exact height and
    // may pass count number larger than expected.
    // This condition should be converted to throwing an error once
    // the header stream is implemented
    if (count === 0 || fromBlock.height + count > bestBlockHeight + 1) {
      historicalCount = bestBlockHeight - fromBlock.height + 1;
    }

    const historicalDataIterator = getHistoricalTransactionsIterator(
      filter,
      fromBlock.height,
      historicalCount,
    );

    requestLogger.debug({
      fromHeight: fromBlock.height,
      count: historicalCount,
    }, 'sending requested historical data');

    let blocksSent = 0;

    for await (const { merkleBlock, transactions, index } of historicalDataIterator) {
      if (index > 0) {
        // Wait a second between the calls to Core just to reduce the load
        await wait(50);
      }

      await sendTransactionsResponse(acknowledgingCall, transactions);
      await sendMerkleBlockResponse(acknowledgingCall, merkleBlock);

      requestLogger.debug(`sent historical block ${merkleBlock.header.hash} and ${transactions.length} transactions`);

      if (isNewTransactionsRequested) {
        // removing sent transactions and blocks from cache
        mediator.emit(ProcessMediator.EVENTS.HISTORICAL_BLOCK_SENT, merkleBlock.header.hash);
      }

      blocksSent = index;
    }

    // notify new txs listener that we've sent historical data
    requestLogger.debug(`${blocksSent} historical blocks sent`);

    mediator.emit(ProcessMediator.EVENTS.HISTORICAL_DATA_SENT);

    if (isNewTransactionsRequested) {
      // Read and test transactions from mempool
      const memPoolTransactions = await getMemPoolTransactions();

      requestLogger.debug(`received ${memPoolTransactions.length} transactions from mempool`);

      memPoolTransactions.forEach(
        bloomFilterEmitterCollection.test.bind(bloomFilterEmitterCollection),
      );

      mediator.emit(ProcessMediator.EVENTS.MEMPOOL_DATA_SENT);

      // Send empty response as a workaround for Rust tonic that expects at least one message
      // to be sent to establish a stream connection
      // https://github.com/hyperium/tonic/issues/515
      if (blocksSent === 0 && memPoolTransactions.length === 0) {
        requestLogger.debug('send empty response to kick off Rust tonic stream connection');
        const response = new TransactionsWithProofsResponse();
        await call.write(response);
      }
    } else {
      requestLogger.debug('close stream');

      // End stream if user asked only for historical data
      call.end();

      // remove bloom filter emitter
      mediator.emit(ProcessMediator.EVENTS.CLIENT_DISCONNECTED);
    }

    call.on('end', () => {
      call.end();

      // remove bloom filter emitter
      mediator.emit(ProcessMediator.EVENTS.CLIENT_DISCONNECTED);
    });

    call.on('cancelled', () => {
      call.end();

      requestLogger.debug('client cancelled the stream');

      // remove bloom filter emitter
      mediator.emit(ProcessMediator.EVENTS.CLIENT_DISCONNECTED);
    });
  }

  return subscribeToTransactionsWithProofsHandler;
}

module.exports = subscribeToTransactionsWithProofsHandlerFactory;
