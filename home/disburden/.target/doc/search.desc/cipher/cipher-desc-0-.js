searchState.loadedDescShard("cipher", 0, "This crate defines a set of traits which describe the …\nTrait which stores algorithm name constant, used in <code>Debug</code> …\nTrait making <code>GenericArray</code> work, marking types to be used …\nAssociated type representing the array type for the number\nMarker trait for block-level asynchronous stream ciphers\nBlock on which <code>BlockSizeUser</code> implementors operate.\nTrait implemented by block cipher encryption and …\nMarker trait for block ciphers.\nTrait for <code>BlockBackend</code> users.\nDecrypt-only functionality for block ciphers.\nDecrypt-only functionality for block ciphers and modes …\nEncrypt-only functionality for block ciphers.\nEncrypt-only functionality for block ciphers and modes …\nSize of the block in bytes.\nTypes which process data in blocks.\nCounter type usable with <code>StreamCipherCore</code>.\nCounter type used inside stream cipher.\nTypes which can be initialized from another type and …\nThe error type returned when key and/or IV used in the …\nInitialization vector (nonce) used by <code>IvSizeUser</code> …\nInitialization vector size in bytes.\nTypes which use initialization vector (nonce) for …\nTrait for loading current IV state.\nKey used by <code>KeySizeUser</code> implementors.\nTypes which can be initialized from key.\nTypes which can be initialized from key and initialization …\nKey size in bytes.\nTypes which use key for initialization.\nThe error type returned when a cipher position can not be …\nParallel blocks on which <code>ParBlocksSizeUser</code> implementors …\nNumber of blocks which can be processed in parallel.\nTypes which can process blocks in parallel.\nTrait implemented for numeric types which can be used with …\nTrait implemented by stream cipher backends.\nSynchronous stream cipher core trait.\nBlock-level synchronous stream ciphers.\nWrapper around <code>StreamCipherCore</code> implementations.\nThis error is returned by the <code>StreamCipher</code> trait methods.\nTrait for seekable stream ciphers.\nBlock-level seeking trait for stream ciphers.\nTrait for <code>StreamBackend</code> users.\nThe <strong>marker trait</strong> for compile time unsigned integers.\nApply keystream to data in-place.\nApply keystream to data in-place.\nApply keystream to data buffer-to-buffer.\nApply keystream to data buffer-to-buffer.\nApply keystream block.\nApply keystream block.\nApply keystream blocks.\nApply keystream blocks.\nApply keystream blocks.\nApply keystream blocks.\nApply keystream to <code>inout</code> data.\nApply keystream to <code>inout</code> data.\nTry to apply keystream to data not divided into blocks.\nTry to apply keystream to data not divided into blocks.\nReturn block size in bytes.\nReturn block size in bytes.\nExecute closure with the provided block cipher backend.\nExecute closure with the provided stream cipher backend.\nGet current keystream position\nGet current keystream position\nDecrypt data in place.\nDecrypt data in place.\nDecrypt data from buffer to buffer.\nDecrypt data from buffer to buffer.\nDecrypt single block in-place.\nDecrypt single block in-place.\nDecrypt <code>in_block</code> and write result to <code>out_block</code>.\nDecrypt <code>in_block</code> and write result to <code>out_block</code>.\nDecrypt <code>in_block</code> and write result to <code>out_block</code>.\nDecrypt <code>in_block</code> and write result to <code>out_block</code>.\nDecrypt single <code>inout</code> block.\nDecrypt single <code>inout</code> block.\nDecrypt single <code>inout</code> block.\nDecrypt single <code>inout</code> block.\nDecrypt single block in-place.\nDecrypt single block in-place.\nDecrypt blocks in-place.\nDecrypt blocks in-place.\nDecrypt blocks buffer-to-buffer.\nDecrypt blocks buffer-to-buffer.\nDecrypt blocks buffer-to-buffer.\nDecrypt blocks buffer-to-buffer.\nDecrypt <code>inout</code> blocks.\nDecrypt <code>inout</code> blocks.\nDecrypt <code>inout</code> blocks.\nDecrypt <code>inout</code> blocks.\nDecrypt blocks in-place.\nDecrypt blocks in-place.\nDecrypt data using <code>InOutBuf</code>.\nDecrypt data using <code>InOutBuf</code>.\nDecrypt data using backend provided to the rank-2 closure.\nDecrypt data using backend provided to the rank-2 closure.\nEncrypt data in place.\nEncrypt data in place.\nEncrypt data from buffer to buffer.\nEncrypt data from buffer to buffer.\nEncrypt single block in-place.\nEncrypt single block in-place.\nEncrypt <code>in_block</code> and write result to <code>out_block</code>.\nEncrypt <code>in_block</code> and write result to <code>out_block</code>.\nEncrypt <code>in_block</code> and write result to <code>out_block</code>.\nEncrypt <code>in_block</code> and write result to <code>out_block</code>.\nEncrypt single <code>inout</code> block.\nEncrypt single <code>inout</code> block.\nEncrypt single <code>inout</code> block.\nEncrypt single <code>inout</code> block.\nEncrypt single block in-place.\nEncrypt single block in-place.\nEncrypt blocks in-place.\nEncrypt blocks in-place.\nEncrypt blocks buffer-to-buffer.\nEncrypt blocks buffer-to-buffer.\nEncrypt blocks buffer-to-buffer.\nEncrypt blocks buffer-to-buffer.\nEncrypt <code>inout</code> blocks.\nEncrypt <code>inout</code> blocks.\nEncrypt <code>inout</code> blocks.\nEncrypt <code>inout</code> blocks.\nEncrypt blocks in-place.\nEncrypt blocks in-place.\nEncrypt data using <code>InOutBuf</code>.\nEncrypt data using <code>InOutBuf</code>.\nEncrypt data using backend provided to the rank-2 closure.\nEncrypt data using backend provided to the rank-2 closure.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nTry to get position for block number <code>block</code>, byte position …\nReturn reference to the core type.\nGenerate keystream block.\nGenerate keystream blocks in parallel.\nGenerate keystream blocks in parallel.\nGenerate keystream blocks. Length of the buffer MUST be …\nGenerate keystream blocks. Length of the buffer MUST be …\nGet current block position.\nReturn reference to the core type.\nImplement simple block backend\nImplement simple block backend\nInitialize value using <code>inner</code> and <code>iv</code> array.\nInitialize value using <code>inner</code> and <code>iv</code> slice.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nTry to get block number and bytes position for given block …\nReturn IV size in bytes.\nReturns current IV state.\nReturn key size in bytes.\nCreate new value from fixed size key.\nCreate new value from fixed length key and nonce.\nCreate new value from variable size key.\nCreate new value from variable length key and nonce.\nProcess single inout block.\nProcess single block in-place.\nProcess single block in-place.\nProcess inout blocks in parallel.\nProcess inout blocks in parallel.\nProcess blocks in parallel in-place.\nProcess blocks in parallel in-place.\nProcess buffer of inout blocks. Length of the buffer MUST …\nProcess buffer of inout blocks. Length of the buffer MUST …\nProcess buffer of blocks in-place. Length of the buffer …\nProcess buffer of blocks in-place. Length of the buffer …\nProcess data using backend provided to the rank-2 closure.\nReturn number of remaining blocks before cipher wraps …\nSeek to the given position\nSeek to the given position\nSet block position.\nApply keystream to data behind <code>buf</code>.\nApply keystream to data behind <code>buf</code>.\nApply keystream to <code>inout</code> data.\nTry to apply keystream to data not divided into blocks.\nTry to apply keystream to data not divided into blocks.\nTry to get current keystream position\nTry to seek to the given position\nWrite algorithm name into <code>f</code>.\nWrite keystream block.\nWrite keystream block.\nWrite keystream blocks.\nWrite keystream blocks.\nThe type-level bit 0.\nThe type-level bit 1.\nThe type-level signed integer 0.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nInstantiates a singleton representing this bit.\nInstantiates a singleton representing this bit.\nInstantiates a singleton representing the integer 0.")