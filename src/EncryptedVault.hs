module EncryptedVault
       ( EncryptedVault
       ) where

import Data.Word (Word8, Word16, Word)

data EncryptedVault = EncryptedVault { version :: Word16
                                     , nonce :: [Word8]
                                     , ciphertext :: [Word8]
                                     }
  deriving (Show)
