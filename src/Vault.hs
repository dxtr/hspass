module Vault
       ( EncryptedVault
       , Vault
       , newVault
       , vaultLen
       , updateEntries
       , entryNames
       , getEntry
       , putEntry
       ) where

import Data.Word (Word8, Word16, Word)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Map (Map)
import qualified Data.Map as Map

import Crypto.Saltine as Sodium
-- xsalsa20poly1305

import Entry

data Vault = Vault { padding :: ByteString
                   , entries :: Map String Entry.EncryptedEntry
                   }
  deriving ()

data EncryptedVault = EncryptedVault { version :: Word16
                                     , nonce :: Sodium.Nonce
                                     , ciphertext :: ByteString
                                     }
  deriving ()




newVault :: Vault
newVault = Vault { padding = ByteString.empty, entries = Map.empty }

vaultLen :: Vault -> Int
vaultLen vault = Map.size (entries vault)

-- update :: ByteString -> Map String Entry.EncryptedEntry -> Vault
-- update padding entries = Vault { padding = padding
--                                , entries = entries
--                               }

-- updatePadding :: Vault -> ByteString -> Vault
-- updatePadding vault newPadding = vault { padding = newPadding }

-- Perhaps this should update the padding too
-- Or maybe that should be done before or during encryption
updateEntries :: Vault -> Map String Entry.EncryptedEntry -> Vault
updateEntries vault newEntries = vault { entries = newEntries }

entryNames :: Vault -> [String]
entryNames vault = vaultEntryKeys
  where vaultEntries = entries vault
        vaultEntryKeys = Map.keys vaultEntries

getEntry :: Vault -> String -> Maybe (EncryptedEntry, EntryMetaData)
getEntry vault entry = case vaultEntry of
  Nothing -> Nothing
  Just e -> Just (e, metadata e)
  where vaultEntries = entries vault
        vaultEntry = Map.lookup entry vaultEntries
--  (Entry.decrypt (Map.lookup entry (entries vault)) key,
--   Entry.metadata (Map.lookup entry (entries vault)))

-- updateEntry :: Vault -> Sodium.Key -> String -> (Entry.Entry, Entry.EntryMetaData) -> Maybe Vault
-- updateEntry vault key (entry, metadata) =

putEntry :: Vault -> String -> EncryptedEntry -> Vault
putEntry vault entryName entry =
  updateEntries vault newEntries
  where
    oldEntries = entries vault
    newEntries = Map.insert entryName entry oldEntries
    
   
