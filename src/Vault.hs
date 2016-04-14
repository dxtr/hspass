module Vault
       ( EncryptedVault
       , Vault
       ) where

import Data.Word (Word8, Word16, Word)
import Data.ByteString (ByteString)
import qualified Data.ByteString as ByteString
import Data.Map (Map)
import qualified Data.Map as Map

import Crypto.Saltine as Sodium
-- xsalsa20poly1305

import Entry

data EncryptedVault = EncryptedVault { version :: Word16
                                     , nonce :: Sodium.Nonce
                                     , ciphertext :: ByteString
                                     }
  deriving ()

data Vault = Vault { padding :: ByteString
                   , entries :: Map String Entry.EncryptedEntry
                   }
  deriving ()

new :: Vault
new = Vault { padding = ByteString.empty, entries = Map.empty }

update :: ByteString -> Map String Entry.EncryptedEntry -> Vault
update padding entries = Vault { padding = padding
                               , entries = entries
                               }

entryNames :: Vault -> [String]
entryNames vault = Map.keys (entries vault)

getEntry :: Vault -> Sodium.Key -> String -> Maybe (Maybe Entry.Entry, Entry.EntryMetaData)
getEntry vault key entry = case Map.lookup entry (entries vault) of
  Nothing -> Nothing
  Just e -> Just (Entry.decrypt e key, Entry.metadata e)
--  (Entry.decrypt (Map.lookup entry (entries vault)) key,
--   Entry.metadata (Map.lookup entry (entries vault)))

updateEntry :: Vault -> Sodium.Key -> String -> (Entry.Entry, Entry.EntryMetaData) -> Maybe Vault
updateEntry vault key (entry, metadata) =

putEntry :: Vault -> Sodium.Key -> (Entry.Entry, Entry.EntryMetaData) -> Vault
putEntry vault key (entry, metadata) =
  update (padding vault) (entries vault)
