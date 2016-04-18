{-#LANGUAGE OverloadedStrings #-}
module Entry
       ( EncryptedEntry
       , Entry
       , EntryMetaData
       , newEntry
       , newMetaData
       , encryptEntry
       , decryptEntry
       , metadata
       ) where

import Data.Word (Word32)
import Data.Time.Clock
-- import Data.Vector.Storable (Vector)
-- import qualified Data.Vector.Storable as Vector
import Data.Map.Lazy (Map)
import qualified Data.Map.Lazy as Map
--import Data.ByteString (ByteString)
--import qualified Data.ByteString as ByteString
import Data.ByteString.Char8 (ByteString)
import qualified Data.ByteString.Char8 as ByteString
import Data.ByteString.Lazy (toStrict)
-- import Data.Maybe
import Data.CBOR
import Data.Binary.CBOR
import Data.Binary.Put
import Data.List (intercalate)

import Crypto.Saltine as Sodium

data EncryptedEntry = EncryptedEntry { nonce :: Sodium.Nonce
                                     , ctr :: Word32
                                     , ciphertext :: ByteString.ByteString
                                     , metadata :: EntryMetaData
                                     }
  deriving ()

instance Show EncryptedEntry where
  show (EncryptedEntry _ entryCounter _ _) = "Counter: " ++ show entryCounter

data EntryMetaData = EntryMetaData { created_at :: Int
                                   , updated_at :: Int
                                   , tags :: [String]
                                   }
  deriving ()

data Entry = Entry { fields :: Map String Field }
  deriving ()

instance Show Entry where
  show (Entry entryFields)
    | null fieldsList = "No fields"
    | otherwise = intercalate "\n" (map fieldMapFunc fieldsList)
      where fieldsList = Map.toList entryFields
            fieldMapFunc (key,_) = key

instance Show EntryMetaData where
  show (EntryMetaData createdAt updatedAt metaTags) = "Created at: " ++ show createdAt ++
    "\nUpdated at: " ++ show updatedAt ++ "\n" ++ show dataTags
    where dataTags = if null metaTags then "No tags" else intercalate "," metaTags
          
            

data Field =
  DerivedField { derived_field_counter :: Word32
               , derived_site_name :: String
               , derived_field_usage :: DerivedUsage
               }
  | StoredField { stored_field_data :: String
                , stored_field_usage :: StoredUsage
                }
  deriving ()
    
data DerivedUsage = RawKey | StoredUsage | Ed25519Usage
data Ed25519Usage = SSH | Signify | SQRL
data StoredUsage = Text | Password
data PasswordTemplate = Maximum | Long | Medium | Short | Basic | Pin
-- 60 | 50 | 40 | 30 | 20 | 10

data Error = WrongEntriesKeyLength
  | WrongEntryNonceLength
  | WrongOuterNonceLength
  | WrongOuterKeyLength
  | WrongDerivedKeyLength
  | InappropriateFormat
  | SeedGenerationError
  | DecryptionError
--  | CodecError(CborError)
--  | ByteCodecError(byteorder::Error),
--  | StringCodecError(string::FromUtf8Error),
--  | OtherError(io::Error),
  | DataError
  | EntryNotFound
  | NotImplemented
  | NotAvailableOnPlatform
  | SSHAgentSocketNotFound

newEntry :: Entry
newEntry = Entry { fields = Map.empty }

newMetaData :: EntryMetaData
newMetaData = EntryMetaData { created_at = 0, updated_at = 0, tags = [] }

fromByteString :: Maybe ByteString -> Maybe Entry
fromByteString Nothing = Nothing
fromByteString (Just rawEntry) = Nothing

serializeDerivedField :: Word32 -> String -> DerivedUsage -> CBOR
serializeDerivedField fieldCounter siteName fieldUsage = CBOR_UInt 1

serializeStoredField :: String -> StoredUsage -> CBOR
serializeStoredField fieldData fieldUsage = CBOR_UInt 1

serializeField :: Field -> CBOR
serializeField (DerivedField {derived_field_counter = fieldCounter,
                              derived_field_usage = fieldUsage,
                              derived_site_name = siteName}) = serializeDerivedField fieldCounter siteName fieldUsage
serializeField (StoredField {stored_field_data = fieldData,
                             stored_field_usage = fieldUsage}) = serializeStoredField fieldData fieldUsage

serializeEntry :: Entry -> CBOR
serializeEntry entry = serializedEntry
  where mapFunc (key, field) = (CBOR_TS(ByteString.pack key), serializeField field)
        entryFields = fields entry
        entryFieldList = Map.toList entryFields
        mappedFields = map mapFunc entryFieldList
        serializedEntry = CBOR_Map mappedFields
        
--  Map.mapWithKey (\key value -> (CBOR_TS(key),(serializeField value))) $ fields entry

encryptEntry :: Entry -> Sodium.Key -> IO EncryptedEntry
encryptEntry entry key = do
  nNonce <- Sodium.newNonce
--  currentTime <- getCurrentTime
  let cipherText = Sodium.secretbox key nNonce byteEntry
  
  return EncryptedEntry { nonce = nNonce
                        , ctr = 0
                        , ciphertext = cipherText
                        , metadata = EntryMetaData { created_at = 0
                                                   , updated_at = 0
                                                   , tags = []
                                                   }
                        }

  where serializedEntry = serializeEntry entry
        cborEntry = putCBOR serializedEntry
        putResult = runPutM cborEntry
        byteEntry = toStrict $ snd putResult

decryptEntry :: EncryptedEntry -> Sodium.Key -> Maybe Entry
decryptEntry encEntry key = fromByteString $
  secretboxOpen key (nonce encEntry) (ciphertext encEntry)

incCounter :: EncryptedEntry -> EncryptedEntry
incCounter encEntry = encEntry { ctr = newCtr }
  where newCtr = ctr encEntry + 1

decCounter :: EncryptedEntry -> EncryptedEntry
decCounter encEntry = encEntry { ctr = ctr encEntry - 1 }
  where newCtr = ctr encEntry - 1
