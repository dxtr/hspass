{-#LANGUAGE OverloadedStrings #-}
module Entry
       ( EncryptedEntry
       , Entry
       , EntryMetaData
       , decrypt
       , metadata
       ) where

import Data.Word (Word8, Word16, Word32)
import Data.Time.Clock
import Data.Vector.Storable (Vector)
import qualified Data.Vector.Storable as Vector
import Data.Map.Lazy (Map)
import qualified Data.Map.Lazy as Map
--import Data.ByteString (ByteString)
--import qualified Data.ByteString as ByteString
import Data.ByteString.Char8 (ByteString)
import qualified Data.ByteString.Char8 as ByteString
import Data.Maybe
import Data.CBOR
import Data.Binary.CBOR
import Data.Binary.Put

import Crypto.Saltine as Sodium

data EncryptedEntry = EncryptedEntry { nonce :: Sodium.Nonce
                                     , counter :: Word32
                                     , ciphertext :: ByteString.ByteString
                                     , metadata :: EntryMetaData
                                     }
  deriving ()

data EntryMetaData = EntryMetaData { created_at :: UTCTime
                                   , updated_at :: UTCTime
                                   , tags :: Vector String
                                   }
  deriving ()

data Entry = Entry { fields :: Map String Field }
  deriving ()

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

serializeEntry :: (String, Field) -> (CBOR, CBOR)
serializeEntry (key, field) = (CBOR_TS(ByteString.pack key), serializeField field)

serialize :: Entry -> CBOR
serialize entry =
  CBOR_Map $ map serializeEntry $ Map.toList $ fields entry
--  Map.mapWithKey (\key value -> (CBOR_TS(key),(serializeField value))) $ fields entry

encrypt :: Entry -> Sodium.Key -> IO EncryptedEntry
encrypt entry key = do
  newNonce <- Sodium.newNonce
  
  let serializedEntry = serialize entry
  let cborEntry = putCBOR serializedEntry
  let putResult = runPutM cborEntry
  let byteEntry = snd putResult
  let cipherText = Sodium.secretbox key newNonce byteEntry
  return EncryptedEntry { nonce = newNonce
                        , counter = 0
                        , ciphertext = cipherText
                                                  }

decrypt :: EncryptedEntry -> Sodium.Key -> Maybe Entry
decrypt encEntry key = fromByteString $
  secretboxOpen key (nonce encEntry) (ciphertext encEntry)

incCounter :: EncryptedEntry -> EncryptedEntry
incCounter encEntry = EncryptedEntry { nonce = nonce encEntry
                                        , counter = counter encEntry + 1
                                        , ciphertext = ciphertext encEntry
                                        , metadata = metadata encEntry
                                        }

decCounter :: EncryptedEntry -> EncryptedEntry
decCounter encEntry = EncryptedEntry { nonce = nonce encEntry
                                        , counter = counter encEntry - 1
                                        , ciphertext = ciphertext encEntry
                                        , metadata = metadata encEntry
                                        }
