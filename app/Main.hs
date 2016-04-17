module Main where

import Lib
import Crypto.Saltine as Sodium
import Vault
import Entry

main :: IO ()
main = do
  entryKey <- Sodium.newKey
  encEntry <- encryptEntry e entryKey
  
  let newV = putEntry v "foo" encEntry
  print $ Vault.vaultLen v
  print $ Vault.vaultLen newV
  print "Created v!"
  where v = newVault
        e = newEntry
        md = newMetaData
        
