module Lib
    ( someFunc
    ) where

import Data.Word (Word8, Word16, Word32)
import Data.Map (Map)
import qualified Data.Map as Map

import Vault
import Entry


someFunc :: IO ()
someFunc = putStrLn "someFunc"
