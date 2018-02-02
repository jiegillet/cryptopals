{-# LANGUAGE OverloadedStrings #-}

import           Encodings
import           AES128
import Data.ByteString.Lazy (ByteString)
import qualified Data.ByteString.Lazy as B
import qualified Data.ByteString.Lazy.Char8 as C hiding (ByteString)
import Data.Int (Int64)
import Data.Word (Word8)
import System.Random
import Control.Exception
import Control.Monad (filterM)

-- Ex 17

messages = ["MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
            "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
            "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
            "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
            "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
            "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
            "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
            "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
            "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
            "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"]

validPadding :: (ByteString -> ByteString) -> ByteString -> IO Bool
validPadding _ "" = return True
validPadding decoder cypher = catch (if "" /= decoder cypher
                                       then return True
                                       else undefined)
                                     oops
  where oops :: EncodingException -> IO Bool
        oops e = return False

breakCBC :: ByteString -> ByteString -> (ByteString -> IO Bool) -> IO ByteString
breakCBC cyphertext iv check = undefined --do
--   let s = B.length iv
--       b = chunksOf s cyphertext
--       breakBlock prev b = B.concat <$> getByte s []
--         where getByte 0 bytes = return bytes
--               getByte i bytes = do
--                 sol <- filterM tryByte [0.255]
--                 rest <- getByte (i-1) (B.cons (head sol) bytes)
--                 return rest
--               tryByte z = check $ C.conct [B.take (i-1) b, z, bytes]
--
--   blocks <- sequence $ zipWith breakBlock (iv:b) b
--   return $ B.concat blocks


ex17 = do
  key <- B.pack . take 16 . randoms <$> newStdGen
  iv <- B.pack . take 16 . randoms <$> newStdGen
  msg <- (messages!!) <$> randomRIO (0,9)
  let cyphertext = encodeAES128CBC key iv $ base64ToByteString msg
      check = validPadding (decodeAES128CBC key iv)
  plain <- breakCBC cyphertext iv check
  print plain
