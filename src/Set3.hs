{-# LANGUAGE OverloadedStrings #-}

import           Encodings
import           AES128
import           Set1
import           Data.ByteString.Lazy (ByteString)
import qualified Data.ByteString.Lazy as B
import qualified Data.ByteString.Lazy.Char8 as C hiding (ByteString)
import           Data.Int (Int64)
import           Data.Word (Word8, Word32, Word64)
import           System.Random
import           Control.Exception
import           Control.Monad (filterM)
import           Data.Function (on)
import           Data.Bits
import           Data.List (maximumBy)

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
validPadding decoder cypher = catch (decoder cypher `seq` return True) oops
  where oops :: EncodingException -> IO Bool
        oops e = return False

breakCBC :: ByteString -> ByteString -> (ByteString -> IO Bool) -> IO ByteString
breakCBC cyphertext iv check = do
  let s = B.length iv
      b = chunksOf s cyphertext
  blocks <- sequence $ zipWith (breakBlock s check) (iv:b) b
  return $ B.concat blocks

breakBlock :: Int64 -> (ByteString -> IO Bool) -> ByteString -> ByteString -> IO ByteString
breakBlock s check b1 b2 = getByte (s-1) ""
  where
  getByte (-1) bytes = return bytes
  getByte i bytes = do
    let rep = B.replicate
        tryByte z = let a = B.append (rep i 0) (B.cons z bytes)
                        b = B.append (rep i 0) (rep (s-i) (fromIntegral (s-i)))
                    in B.append (xorB b1 (xorB a b)) b2
    sol <- filterM (check . tryByte) [0..255]
    if null sol
    then return ""
    else B.concat <$> mapM (\x -> getByte (i-1) (B.cons x bytes)) sol

ex17 = do
  key <- B.pack . take 16 . randoms <$> newStdGen
  iv <- B.pack . take 16 . randoms <$> newStdGen
  msg <- randomRIO (0,9)
  let cyphertext = encodeAES128CBC key iv $ base64ToByteString (messages!!msg)
      check = validPadding (decodeAES128CBC key iv)
  plain <- breakCBC cyphertext iv check
  print $ stripPkcs7 16 plain

-- Ex 18

littleEndian :: (Integral a) => a -> [Word8]
littleEndian i = go (fromIntegral i :: Word64) 1
  where go _ 9 = []
        go n k = let (q, r) = quotRem n 256 in fromIntegral r : go q (k+1)

ex18 = do
  let key = "YELLOW SUBMARINE"
      seed = (0, 0)
      format :: (Int64, Word64) -> (ByteString, (Int64, Word64))
      format (n, c) = (B.pack $ littleEndian n ++ littleEndian c , (n, c+1))
      txt = base64ToByteString "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
  print $ decodeAES128CTR key seed format txt

-- ex 19

bestFit :: ByteString -> Word8
bestFit b = maximumBy (compare `on` score . decode b) [0..255]
  where score = length . filter letter . C.unpack
        decode s c = B.map (xor c) s
        letter x = x `elem` ['a'..'z']++['A'..'Z']++[',','.',' ']

ex19 = do
  r <- lines <$> readFile "../doc/19.txt"
  key <- B.pack . take 16 . randoms <$> newStdGen
  let seed = (0, 0)
      format :: (Int64, Word64) -> (ByteString, (Int64, Word64))
      format (n, c) = (B.pack $ littleEndian n ++ littleEndian c , (n, c+1))
      cypher = map (decodeAES128CTR key seed format . base64ToByteString) r
      k = B.pack $ map bestFit $ B.transpose cypher
      plain = map (xorB k) cypher
  mapM_ C.putStrLn plain

-- ex 20: Not great results but not great interest in this one. Bestfit method works much better

deXor :: Int64 -> [ByteString] -> (ByteString, ByteString)
deXor k b = (B.concat key, B.concat $ B.transpose msg)
  where (key, msg)  = unzip $ map singleByteXor $ B.transpose b

ex20 = do
  r <- lines <$> readFile "../doc/20.txt"
  key <- B.pack . take 16 . randoms <$> newStdGen
  let seed = (0, 0)
      format :: (Int64, Word64) -> (ByteString, (Int64, Word64))
      format (n, c) = (B.pack $ littleEndian n ++ littleEndian c , (n, c+1))
      cypher = map (decodeAES128CTR key seed format . base64ToByteString) r
      n = maximum $ map B.length cypher
      cypher' =  map (B.take n) cypher
      (k, plain) = deXor n cypher'
  C.putStrLn plain

-- ex 21

mkSeedMT19937 :: Word32 -> [Word32]
mkSeedMT19937 s0 = drop (fromIntegral n) x
  where x = s ++ zipWith3 comb x (tail x) (drop m x)
        comb x0 x1 xm = let pick i b = b .|. (bit i .&. if i<r then x1 else x0)
                        in xm `xor` twist (foldr pick zeroBits [0..w-1])
        twist b = if testBit b 0 then a `xor` shiftR b 1 else shiftR b 1
        s = s0 : zipWith (\x i -> f*(x `xor` shiftR x (w-2)) +i) s [1..n-1]
        (w, n, m, r) = (32, 624, 397, 31)
        a = 0x9908B0DF
        f = 1812433253

mt19937 :: [Word32] -> (Word32, [Word32])
mt19937 (x:xs) = (tempering x, xs)
  where
  tempering = (\y -> xor y (shiftR y l)) . (\y -> xor y (c .&. shiftL y t)) .
              (\y -> xor y (b .&. shiftL y s)) . (\y -> xor y (shiftR y u))
  (u, d) = (11, 0xFFFFFFFF)
  (s, b) = (7,  0x9D2C5680)
  (t, c) = (15, 0xEFC60000)
  l = 18
