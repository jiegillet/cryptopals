{-# LANGUAGE OverloadedStrings #-}

module Hashes (padMD4,
               md4,
               md4With,
               padSHA1,
               sha1,
               sha1With,
               hMAC
               ) where

import           Encodings
import qualified Data.ByteString.Lazy as B
import           Data.Bits
import           Data.List (zipWith4, foldl')

-- MD4

padMD4 :: ByteString -> ByteString
padMD4 s = flip B.append end . flip B.append padSHA1 . flip B.snoc 128 $ s
  where m1 = B.length s
        padSHA1 = B.replicate (mod (55-m1) 64) 0
        (h, l) = quotRem (8*m1) (bit 32)
        format = fromWord32 . pure . littleEndian . fromIntegral
        end = B.append  (format l) (format h)

md4 :: ByteString -> ByteString
md4 = md4With buffer . padMD4
  where buffer = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]


md4With :: [Word32] -> ByteString -> ByteString
md4With b = fromWord32 . map littleEndian . foldl' addChunk b . chunksOf 64
  where
  addChunk buff s = zipWith (+) buff $ foldl' (rounds w) buff [0..47]
    where w = map littleEndian $ toWord32 s
  rounds w [a,b,c,d] i = [d, rotateL (a + fi + k + wi ) s, b, c]
    where (fi, k, s, wi)
            | i < 16    = (f, 0         , [3,7,11,19]!!mi, w!!i)
            | i < 32    = (g, 0x5A827999, [3,5,9, 13]!!mi, w!!(4*(mi-1) + div i 4))
            | otherwise = (h, 0x6ED9EBA1, [3,9,11,15]!!mi, w!!(o!!(i-32)))
          mi = mod i 4
          o = [0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15]
          f = (b .&. c) .|. ((complement b) .&. d)
          g = (b .&. c) .|. (b .&. d) .|. (c .&. d)
          h = b `xor` c `xor` d

-- SHA-1

padSHA1 :: ByteString -> ByteString
padSHA1 s = flip B.append end . flip B.append padSHA1 . flip B.snoc 128 $ s
  where m1 = B.length s
        padSHA1 = B.replicate (mod (56-(m1 + 1)) 64) 0
        end = B.pack $ splitInt64 (8*m1)

sha1 :: ByteString -> ByteString
sha1 = sha1With register . padSHA1
  where register = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]

sha1With :: [Word32] -> ByteString -> ByteString
sha1With h = fromWord32 . foldl' addChunk h . chunksOf 64
  where
  addChunk hs s = addtoH $ foldl' crunchW hs $ zip [0..79] w
    where w = toWord32 s ++ zipWith4 xor4 w (drop 2 w) (drop 8 w) (drop 13 w)
          xor4 a b c d = (xor a b `xor` xor c d) `rotateL` 1
          addtoH = zipWith (+) hs
  crunchW [a,b,c,d,e] (i, word) = [t, a, rotateL b 30, c, d]
    where (f, k) = fAndK i
          t = rotateL a 5 + f + e + k + word
          fAndK i
            | i < 20    = ((b .&. c) .|. ((complement b) .&. d) , 0x5A827999)
            | i < 40    = (b `xor` c `xor` d                    , 0x6ED9EBA1)
            | i < 60    = ((b .&. c) .|. (b .&. d) .|. (c .&. d), 0x8F1BBCDC)
            | otherwise = (b `xor` c `xor` d                    , 0xCA62C1D6)

-- HMAC

hMAC :: (ByteString -> ByteString) -> Int64 -> ByteString -> ByteString -> ByteString
hMAC hash size key' msg = hash $ B.append oKeyPad (hash $ B.append iKeyPad msg)
  where kl = B.length key'
        key
          | kl > size = hash key'
          | otherwise = B.append key' (B.replicate (size-kl) 0)
        oKeyPad = xorB key $ B.repeat 0x5C
        iKeyPad = xorB key $ B.repeat 0x36
