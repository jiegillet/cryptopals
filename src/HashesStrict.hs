{-# LANGUAGE OverloadedStrings #-}

module HashesStrict (padMD4,
               md4,
               md4With,
               padSHA1,
               sha1,
               sha1With,
               sha256,
               sha256With,
               hMAC
               ) where

import           EncodingsStrict
import qualified Data.ByteString as B
import           Data.Bits
import           Data.List (zipWith4, foldl')
import           Data.Array

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
        end = B.pack $ splitInt (8*m1)

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

hMAC :: (ByteString -> ByteString) -> Int -> ByteString -> ByteString -> ByteString
hMAC hash size key' msg = hash $ B.append oKeyPad (hash $ B.append iKeyPad msg)
  where kl = B.length key'
        key
          | kl > size = hash key'
          | otherwise = B.append key' (B.replicate (size-kl) 0)
        oKeyPad = xorB key $ B.replicate (B.length key) 0x5C
        iKeyPad = xorB key $ B.replicate (B.length key) 0x36

-- SHA-256

sha256 :: ByteString -> ByteString
sha256 = sha256With register . padSHA1
  where register = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

sha256With :: [Word32] -> ByteString -> ByteString
sha256With h = fromWord32 . foldl' addChunk h . chunksOf 64
  where
  addChunk hs s = zipWith (+) hs $ foldl' crunchW hs $ zip w k
    where w = toWord32 s ++ zipWith4 makeW (drop 14 w) (drop 9 w) (drop 1 w) w
          makeW a b c d = sig1 a + b + sig0 c + d
  crunchW [a,b,c,d,e,f,g,h] (word, k) = [t1 + t2, a, b, c, d + t1, e, f, g]
    where t1 = h + sum1 e + ch e f g + k + word
          t2 = sum0 a + maj a b c
  k = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
       0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
       0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
       0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
       0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
       0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
       0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
       0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]
  ch x y z = (x .&. y) `xor` (complement x .&. z)
  maj x y z = (x .&. y) `xor` (x .&. z) `xor` (y .&. z)
  sum0 x = rotateR x 2 `xor` rotateR x 13 `xor` rotateR x 22
  sum1 x = rotateR x 6 `xor` rotateR x 11 `xor` rotateR x 25
  sig0 x = rotateR x 7 `xor` rotateR x 18 `xor` shiftR x 3
  sig1 x = rotateR x 17 `xor` rotateR x 19 `xor` shiftR x 10
