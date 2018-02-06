{-# LANGUAGE OverloadedStrings #-}

module AES128 (EncodingException,
               pkcs7,
               stripPkcs7,
               encodeAES128ECB,
               decodeAES128ECB,
               encodeAES128CBC,
               decodeAES128CBC,
               encodeAES128CTR,
               decodeAES128CTR
               ) where

import           Encodings
import qualified Data.ByteString.Lazy as B
import qualified Data.ByteString.Lazy.Char8 as C (unpack, lines)
import           Data.Bits
import           Data.Array
import           Control.Exception
import           Data.List (unfoldr)

data EncodingException = PaddingException deriving Show

instance Exception EncodingException

-- with polynomial x^8 + x^4 + x^3 + x + 1
rijndaelMult :: Word8 -> Word8 -> Word8
rijndaelMult a b = mult a b 0
  where mult 0 _ p = p
        mult _ 0 p = p
        mult a b p = let a' = (if a>= 128 then xor 0x1b else id) $ shift a 1
                         b' = shift b (-1)
                         p' = if odd b then xor a p else p
                     in mult a' b' p'

expTable :: Array Word8 Word8
expTable =
  array (0,255) $ (0,1):[ (i, rijndaelMult (expTable!(i-1)) 0x03) | i <- [1..255]]

logTable :: Array Word8 Word8
logTable = array (1,255) [ (expTable!i, i) | i <- [1..255]]

quickMult :: Word8 -> Word8 -> Word8
quickMult 0 _ = 0
quickMult _ 0 = 0
quickMult a b = expTable!(if l<=la || l<=lb then l+1 else l)
  where la = logTable!a
        lb = logTable!b
        l = la + lb

inverse :: Word8 -> Word8
inverse = (expTable!) . (flip subtract 0xff) . (logTable!)

rcon :: Array Int Word8
rcon = listArray (1,10) $ iterate (quickMult 2) 1

sBox :: Array Word8 Word8
sBox = array (0,255) $ (0, 0x63): [ (i, s (inverse i)) | i <- [1..255]]
  where s i = foldr xor 0x63 $ map (rotate i) [0..4]

invSBox :: Array Word8 Word8
invSBox = array (0,255) [ (sBox!i,i) | i <- [0..255]]

keySchedule :: ByteString -> ByteString
keySchedule key = B.concat $ take 11 $ scanl generate key [1..]
  where generate t i  = let k1 = xorB (B.take 4 t) (core i (B.drop 12 t))
                        in B.concat $ scanl xorB k1 $ tail $ chunksOf 4 t
        core i = B.pack . mapFirst (xor (rcon!i)) . map (sBox!) . rotate . B.unpack
        rotate (a:b) = b ++ [a]
        mapFirst f (h:hs) = f h : hs

subBytes :: ByteString -> ByteString
subBytes = B.map (sBox!)

unSubBytes :: ByteString -> ByteString
unSubBytes = B.map (invSBox!)

shiftRows :: ByteString -> ByteString
shiftRows = B.concat . B.transpose . zipWith rot [0..3] . B.transpose . chunksOf 4
  where rot n = B.take 4 . B.drop n . B.cycle

unShiftRows :: ByteString -> ByteString
unShiftRows = B.concat . B.transpose . zipWith rot [4,3..1] . B.transpose . chunksOf 4
  where rot n = B.take 4 . B.drop n . B.cycle

mixColumns :: ByteString -> ByteString
mixColumns = B.concat . map (B.pack . mix . B.unpack) . chunksOf 4
  where
  mix [a,b,c,d] = map (foldr1 xor)
                    [ [quickMult 2 a, quickMult 3 b, c, d],
                       [a, quickMult 2 b, quickMult 3 c, d],
                       [a, b, quickMult 2 c, quickMult 3 d],
                       [quickMult 3 a, b, c, quickMult 2 d]]

unMixColumns :: ByteString -> ByteString
unMixColumns = B.concat . map (B.pack . mix . B.unpack) . chunksOf 4
  where
  mul = quickMult
  mix [a,b,c,d] = map (foldr1 xor)
                    [ [ mul 14 a, mul 11 b, mul 13 c, mul 9 d],
                      [ mul 9 a , mul 14 b, mul 11 c, mul 13 d],
                      [ mul 13 a, mul 9 b , mul 14 c, mul 11 d],
                      [ mul 11 a, mul 13 b, mul 9 c , mul 14 d]]

pkcs7 :: Int64 -> ByteString -> ByteString
pkcs7 n b = B.append b (B.pack $ replicate (fromIntegral diff) (fromIntegral diff))
  where diff = 1 + mod (n - B.length b - 1) n

stripPkcs7 :: Int64 -> ByteString -> ByteString
stripPkcs7 k s
  | B.length g == fromIntegral (B.head g) = B.concat $ init $ B.group s
  | otherwise                             = throw PaddingException
  where g = last $ B.group $ last $ chunksOf k s

encodeAES128ECB :: ByteString -> ByteString -> ByteString
encodeAES128ECB key = B.concat .
                      map (encodeBlockAES128 keyS) .
                      chunksOf 16 .
                      pkcs7 16
  where keyS = keySchedule key

encodeBlockAES128 :: ByteString -> ByteString -> ByteString
encodeBlockAES128 key = encode
  where (k0:ks) = chunksOf 16 key
        encode = lastRound . (\t -> foldl rounds t (init ks)) . xorB k0
        rounds t k = xorB k . mixColumns . shiftRows . subBytes $ t
        lastRound = xorB (last ks) . shiftRows . subBytes

decodeAES128ECB :: ByteString -> ByteString -> ByteString
decodeAES128ECB key =  stripPkcs7 16 .
                       B.concat .
                       map (decodeBlockAES128 keyS) .
                       chunksOf 16
  where keyS = keySchedule key

decodeBlockAES128 :: ByteString -> ByteString -> ByteString
decodeBlockAES128 key = decode
  where (k0:ks) = chunksOf 16 key
        decode =  xorB k0 . (\t -> foldr rounds t (init ks)) . lastRound
        rounds t k = unSubBytes . unShiftRows . unMixColumns . xorB k $ t
        lastRound = unSubBytes . unShiftRows . xorB (last ks)

encodeAES128CBC :: ByteString -> ByteString -> ByteString -> ByteString
encodeAES128CBC key iv = B.concat . tail . scanl encode iv . chunksOf 16 . pkcs7 16
  where keyS = keySchedule key
        encode prev b = encodeBlockAES128 keyS $ xorB prev b

decodeAES128CBC :: ByteString -> ByteString -> ByteString -> ByteString
decodeAES128CBC key iv b = stripPkcs7 16 $ B.concat $ zipWith encode (iv:b') b'
  where keyS = keySchedule key
        b' = chunksOf 16 b
        encode prev b = xorB prev $ decodeBlockAES128 keyS b

encodeAES128CTR :: ByteString -> s -> (s -> (ByteString, s)) -> ByteString -> ByteString
encodeAES128CTR key nonce gen =
  xorB (B.concat $ map (encodeBlockAES128 keyS) $ unfoldr (Just . gen) nonce)
  where keyS = keySchedule key

decodeAES128CTR = encodeAES128CTR
