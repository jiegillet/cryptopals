{-# LANGUAGE OverloadedStrings #-}

module EncodingsStrict (ByteString, Int, Word8, Word32, Word64,
                  Base64,
                  Hex,
                  splitInt,
                  toWord32,
                  fromWord32,
                  base64ToHex,
                  hexToBase64,
                  base64ToByteString,
                  byteStringToBase64,
                  hexToByteString,
                  byteStringToHex,
                  hexXor,
                  xorB,
                  chunksOf,
                  littleEndian
                  ) where

import           Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C hiding (ByteString)
import           Data.Word (Word8, Word32, Word64)
import qualified Data.Map as M
import           Numeric (showHex)
import           Data.Bits (xor)
import           Data.List (unfoldr)


type Base64 = String
type Hex    = String

base64Alphabet :: Base64
base64Alphabet = ['A'..'Z'] ++ ['a'..'z'] ++ ['0'..'9'] ++ "+/"

hexAlphabet :: Hex
hexAlphabet = ['0'..'9'] ++ ['a'..'f']

base64ToBits :: M.Map Char String
base64ToBits = M.fromList $ zip base64Alphabet $ sequence (replicate 6 "01")

bitsToBase64 :: M.Map String Char
bitsToBase64 = M.fromList $ zip (sequence (replicate 6 "01")) base64Alphabet

hexToBits :: M.Map Char String
hexToBits = M.fromList $ zip hexAlphabet (sequence (replicate 4 "01"))

bitsToHex :: M.Map String Char
bitsToHex = M.fromList $ zip (sequence (replicate 4 "01")) hexAlphabet

hexToInt :: M.Map Char Int
hexToInt = M.fromList $ zip hexAlphabet [0..15]

base64ToBytes :: Base64 -> [Hex]
base64ToBytes []             = []
base64ToBytes [a, b,'=','='] = take 1 $ threeBytes [a, b, 'A', 'A']
base64ToBytes [a, b, c,'=']  = take 2 $ threeBytes [a, b, c, 'A']
base64ToBytes b              = threeBytes (take 4 b) ++ base64ToBytes (drop 4 b)

threeBytes :: Base64 -> [Hex]
threeBytes = bytesToHex . concatMap (base64ToBits M.!)

bytesToHex :: String -> [Hex]
bytesToHex [] = []
bytesToHex x  = let h1 = bitsToHex M.! (take 4 x)
                    h2 = bitsToHex M.! (take 4 $ drop 4 x)
                in [h1, h2]  : bytesToHex (drop 8 x)

base64ToHex :: Base64 -> Hex
base64ToHex = concat . base64ToBytes

hexToBase64 :: Hex  -> Base64
hexToBase64 h
  | null h        = []
  | length h == 2 = take 2 (fourB64 (h++"0000")) ++ "=="
  | length h == 4 = take 3 (fourB64 (h++"00")) ++ "="
  | otherwise     = fourB64 (take 6 h) ++ hexToBase64 (drop 6 h)
  where fourB64 = toB64 . concatMap (hexToBits M.!)
        toB64 [] = []
        toB64 x  = bitsToBase64 M.! (take 6 x) : toB64 (drop 6 x)

base64ToByteString :: Base64 -> ByteString
base64ToByteString = hexToByteString . base64ToHex

byteStringToBase64 :: ByteString -> Base64
byteStringToBase64 = hexToBase64 . byteStringToHex

hexToByteString :: Hex -> ByteString
hexToByteString = B.pack . map fromIntegral . val
  where val (h1:h2:rest) = (hexToInt M.! h1)*16 + (hexToInt M.! h2) : val rest
        val _ = []

byteStringToHex :: ByteString -> Hex
byteStringToHex = concatMap (pad . flip showHex "") . B.unpack
  where pad [a] = ['0', a]
        pad s   = s

hexXor :: Hex -> Hex -> Hex
hexXor a b = concat $ bytesToHex $ zipWith myXor a' b'
  where a' = concatMap (hexToBits M.!) a
        b' = concatMap (hexToBits M.!) b
        myXor '0' '1' = '1'
        myXor '1' '0' = '1'
        myXor _ _     = '0'

xorB :: ByteString -> ByteString -> ByteString
xorB a b = B.pack $ B.zipWith xor a b

chunksOf :: Int -> ByteString -> [ByteString]
chunksOf _ "" = []
chunksOf n s  = let (a,b) = B.splitAt n s in a : chunksOf n b

littleEndian :: Word32 -> Word32
littleEndian i = go i 3
  where go _ (-1) = 0
        go n k = let (q, r) = quotRem n 256 in 256^k * r + go q (k-1)

splitInt :: Int -> [Word8]
splitInt n = reverse $ take 8 $ go n
  where go 0 = repeat 0
        go n = let (q, r) = quotRem n 256 in fromIntegral r : go q

toWord32 :: ByteString -> [Word32]
toWord32 "" = []
toWord32 s = B.foldl (\t b -> 256 * t + fromIntegral b) 0 a : toWord32 b
  where (a, b) = B.splitAt 4 s

fromWord32 :: [Word32] -> ByteString
fromWord32 = B.pack . concatMap (reverse . take 4 . toWord8)
  where toWord8 0 = repeat 0
        toWord8 n = let (q, r) = quotRem n 256 in fromIntegral r : toWord8 q
