{-# LANGUAGE OverloadedStrings #-}

module Encodings (ByteString, Int64, Word8,
                  Base64,
                  Hex,
                  base64ToHex,
                  hexToBase64,
                  base64ToByteString,
                  byteStringToBase64,
                  hexToByteString,
                  byteStringToHex,
                  hexXor,
                  xorB,
                  chunksOf
                  ) where

import           Data.ByteString.Lazy (ByteString)
import qualified Data.ByteString.Lazy as B
import qualified Data.ByteString.Lazy.Char8 as C hiding (ByteString)
import           Data.Int (Int64)
import           Data.Word (Word8)
import qualified Data.Map as M
import           Numeric (showHex)
import           Data.Bits (xor)


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

chunksOf :: Int64 -> ByteString -> [ByteString]
chunksOf _ "" = []
chunksOf n s  = let (a,b) = B.splitAt n s in a : chunksOf n b
