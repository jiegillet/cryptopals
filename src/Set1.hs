{-# LANGUAGE OverloadedStrings #-}

module Set1 (charFrequencies) where

import           Encodings
import qualified Data.Map                   as M
import qualified Data.ByteString.Lazy       as B
import qualified Data.ByteString.Lazy.Char8 as C
import           Data.List (sortOn, sort, maximumBy)
import           Data.Function (on)
import           Data.Bits
import           Data.Char (ord, isAlphaNum)

-- Ex 1: Hex to Base64
ex1 = do
  let h = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
      b = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
  print $ hexToBase64 h == b
  print $ base64ToHex b == h
  print $ base64ToByteString b

-- Ex 2: fixed XOR
ex2 = do
  let h1 = "1c0111001f010100061a024b53535009181c"
      h2 = "686974207468652062756c6c277320657965"
      h = "746865206b696420646f6e277420706c6179"
  print $ hexXor h1 h2 == h
  print $ hexToByteString h

-- Ex 3: Single-byte XOR cipher

getCharFrequencies :: IO [(Word8, Int)]
getCharFrequencies = do
  r <- B.readFile "../doc/pride_and_prejudice.txt"
  let freq :: M.Map Word8 Int
      freq = M.fromListWith (+) $ zip (B.unpack r) (repeat 1)
      alph = sortOn (negate . snd) $ M.assocs freq
  return alph

-- Copy paste from function getCharFrequencies (to drop IO)
charFrequencies :: [(Word8, Int)]
charFrequencies =
  [(32,113941),(101,70345),(116,47284),(97,42155),(111,41139),(110,38430),
  (105,36273),(104,33882),(114,33293),(115,33292),(100,22247),(108,21282),
  (117,15439),(10,13427),(13,13427),(109,13401),(99,13397),(121,12653),
  (102,12177),(119,11922),(103,10161),(44,9280),(112,8386),(98,8249),(46,6396),
  (118,5811),(128,4301),(226,4301),(107,3241),(73,2674),(156,1802),(157,1751),
  (77,1723),(59,1538),(45,1196),(66,1114),(122,933),(84,877),(120,865),(69,856),
  (95,808),(76,788),(153,723),(72,701),(67,667),(87,651),(106,638),(113,637),
  (68,597),(83,578)]

singleByteXor :: ByteString -> (ByteString, ByteString)
singleByteXor h = (B.singleton c, decoded)
  where freq = M.fromListWith (+) $ zip (B.unpack h) (repeat 1)
        alph = sortOn (negate . (freq M.!)) $ M.keys freq
        c = xor (head alph) (fst $ head $ charFrequencies)
        decoded = B.map (xor c) h

ex3 = singleByteXor $ hexToByteString "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

-- Ex 4

ex4 = do
  r <- C.lines <$> B.readFile "../doc/4.txt"
  let unXored = map (snd . singleByteXor . hexToByteString . C.unpack) r
      countAlpha = length . (filter isAlphaNum) . C.unpack
  print $ head $ sortOn (negate . countAlpha) unXored

-- Ex 5

ex5 = xorWith "ICE" "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"

xorWith :: ByteString -> ByteString -> Hex
xorWith key b = byteStringToHex $ xorB (cycleB key) b
  where cycleB = B.pack . cycle . B.unpack

-- Ex 6

ex6 = do
  r <- C.unpack . B.filter (/= B.head "\n") <$> B.readFile "../doc/6.txt"
  let (key, plain) = breakKeyXor $ base64ToByteString r
  C.putStrLn key
  C.putStrLn plain

hammingDist :: ByteString -> ByteString -> Int
hammingDist a b = sum $ map popCount $ B.zipWith xor a b

breakKeyXor :: ByteString -> (ByteString, ByteString)
breakKeyXor b = (B.concat key, B.concat $ B.transpose msg)
  where keyLengths = sort $ map (keyDist b) [2..40]
        tries = map tryKey $ take 5 $ map snd keyLengths
        tryKey k = unzip $ map singleByteXor $ B.transpose $ chunksOf k b
        (key, msg) = maximumBy (compare `on` countAlpha) tries
        countAlpha = length . (filter isAlphaNum) . C.unpack . B.concat . snd


keyDist :: (Fractional a) => ByteString -> Int64 -> (a, Int64)
keyDist txt n = ( (fromIntegral d)/(fromIntegral n), n)
  where d = dist $ B.take (10*n) txt
        dist t
          | t==B.empty = 0
          | otherwise  = let (t1, t2) = B.splitAt (2*n) t
                             (a, b) = B.splitAt n t1
                         in hammingDist a b + dist t2
