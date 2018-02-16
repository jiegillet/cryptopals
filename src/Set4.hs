{-# LANGUAGE OverloadedStrings #-}

import           Encodings
import           AES128
import           Set2
import qualified Data.ByteString.Lazy as B
import qualified Data.ByteString.Lazy.Char8 as C
import           System.Random
import           Control.Exception
import           Test.QuickCheck (quickCheck)
import           Data.List (foldl', zipWith4)
import           Data.Bits

-- Ex 25

edit :: ByteString -> ByteString -> Int64 -> ByteString -> ByteString
edit cypher key offset newtext
  | B.null newtext           = cypher
  | B.null cypher            = encodeAES128CTR key (0, 0) newtext
  | offset < 0               = edit cypher key 0 newtext
  | offset > B.length cypher = edit cypher key (B.length cypher) newtext
  | otherwise                = B.concat [pre, change core, post]
  where
  (n, off) = quotRem offset 16
  (pre, tmp) = B.splitAt (16 * n) cypher
  (core, post) = B.splitAt (off + B.length newtext) tmp
  change = encodeAES128CTR key (0, fromIntegral n) .
           replace off newtext .
           decodeAES128CTR key (0, fromIntegral n)

replace :: Int64 -> ByteString -> ByteString -> ByteString
replace off new old = let (pre, mid) = B.splitAt off old
                          (_, post) = B.splitAt (B.length new) mid
                      in B.concat [pre, new, post]

prop_edit :: String -> String -> Int64 -> Bool
prop_edit txt' new' offset = replace offset new txt == edited
  where txt = C.pack txt'
        new = C.pack new'
        key = "YELLOW SUBMARINE"
        edited = decodeAES128CTR key (0, 0) $
                 (\cypher -> edit cypher key offset new) $
                 encodeAES128CTR key (0, 0) txt

ex25 = do
  key <- B.pack . take 16 . randoms <$> newStdGen
  r <- base64ToByteString . filter (/= '\n') <$> readFile "../doc/25.txt"
  let plain = decodeAES128ECB "YELLOW SUBMARINE" r
      seed = (0, 0)
      cypher = decodeAES128CTR key seed plain
      editAPI cypher offset newtext = edit cypher key offset newtext
  putStrLn $ C.unpack $  editAPI cypher 0 cypher

-- Ex 26

addAdmin :: (ByteString -> ByteString) -> (ByteString -> Bool) -> ByteString
addAdmin encoder check = cyphertext
  where offset = let a = encoder "a"
                     b = encoder "b"
                 in fromIntegral $ length $ takeWhile id $ B.zipWith (==) a b
        msg = encoder "_admin|true_"
        xorMe = xorB "_admin|true_" ";admin=true;"
        (pre, tmp) = B.splitAt offset msg
        (core, post) = B.splitAt 12 tmp
        cyphertext = B.concat [pre, xorB xorMe core, post]

ex26 = do
  key <- B.pack . take 16 . randoms <$> newStdGen
  let prefix  = "comment1=cooking%20MCs;userdata="
      postfix = ";comment2=%20like%20a%20pound%20of%20bacon"
      escape = B.filter (not . flip B.elem ";=")
      encoder = encodeAES128CTR key (0, 0) . (\x -> B.concat [prefix, x, postfix]) . escape
      decoder = decodeAES128CTR key (0, 0)

  let cyphertext = addAdmin encoder (isAdmin decoder)
  print $ decoder cyphertext
  print $ isAdmin decoder cyphertext

-- Ex 27

asciiCompliant :: (ByteString -> ByteString) -> ByteString -> Bool
asciiCompliant decoder cypher
  | B.all (<128) plain = True
  | otherwise          = throw (ASCIIComplianceException plain)
  where plain = decoder cypher

findKey :: (ByteString -> Bool) -> ByteString -> IO ByteString
findKey check cypher = do
  let oops (ASCIIComplianceException e) = return e
      (c1:_:_:rest) = chunksOf 16 cypher
      cypher' = B.concat [c1, B.replicate 16 0, c1, B.concat rest]
  msg <- catch (check cypher' `seq` return "") oops
  let (p1:_:p3:_) = chunksOf 16 msg
  return $ xorB p1 p3

ex27 = do
  key <- B.pack . take 16 . randoms <$> newStdGen
  let prefix  = "comment1=cooking%20MCs;userdata="
      postfix = ";comment2=%20like%20a%20pound%20of%20bacon"
      p = (key, key, prefix, postfix, 2)
      encoder = encryptionOracle p . B.filter (not . flip B.elem ";=")
      check = asciiCompliant (decryptionOracle p)
  k <- findKey check (encoder "this doesn't matter")
  print k
  print $ k==key

-- Ex 28

splitInt64 :: Int64 -> [Word8]
splitInt64 n = reverse $ take 8 $ go n
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

prop_words :: [Word32] -> Bool
prop_words w = w ==  toWord32 (fromWord32 w)

sha1 :: ByteString -> ByteString
sha1 = preprocess--combine . foldl' addChunk h . chunksOf 64 . preprocess
  where
  h = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)
  preprocess s = flip B.append end . flip B.append pad . flip B.snoc 128 $ s
    where m1 = B.length s
          pad = B.replicate (mod (56-(m1 + 1)) 64) 0
          end = B.pack $ splitInt64 m1
  combine (h0,h1,h2,h3,h4) = fromWord32 [h0,h1,h2,h3,h4]
  addChunk hs@(h0,h1,h2,h3,h4) s = addtoH $ foldl' crunch hs $ zip [0..79] w
    where w = toWord32 s ++ zipWith4 xor4 w (drop 2 w) (drop 8 w) (drop 13 w)
          xor4 a b c d = (xor a b `xor` xor c d) `rotateL` 1
          addtoH (a,b,c,d,e) = (h0+a,h1+b,h2+c,h3+d,h4+e)
  crunch (a,b,c,d,e) (i, word) = (t, a, rotateL b 30, c, d)
    where (f, k) = fAndK i
          t = rotateL a 5 + f + e + k + word
          fAndK i
            | i < 20    = ((b .&. c) .|. ((complement b) .&. d) , 0x5A827999)
            | i < 40    = (b `xor` c `xor` d                    , 0x6ED9EBA1)
            | i < 60    = ((b .&. c) .|. (b .&. d) .|. (c .&. d), 0x8F1BBCDC)
            | otherwise = (b `xor` c `xor` d                    , 0xCA62C1D6)
