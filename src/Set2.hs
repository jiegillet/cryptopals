{-# LANGUAGE OverloadedStrings #-}

module Set2 where

import           Encodings
import           AES128
import qualified Data.Map                   as M
import qualified Data.IntMap                as IM
import qualified Data.ByteString.Lazy       as B
import qualified Data.ByteString.Lazy.Char8 as C
import           Data.List (group, unfoldr, group, sort)
import           Data.Function (on)
import           Data.Bits
import           Data.Char (chr, ord, isAlphaNum)
import           System.Random
import           Control.Monad (replicateM_)
import           Text.ParserCombinators.ReadP
import           Test.QuickCheck

type Parameters = (ByteString, ByteString, ByteString, ByteString, Int)

encryptionOracle :: Parameters -> ByteString -> ByteString
encryptionOracle (key, iv, prefix, postfix, mode) txt =
  if mode == 1
  then encodeAES128ECB key $ B.concat [prefix, txt, postfix]
  else encodeAES128CBC key iv $ B.concat [prefix, txt, postfix]

decryptionOracle :: Parameters -> ByteString -> ByteString
decryptionOracle (key, iv, _, _, mode) txt =
  if mode == 1
  then decodeAES128ECB key txt
  else decodeAES128CBC key iv txt

-- ex 7

ex7  = do
  r <- base64ToByteString . filter (/= '\n') <$> readFile "../doc/7.txt"
  putStr $ C.unpack $ decodeAES128ECB "YELLOW SUBMARINE" r

-- ex 8

ex8  = do
  r <- map hexToByteString . lines <$> readFile "../doc/8.txt"
  let encoded = filter (any (>1) . map length . group . sort . chunksOf 16) r
  mapM_ print encoded

-- ex 9

ex9 = print $ pkcs7 20 "YELLOW SUBMARINE"

-- ex 10

ex10  = do
  r <- base64ToByteString . filter (/= '\n') <$> readFile "../doc/10.txt"
  putStr $ C.unpack $ decodeAES128CBC "YELLOW SUBMARINE" (B.pack $ replicate 16 0) r

-- ex 11

detectCypherMode :: (ByteString -> ByteString) -> Int
detectCypherMode oracle = if a==b then 1 else 2
  where (_:a:b:_) = chunksOf 16 $ oracle (B.pack $ replicate 64 0)

ex11 = replicateM_ 20 $ do
  key <- B.pack . take 16 . randoms <$> newStdGen
  iv <- B.pack . take 16 . randoms <$> newStdGen
  [nPre, nPost] <- take 2 . randomRs (5,10) <$> newStdGen
  prefix <- B.pack . take nPre . randoms <$> newStdGen
  postfix <- B.pack . take nPost . randoms <$> newStdGen
  mode <- randomRIO (1,2)
  let p = (key, iv, prefix, postfix, mode)
  print (mode, detectCypherMode (encryptionOracle p))

-- ex 12


-- returns block size, length of prefix+postfix (works even with CBC)
-- length of prefix, length of postfix (work only with ECB)
-- Might fail if \NULL is part of the postfix
findEncoderSizes :: (ByteString -> ByteString) -> (Int64, Int64, Int64, Int64)
findEncoderSizes encoder = (s64, preAndPost, pre, post)
  where increasing = map (encoder .flip B.replicate 0) [0..]
        (a:b:_) = group $ map B.length increasing
        s = length b
        s64 = fromIntegral s
        preAndPost = head a - (fromIntegral $ length a) + 1
        ((n, cy):_) = filter twoIdenticalBlocks $ drop (2*s) $ zip [0..] increasing
        twoIdenticalBlocks = any ((>1) . length) . group . chunksOf s64 . snd
        (pre, post)
          | B.length cy == n            = (0, 0)
          | head ch == (head $ tail ch) = (0, preAndPost)
          | last ch == (last $ init ch) = (preAndPost, 0)
          | otherwise                   = let p= z*s64 - n in (p, preAndPost - p)
          where ch = chunksOf s64 cy
                ((z,_):_) = dropWhile ((==1) . length . snd) $ zip [2..] (group ch)

-- run: quickCheck prop_EncoderSizes
prop_EncoderSizes :: String -> String -> Bool
prop_EncoderSizes a b = B.elem 0 (C.pack a) || B.elem 0 (C.pack b) ||
  (16, fromIntegral $ length (a++b) ,fromIntegral $ length a, fromIntegral $ length b)
     == findEncoderSizes (encryptionOracle
          ("YELLOW SUBMARINE", "", C.pack a, C.pack b, 1))

getPostfix :: (ByteString -> ByteString) -> ByteString
getPostfix encoder = B.pack post
  where
  (s, _, nPre, nPost) = findEncoderSizes encoder
  post = unfoldr decrypt (B.replicate (s-1) 65, 0)
  decrypt (p, n) = if n == nPost
                   then Nothing
                   else Just (byte, (B.tail $ B.snoc p byte, n+1))
    where byte = head $ filter ((==goal) . addByte) [0..255]
          addByte = B.take s . B.drop preDrop . encoder . B.append preAdd . B.snoc p
          msg = B.append preAdd $ B.replicate (mod (s - n - 1) s) 65
          goal = B.take s $ B.drop (preDrop + s * div n s) $ encoder msg
          preAdd = B.replicate (s - mod nPre s) 65
          preDrop = s *( 1 + div nPre s )

unknown = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"

ex12 = do
  key <- B.pack . take 16 . randoms <$> newStdGen
  let p = (key, "", "", base64ToByteString unknown, 1)
      encoder = encryptionOracle p
      mode = detectCypherMode encoder
      post = getPostfix encoder
  putStrLn $ "Mode: " ++ show mode
  putStrLn $ "Appended message: \n" ++ C.unpack post

-- Ex13

readObj :: ReadP (String, String)
readObj = do
  k <- munch (/= '=')
  char '='
  v <- munch (/= '&')
  return (k, v)

readUser :: ReadP User
readUser = do
  obj <- sepBy readObj (char '&')
  let Just i = read <$> lookup "uid" obj
      Just e = lookup "email" obj
      Just r = lookup "role" obj
  return $ User i e r

parseUser :: String -> User
parseUser = fst . last . readP_to_S readUser

data User = User {uid::Int, email::String, role::String}

instance Show User where
  show u = concat ["email=", email u, "&uid=", show (uid u), "&role=", role u]

profileFor :: String -> User
profileFor email = User 10 (filter (not . flip elem ("&="::String)) email) "user"

ex13 = do
  key <- B.pack . take 16 . randoms <$> newStdGen
  let p = (key, "", "", "", 1)
      encoder = encryptionOracle p . C.pack . show . profileFor . C.unpack

  let (s, _, nPre, nPost) = findEncoderSizes encoder
      (a:b:c:_) = chunksOf s $ encoder "jeremie.gillet@gmail.com+hack" -- 26 long, pushes "user" into a new block
      (_:end:_) = chunksOf s $ encoder $ B.concat [B.replicate (s-nPre) 0, pkcs7 s "admin" ]
  print $ show $ parseUser $ C.unpack $ decodeAES128ECB key $ B.concat [a,b,c,end]


-- Ex 14

ex14 = do
  key <- B.pack . take 16 . randoms <$> newStdGen
  let encoder = encryptionOracle (key, "", "random-prefix", "target-bytes", 1)
  print $ getPostfix encoder

-- Ex 15

ex15 = do
  print $ stripPkcs7 "ICE ICE BABY\x04\x04\x04\x04"
  print $ stripPkcs7 "ICE ICE BABY\x05\x05\x05\x05"

-- Ex 16

readElem :: ReadP (String, String)
readElem = do
  k <- munch (/= '=')
  char '='
  v <- munch (/= ';')
  return (k, v)

readString :: ReadP [(String, String)]
readString = sepBy readElem (char ';')

parseString :: String -> [(String, String)]
parseString = fst . last . readP_to_S readString

isAdmin :: (ByteString -> ByteString) -> ByteString -> Bool
isAdmin decode = (==Just "true") . lookup "admin" . parseString . C.unpack . decode

addAdmin :: (ByteString -> ByteString) -> (ByteString -> Bool) -> ByteString
addAdmin encoder check = cyphertext
  where (s, p, _, _) = findEncoderSizes encoder
        (cyphertext:_) = filter check [ msg b x |b<-[0..s-12], x<-[0..p+b]]
        xorMe = xorB "_admin|true_" ";admin=true;"
        msg b x = let txt = B.append (B.replicate (s+b) 32)  "_admin|true_"
                      cyp = encoder txt
                  in xorB cyp $ B.concat [B.replicate x 0, xorMe, B.repeat 0]

ex16 = do
  key <- B.pack . take 16 . randoms <$> newStdGen
  iv <- B.pack . take 16 . randoms <$> newStdGen
  let prefix  = "comment1=cooking%20MCs;userdata="
      postfix = ";comment2=%20like%20a%20pound%20of%20bacon"
      p = (key, iv, prefix, postfix, 2)
      encoder = encryptionOracle p . B.filter (not . flip B.elem ";=")
      decoder = decryptionOracle p
      
  let cyphertext = addAdmin encoder (isAdmin decoder)
  print $ decoder cyphertext
  print $ isAdmin decoder cyphertext
