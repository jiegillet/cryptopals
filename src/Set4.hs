{-# LANGUAGE OverloadedStrings #-}

import           Encodings
import           AES128
import qualified Data.ByteString.Lazy as B
import qualified Data.ByteString.Lazy.Char8 as C
import           System.Random
import           Test.QuickCheck (quickCheck)

-- Ex 25

edit :: ByteString -> ByteString -> Int64 -> ByteString -> ByteString
edit cypher key offset newtext
  | B.null newtext           = cypher
  | B.null cypher            = encodeAES128CTR key (0, 0) newtext
  | offset < 0               = edit cypher key 0 newtext
  | offset > B.length cypher = edit cypher key (B.length cypher) newtext
  | otherwise                = B.concat [pre, blocks core, post]
  where
  (n, off) = quotRem offset 16
  (pre, tmp) = B.splitAt (16 * n) cypher
  (core, post) = B.splitAt (off + B.length newtext) tmp
  blocks = encodeAES128CTR key (0, fromIntegral n) .
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
  let seed = (0, 0)
      cypher = decodeAES128CTR key seed  r
  print 1
