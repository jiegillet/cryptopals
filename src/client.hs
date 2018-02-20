{-# LANGUAGE OverloadedStrings #-}

import Network.HTTP
import Data.Time.Clock.POSIX
import Encodings
import Data.List (sort)
import qualified Data.ByteString.Lazy as B

main = do
  choices <- flip zip [0..] <$> mapM checkletter [0..255]
  print $ sort choices

checkletter :: Word8 -> IO POSIXTime
checkletter i = do
  let hash = byteStringToHex $ B.pack [i, i]
      pre = "http://localhost:8000/test?file="
      file = byteStringToHex ";user=admin;"
      sep = "&signature="
      request = pre ++ file ++ sep ++ hash
  t0 <- getPOSIXTime
  response <- simpleHTTP (getRequest request)
  t1 <- getPOSIXTime
  (c,_,_) <- getResponseCode response
  return (t1-t0)
