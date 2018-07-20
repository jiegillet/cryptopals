{-# LANGUAGE OverloadedStrings #-}

import           System.IO
import           System.Random
import           Encodings
import           Hashes
import           Network
import           Control.Concurrent
import qualified Data.ByteString.Lazy as B
import           Text.ParserCombinators.ReadP

main = withSocketsDo $ do
  key <- B.pack . take 16 . randoms <$> newStdGen
  print $ byteStringToHex $ getHMAC key ";user=admin;"
  sock <- listenOn $ PortNumber 8000
  loop key sock
    where loop key sock = do
          (h,_,_) <- accept sock
          forkIO $ treatRequest key h
          loop key sock

treatRequest :: ByteString -> Handle -> IO ()
treatRequest key h = do
  request <- hGetLine h
  let ((file, hash),_) = last $ readP_to_S parsePair request
      hash' = getHMAC key (hexToByteString file)
  check <- insecureCompare (hexToByteString hash) hash'
  if check
    then hPutStr h "HTTP/1.0 200 OK\r\nContent-Length: 4\r\n\r\nYay!\r\n"
    else hPutStr h "HTTP/1.0 500 Internal Error\r\nContent-Length: 6\r\n\r\nSorry!\r\n"
  hFlush h
  hClose h

getHMAC :: ByteString -> ByteString -> ByteString
getHMAC key = hMAC sha1 64 key

insecureCompare ::  ByteString -> ByteString -> IO Bool
insecureCompare "" "" = return True
insecureCompare "" _ = return False
insecureCompare _ "" = return False
insecureCompare h1 h2 = do
  -- threadDelay 50000 -- Ex31
  threadDelay 20000 -- Ex32
  if B.head h1 == B.head h2
    then insecureCompare (B.tail h1) (B.tail h2)
    else return False

parsePair :: ReadP (String, String)
parsePair = do
  skipMany $ satisfy (/='?')
  string "?file="
  file <- munch (/='&')
  string "&signature="
  hash <- munch (/=' ')
  return (file, hash)
