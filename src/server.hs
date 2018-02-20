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
  print $ getHMAC key $ byteStringToHex ";user=admin;"
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
      hash' = getHMAC key file
  check <- insecureCompare hash hash'
  if check
    then hPutStr h "HTTP/1.0 200 OK\r\nContent-Length: 4\r\n\r\nYay!\r\n"
    else hPutStr h "HTTP/1.0 500 OK\r\nContent-Length: 6\r\n\r\nSorry!\r\n"
  hFlush h
  hClose h

getHMAC :: ByteString -> Hex -> Hex
getHMAC key = byteStringToHex . hMAC sha1 64 key . hexToByteString

insecureCompare ::  Hex -> Hex -> IO Bool
insecureCompare "" "" = return True
insecureCompare "" _ = return False
insecureCompare _ "" = return False
insecureCompare (h:h1) (h':h2) = do
  threadDelay 50000
  if h==h'
    then insecureCompare h1 h2
    else return False

parsePair :: ReadP (String, String)
parsePair = do
  skipMany $ satisfy (/='?')
  string "?file="
  file <- munch (/='&')
  string "&signature="
  hash <- munch (/=' ')
  return (file, hash)
