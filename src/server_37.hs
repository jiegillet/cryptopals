{-# LANGUAGE OverloadedStrings #-}

import Set5
import EncodingsStrict
import HashesStrict
import System.Random

import Control.Concurrent (forkFinally)
import qualified Control.Exception as E
import Control.Monad (unless, forever, void)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import Network.Socket hiding (recv)
import Network.Socket.ByteString (recv, sendAll)

main :: IO ()
main = withSocketsDo $ do
    addr <- resolve "3000"
    E.bracket (open addr) close loop
  where
    resolve port = do
        let hints = defaultHints {
                addrFlags = [AI_PASSIVE]
              , addrSocketType = Stream
              }
        addr:_ <- getAddrInfo (Just hints) Nothing (Just port)
        return addr
    open addr = do
        sock <- socket (addrFamily addr) (addrSocketType addr) (addrProtocol addr)
        setSocketOption sock ReuseAddr 1
        bind sock (addrAddress addr)
        listen sock 10
        return sock
    loop sock = forever $ do
        (conn, peer) <- accept sock
        putStrLn $ "Connection from " ++ show peer
        void $ forkFinally (srp conn) (\_ -> close conn)

readSHA :: ByteString -> Integer
readSHA = read . ("0x"++) . byteStringToHex

bsToInt :: ByteString -> Integer
bsToInt =  read . C.unpack

intToBS :: Integer -> ByteString
intToBS = C.pack . show

srp :: Socket -> IO ()
srp conn = do
  -- C & S agree on constants
  (b, _, g) <- generateParam
  let k = 3
      n = p
      password = "super secret"
  sendAll conn $ C.pack $ show (n, g, k)
  -- S: salt, v
  salt <- intToBS . abs <$> randomIO
  let x = readSHA $ sha256 $ B.append salt password
      v = expMod g x n
      sb = k * v + expMod g b n
  -- C->S: Send I, A=g**a % N (a la Diffie Hellman)
  email <- recv conn 1024
  sa <- read . C.unpack <$> recv conn 1024
  -- S->C: Send salt, B=kv + g**b % N
  sendAll conn salt
  sendAll conn $ intToBS sb
  -- S, C: Compute string uH = SHA256(A|B), u = integer of uH
  let u = readSHA $ sha256 $ B.append (intToBS sa) (intToBS sb)
      sForB = expMod (sa * expMod v u n) b n
      kb = sha256 $ intToBS sForB
  putStrLn $ "S = " ++ show sForB
  -- C->S: Send HMAC-SHA256(K, salt)
  msgA <- recv conn 1024
  -- S->C: Send "OK" if HMAC-SHA256(K, salt) validates
  if msgA == hMAC sha256 64 kb salt
    then sendAll conn "OK"
    else sendAll conn "Not OK"
