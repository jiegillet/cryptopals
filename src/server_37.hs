{-# LANGUAGE OverloadedStrings #-}

import Set5
import Encodings hiding (ByteString)
import Hashes
import System.Random

import Control.Concurrent (forkFinally)
import qualified Control.Exception as E
import Control.Monad (unless, forever, void)
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
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

intToLByteString :: (Integral a) => a -> B.ByteString
intToLByteString = BL.toStrict . intToByteString

byteStringToInt :: (Integral a) => B.ByteString -> a
byteStringToInt = B.foldl' (\n w -> 256 * n + fromIntegral w) 0

srp :: Socket -> IO ()
srp conn = do
  -- C & S agree on constants
  (b, _, g) <- generateParam
  let k = 3
      n = p
  sendAll conn $ intToLByteString n
  sendAll conn $ intToLByteString g
  sendAll conn $ intToLByteString k
  -- S: salt, v
  salt <- intToLByteString <$> randomIO
  let x = byteStringToInt $ sha256 $ B.append salt password
      v = expMod g x n
      sb = intToLByteString $ k * v + expMod g b n
  -- C->S: Send I, A=g**a % N (a la Diffie Hellman)
  email <- recv conn 1024
  sa <- recv conn 1024
  let password = "super secret"
  -- S->C: Send salt, B=kv + g**b % N
  sendAll conn salt
  sendAll conn sb
  -- S, C: Compute string uH = SHA256(A|B), u = integer of uH
  let u = byteStringToInt $ sha256 (B.append sa sb)
  -- C
  -- S
      sForB = expMod (byteStringToInt sa * expMod v u n) b n
      kb = sha256 (intToLByteString sForB)
  -- C->S: Send HMAC-SHA256(K, salt)
  msgA <- recv conn 1024
  -- S->C: Send "OK" if HMAC-SHA256(K, salt) validates
  if msgA == hMAC sha256 64 kb (intToLByteString salt)
    then print "OK"
    else print "Not OK"
