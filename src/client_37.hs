{-# LANGUAGE OverloadedStrings #-}

import Set5
import EncodingsStrict
import HashesStrict
import System.Random

import qualified Control.Exception as E
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import Network.Socket hiding (recv)
import Network.Socket.ByteString (recv, sendAll)

main :: IO ()
main = withSocketsDo $ do
    addr <- resolve "127.0.0.1" "3000"
    E.bracket (open addr) close srp
  where
    resolve host port = do
        let hints = defaultHints { addrSocketType = Stream }
        addr:_ <- getAddrInfo (Just hints) (Just host) (Just port)
        return addr
    open addr = do
        sock <- socket (addrFamily addr) (addrSocketType addr) (addrProtocol addr)
        connect sock $ addrAddress addr
        return sock
    talk sock = do
        sendAll sock "Hello, world!"
        msg <- recv sock 1024
        putStr "Received: "
        C.putStrLn msg

readSHA :: ByteString -> Integer
readSHA = read . ("0x"++) . byteStringToHex

bsToInt :: ByteString -> Integer
bsToInt =  read . C.unpack

intToBS :: Integer -> ByteString
intToBS = C.pack . show

srp conn = do
  -- C & S agree on constants
  (n, g, k) <- read . C.unpack <$> recv conn 1024 :: IO (Integer, Integer, Integer)
  -- S: salt, v
  -- C->S: Send I, A=g**a % N (a la Diffie Hellman)
  (a, _, _) <- generateParam
  let email = "jie@email.com"
      password = "not super secret"
      sa = n -- expMod g a n
  sendAll conn email
  sendAll conn $ intToBS sa
  -- S->C: Send salt, B=kv + g**b % N
  salt <- recv conn 1024
  sb <- read . C.unpack <$> recv conn 1024
  -- S, C: Compute string uH = SHA256(A|B), u = integer of uH
  let u = readSHA $ sha256 $ B.append (intToBS sa) (intToBS sb)
      x = readSHA $ sha256 $ B.append salt password
      sForA = 0 -- expMod (sb - k * expMod g x n) (a + u * x) n
      ka = sha256 (intToBS sForA)
  -- C->S: Send HMAC-SHA256(K, salt)
      msgA = hMAC sha256 64 ka salt
  print sForA
  sendAll conn msgA
  -- S->C: Send "OK" if HMAC-SHA256(K, salt) validates
  -- print $ "S for client: " ++ show sForA
  verdict <- recv conn 1024
  print $ "Verdict: " ++ C.unpack verdict
